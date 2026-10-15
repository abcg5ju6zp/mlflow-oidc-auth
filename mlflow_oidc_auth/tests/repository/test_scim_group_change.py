"""Versioned, recoverable SCIM group changes against a real SQLite store.

These exercise the two-phase ledger (plan -> apply -> replay/recover), crash rollback, the
ownership guards, optimistic version conflicts and grant survival across the stable group id —
none of which a mocked session can prove.
"""

import json
from types import SimpleNamespace

import pytest
from mlflow.exceptions import MlflowException
from mlflow.protos.databricks_pb2 import ErrorCode, RESOURCE_ALREADY_EXISTS

from mlflow_oidc_auth.config import config
from mlflow_oidc_auth.db.models import (
    GROUP_CHANGE_APPLYING,
    GROUP_CHANGE_COMPLETED,
    GROUP_CHANGE_PENDING,
    GROUP_CHANGE_SUPERSEDED,
    SqlGroup,
    SqlScimGroupChange,
)
from mlflow_oidc_auth.ownership import Enforcement
from mlflow_oidc_auth.repository import scim_group_change as change_module
from mlflow_oidc_auth.repository.group import GroupRepository, GroupWriteRefused, MembershipRefused, UnknownMember
from mlflow_oidc_auth.repository.scim_group_change import GroupChangeBlocked, GroupVersionConflict, SameVersion, compare_versions

ALICE = "alice@example.com"
BOB = "bob@example.com"
CAROL = "carol@example.com"


@pytest.fixture
def store(tmp_path):
    # Permission resolution imports the lazy singleton, so bind it to this test store exactly as
    # the SCIM suite's bound_store fixture does.
    import mlflow_oidc_auth.store as store_module
    from mlflow_oidc_auth.sqlalchemy_store import SqlAlchemyStore

    s = SqlAlchemyStore()
    s.init_db(f"sqlite:///{tmp_path / 'auth.db'}")
    previous = object.__getattribute__(store_module.store, "_instance")
    object.__setattr__(store_module.store, "_instance", s)
    yield s
    object.__setattr__(store_module.store, "_instance", previous)
    s.engine.dispose()


@pytest.fixture(autouse=True)
def no_tracking_store(monkeypatch):
    """Group grants resolve through the regex fallback, which looks experiments up in MLflow's
    tracking store; no regex grants here, so stub the lookup as the SCIM suite does."""
    from mlflow_oidc_auth.utils import permissions

    class _Store:
        def get_experiment(self, experiment_id):
            return SimpleNamespace(experiment_id=experiment_id, name=f"experiment-{experiment_id}")

    monkeypatch.setattr(permissions, "_get_tracking_store", lambda: _Store())
    monkeypatch.setattr(config, "MANAGED_BY_ENFORCEMENT", Enforcement.REPORT)


def group_permission(experiment, username):
    from mlflow_oidc_auth.utils.permissions import effective_experiment_permission, flush_permission_cache

    flush_permission_cache()
    return effective_experiment_permission(experiment, username)


@pytest.fixture
def directory_group(store):
    for name in (ALICE, BOB, CAROL):
        store.create_user(name, name.split("@")[0].title())
    store.create_user("svc", "Service", is_service_account=True)
    store.create_directory_group("eng", "ext-eng", [ALICE], written_by="scim")
    store.create_group_experiment_permission("eng", "5", "READ")
    return "eng"


def plan(store, name="eng", *, version="1", external_id="ext-eng", new_name=None, operations=None, **kwargs):
    return store.plan_scim_group_change(
        name,
        version=version,
        target_external_id=external_id,
        new_name=new_name or name,
        operations=operations if operations is not None else [],
        written_by="scim",
        actor="scim:entra",
        **kwargs,
    )


def rows(store, **filters):
    """Plain dicts read inside the session — ORM rows expire on commit and detach afterwards."""
    with store.ManagedSessionMaker() as session:
        q = session.query(SqlScimGroupChange)
        for key, value in filters.items():
            q = q.filter(getattr(SqlScimGroupChange, key) == value)
        return [
            {
                "id": r.id,
                "group_id": r.group_id,
                "version": r.version,
                "status": r.status,
                "attempts": int(r.attempts or 0),
                "last_error": r.last_error,
                "result_json": r.result_json,
            }
            for r in q.order_by(SqlScimGroupChange.id).all()
        ]


def test_compare_versions_rules():
    assert compare_versions("2", None) == 1
    assert compare_versions("10", "9") == 1
    assert compare_versions("09", "10") == -1
    assert compare_versions("a", "a") == 0
    assert compare_versions("b", "a") == 1
    assert compare_versions("v2", "v10") == 1  # non-integer versions are lexicographic


class TestPlan:
    def test_persists_pending_row_with_diff_before_any_group_write(self, store, directory_group):
        record = plan(store, new_name="eng-new", operations=[("add", [BOB]), ("remove", [ALICE])])

        assert record.status == GROUP_CHANGE_PENDING
        assert (record.external_id, record.version, record.old_name, record.new_name) == ("ext-eng", "1", "eng", "eng-new")
        assert record.base_version is None
        assert record.planned_diff == {"added": [BOB], "removed": [ALICE]}
        assert record.ops == [("add", [BOB]), ("remove", [ALICE])]
        # Planning writes the ledger row and nothing else.
        detail = store.get_group_detail("eng")
        assert detail["group_name"] == "eng" and detail["current_version"] is None
        assert [m["username"] for m in detail["members"]] == [ALICE]

    def test_unknown_member_plans_nothing(self, store, directory_group):
        with pytest.raises(UnknownMember):
            plan(store, operations=[("add", ["ghost@example.com"])])
        assert rows(store) == []
        assert [m["username"] for m in store.get_group_detail("eng")["members"]] == [ALICE]

    def test_service_account_member_plans_nothing(self, store, directory_group):
        with pytest.raises(UnknownMember):
            plan(store, operations=[("replace", ["svc"])])
        assert rows(store) == []

    def test_targeted_remove_of_a_foreign_membership_is_refused_before_the_row(self, store, directory_group, monkeypatch):
        monkeypatch.setattr(config, "MANAGED_BY_ENFORCEMENT", Enforcement.ENFORCE)
        store.add_user_to_group(BOB, "eng", written_by="oidc:default")

        with pytest.raises(MembershipRefused):
            plan(store, operations=[("remove", [BOB])])

        assert rows(store) == []
        members = {m["username"]: m["managed_by"] for m in store.get_group_detail("eng")["members"]}
        assert members == {ALICE: "scim", BOB: "oidc:default"}

    def test_rename_taken_name_and_external_id_are_refused(self, store, directory_group):
        store.create_directory_group("eng-new", "ext-new", [], written_by="scim")

        with pytest.raises(MlflowException) as name_exc:
            plan(store, new_name="eng-new", external_id="ext-eng")
        assert name_exc.value.error_code == ErrorCode.Name(RESOURCE_ALREADY_EXISTS)

        with pytest.raises(MlflowException) as ext_exc:
            plan(store, new_name="eng-2", external_id="ext-new")
        assert ext_exc.value.error_code == ErrorCode.Name(RESOURCE_ALREADY_EXISTS)
        assert rows(store) == []

    def test_manual_group_is_refused_under_enforce(self, store, directory_group, monkeypatch):
        monkeypatch.setattr(config, "MANAGED_BY_ENFORCEMENT", Enforcement.ENFORCE)
        store.populate_groups(["hand-made"])

        with pytest.raises(GroupWriteRefused):
            plan(store, name="hand-made", external_id="ext-hand", operations=[("add", [ALICE])])
        assert rows(store) == []

    def test_duplicate_key_returns_the_existing_record(self, store, directory_group):
        first = plan(store, version="3", operations=[("add", [BOB])])
        store.apply_scim_group_change(first.id, written_by="scim")

        again = plan(store, version="3", operations=[("add", [BOB])])
        assert again.id == first.id and again.status == GROUP_CHANGE_COMPLETED
        assert len(rows(store)) == 1

    def test_same_version_with_no_record_is_a_no_op_sentinel(self, store, directory_group):
        with store.ManagedSessionMaker(read_only=False) as session:
            session.query(SqlGroup).update({"current_version": "9"})

        with pytest.raises(SameVersion):
            plan(store, version="9", operations=[("add", [BOB])])
        assert rows(store) == []


class TestApply:
    def test_failed_apply_keeps_the_original_group_usable_then_resumes_from_snapshot(self, store, directory_group, monkeypatch):
        record = plan(store, new_name="eng-new", operations=[("replace", [BOB])])

        real = change_module.ScimGroupChangeRepository._apply_ops

        def flaky(session, group, operations, outcome, *, written_by):
            flaky.calls += 1
            if flaky.calls == 1:
                raise RuntimeError("simulated permission migration failure")
            return real(session, group, operations, outcome, written_by=written_by)

        flaky.calls = 0
        monkeypatch.setattr(change_module.ScimGroupChangeRepository, "_apply_ops", staticmethod(flaky))

        # First attempt: everything rolls back, original group and grant remain usable. The
        # managed-session wrapper surfaces the injected fault as a generic MlflowException.
        with pytest.raises(MlflowException) as failed:
            store.apply_scim_group_change(record.id, written_by="scim")
        assert "simulated permission migration failure" in str(failed.value)
        detail = store.get_group_detail("eng")
        assert detail is not None and [m["username"] for m in detail["members"]] == [ALICE]
        assert group_permission("5", ALICE).kind == "group"
        [row] = rows(store)
        assert row["status"] == GROUP_CHANGE_PENDING and row["attempts"] == 1 and "simulated" in row["last_error"]

        # Retry drives the stored snapshot to completion — no original request body involved.
        outcome, completed, record2, settled_now = store.apply_scim_group_change(record.id, written_by="scim")
        assert settled_now is True
        assert record2.status == GROUP_CHANGE_COMPLETED
        assert completed["group_name"] == "eng-new"
        assert store.get_group_detail("eng") is None
        assert [m["username"] for m in store.get_group_detail("eng-new")["members"]] == [BOB]
        assert store.get_group_detail("eng-new")["current_version"] == "1"
        # The stable group id carries the grant across the rename; membership changes bite at once.
        assert group_permission("5", BOB).permission.name == "READ"
        assert group_permission("5", ALICE).kind != "group"
        assert outcome.removed == [(ALICE, "eng-new")] and outcome.added == [(BOB, "eng-new")]

    def test_completed_apply_is_a_write_free_replay(self, store, directory_group):
        record = plan(store, version="2", operations=[("add", [BOB])])
        _, first_detail, _, _ = store.apply_scim_group_change(record.id, written_by="scim")

        outcome, replay_detail, replay, settled_now = store.apply_scim_group_change(record.id, written_by="scim")
        assert settled_now is False
        assert replay.status == GROUP_CHANGE_COMPLETED
        assert replay_detail["group_name"] == first_detail["group_name"] == "eng"
        assert not outcome.changed and [m["username"] for m in replay_detail["members"]] == [ALICE, BOB]

    def test_sync_keeps_a_foreign_membership_row(self, store, directory_group):
        store.add_user_to_group(BOB, "eng", written_by="oidc:default")
        record = plan(store, version="2", operations=[("replace", [ALICE])])

        outcome, detail, _, settled_now = store.apply_scim_group_change(record.id, written_by="scim")
        assert sorted(m["username"] for m in detail["members"]) == [ALICE, BOB]
        assert settled_now is True
        assert [c.username for c in outcome.conflicts if c.kept] == [BOB]


class TestVersionConflicts:
    def test_stale_and_same_base_conflicts(self, store, directory_group):
        v2 = plan(store, version="2", operations=[("add", [BOB])])
        store.apply_scim_group_change(v2.id, written_by="scim")

        # A strictly older version after v2 landed can never advance.
        with pytest.raises(GroupVersionConflict):
            plan(store, version="1", operations=[("add", [CAROL])])

        # Two changes planned on the same base: one wins, the other loses at apply — no overwrite.
        v3 = plan(store, version="3", operations=[("add", [CAROL])])
        v4 = plan(store, version="4", new_name="eng-4", operations=[("add", [BOB])])
        _, detail3, _, _ = store.apply_scim_group_change(v3.id, written_by="scim")
        assert CAROL in [m["username"] for m in detail3["members"]]
        with pytest.raises(GroupVersionConflict):
            store.apply_scim_group_change(v4.id, written_by="scim")
        assert store.get_group_detail("eng-4") is None
        assert [m["username"] for m in store.get_group_detail("eng")["members"]] == [ALICE, BOB, CAROL]
        v4_row = [r for r in rows(store) if r["version"] == "4"][0]
        # The lost race closes terminally — it must not block the group's later delete.
        assert v4_row["status"] == GROUP_CHANGE_SUPERSEDED and v4_row["attempts"] == 1
        # And its answer stays a conflict on any same-key retry.
        with pytest.raises(GroupVersionConflict):
            store.apply_scim_group_change(v4.id, written_by="scim")

    def test_superseded_loser_no_longer_blocks_delete(self, store, directory_group):
        v3 = plan(store, version="3", operations=[("add", [CAROL])])
        v4 = plan(store, version="4", new_name="eng-4")
        store.apply_scim_group_change(v3.id, written_by="scim")
        with pytest.raises(GroupVersionConflict):
            store.apply_scim_group_change(v4.id, written_by="scim")

        # The group settles (v3) and deletes despite the loser's row.
        removed, grants = store.delete_directory_group("eng", written_by="scim")
        assert (ALICE, "eng") in removed and store.get_group_detail("eng") is None

    def test_apply_maps_a_name_taken_between_plan_and_apply(self, store, directory_group):
        record = plan(store, version="2", new_name="eng-new")
        store.create_directory_group("eng-new", "ext-other", [], written_by="scim")
        with pytest.raises(MlflowException) as exc:
            store.apply_scim_group_change(record.id, written_by="scim")
        assert exc.value.error_code == ErrorCode.Name(RESOURCE_ALREADY_EXISTS)
        # Retryable: the original group and its pending row remain.
        assert store.get_group_detail("eng") is not None
        assert rows(store)[0]["status"] == GROUP_CHANGE_PENDING

    def test_find_change_requires_an_unambiguous_match(self, store, directory_group):
        # Two groups that both historically carried the name "dup" with the same version string.
        store.create_directory_group("dup", "ext-dup", [], written_by="scim")
        plan(store, name="dup", external_id="ext-dup", version="5", new_name="dup-a")
        store.create_directory_group("other", "ext-other", [], written_by="scim")
        plan(store, name="other", external_id="ext-other", version="5", new_name="dup-b")
        with store.ManagedSessionMaker(read_only=False) as session:
            for row in session.query(SqlScimGroupChange).all():
                row.old_name = "shared-old"

        assert store.find_scim_group_change(version="5", old_name="shared-old") is None


class TestDeleteMutex:
    def test_open_change_blocks_delete_completed_change_cascades(self, store, directory_group):
        record = plan(store, version="2", operations=[("add", [BOB])])

        with pytest.raises(GroupChangeBlocked):
            store.delete_directory_group("eng", written_by="scim")
        assert store.get_group_detail("eng") is not None

        store.apply_scim_group_change(record.id, written_by="scim")
        removed, grants = store.delete_directory_group("eng", written_by="scim")
        assert (ALICE, "eng") in removed and "experiment_group_permissions" in grants
        assert rows(store) == []


class TestRecovery:
    def test_applying_rows_are_reconciled(self, store, directory_group):
        # Settled: group already carries the row's version and target name.
        settled = plan(store, version="10", new_name="eng-a", operations=[("add", [BOB])])
        # Unsettled: group never reached the target.
        store.create_directory_group("ops", "ext-ops", [], written_by="scim")
        unsettled = plan(store, name="ops", external_id="ext-ops", version="11", new_name="ops-b")

        with store.ManagedSessionMaker(read_only=False) as session:
            session.get(SqlScimGroupChange, settled.id).status = GROUP_CHANGE_APPLYING
            session.get(SqlScimGroupChange, unsettled.id).status = GROUP_CHANGE_APPLYING
            group = session.get(SqlGroup, settled.group_id)
            group.group_name = "eng-a"
            group.current_version = "10"

        summary = store.recover_scim_group_changes()

        assert summary["completed"] == 1 and summary["pending"] == 1 and summary["failed"] == 0
        by_id = {r["id"]: r for r in rows(store)}
        assert by_id[settled.id]["status"] == GROUP_CHANGE_COMPLETED
        assert json.loads(by_id[settled.id]["result_json"])["detail"]["group_name"] == "eng-a"
        assert by_id[unsettled.id]["status"] == GROUP_CHANGE_PENDING and by_id[unsettled.id]["attempts"] == 1
        # pending rows are never auto-applied.
        assert store.get_group_detail("ops-b") is None

    def test_recovery_tolerates_a_row_level_error_and_keeps_reconciling(self, store, directory_group, monkeypatch):
        broken = plan(store, version="12", new_name="eng-d")
        waiting = plan(store, version="13", new_name="eng-e")
        with store.ManagedSessionMaker(read_only=False) as session:
            session.get(SqlScimGroupChange, broken.id).status = GROUP_CHANGE_APPLYING
            target = session.get(SqlGroup, broken.group_id)
            target.group_name = "eng-d"
            target.current_version = "12"
            session.get(SqlScimGroupChange, waiting.id).status = GROUP_CHANGE_APPLYING

        # Snapshot building for the settled row fails: recovery counts it failed, never raises, and
        # still returns the other row to pending.
        def boom(session, group_ids, *, include_service_accounts):
            raise RuntimeError("snapshot unavailable")

        monkeypatch.setattr(GroupRepository, "_members_by_group", boom)

        summary = store.recover_scim_group_changes()
        assert summary["failed"] == 1 and summary["pending"] == 1 and summary["completed"] == 0
        by_id = {r["id"]: r for r in rows(store)}
        assert by_id[broken.id]["status"] == GROUP_CHANGE_APPLYING  # left untouched on failure
        assert by_id[waiting.id]["status"] == GROUP_CHANGE_PENDING
