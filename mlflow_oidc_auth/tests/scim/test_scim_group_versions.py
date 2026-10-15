"""Versioned, recoverable SCIM group writes: rename, idempotent replay, version conflicts.

The directory sends its monotonic ``directoryVersion`` (top level or the mlflow-oidc extension
object); ``(externalId, version)`` is the idempotency key, the base version gates concurrency, and
a crash between plan and apply leaves a ``pending`` ledger row the same key resumes.
"""

import pytest

from mlflow_oidc_auth.config import config
from mlflow_oidc_auth.db.models import SqlScimActivity, SqlScimGroupChange
from mlflow_oidc_auth.ownership import Enforcement

from .conftest import patch_body, user_body

GROUPS = "/scim/v2/Groups"
USERS = "/scim/v2/Users"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
EXT = "urn:ietf:params:scim:schemas:extension:mlflow-oidc:2.0:Group"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"

ALICE = "alice@example.com"
BOB = "bob@example.com"
CAROL = "carol@example.com"


@pytest.fixture(autouse=True)
def no_tracking_store(monkeypatch):
    from types import SimpleNamespace

    from mlflow_oidc_auth.utils import permissions

    class _Store:
        def get_experiment(self, experiment_id):
            return SimpleNamespace(experiment_id=experiment_id, name=f"experiment-{experiment_id}")

    monkeypatch.setattr(permissions, "_get_tracking_store", lambda: _Store())


def assert_scim_error(response, status, scim_type=None):
    assert response.status_code == status, response.text
    body = response.json()
    assert body["schemas"] == [ERROR_SCHEMA]
    assert body["status"] == str(status)
    if scim_type:
        assert body["scimType"] == scim_type


def group_body(name, members=(), external_id=None, version=None, *, extension=False):
    body = {"schemas": [GROUP_SCHEMA], "displayName": name}
    if members is not None:
        body["members"] = [{"value": m} for m in members]
    if external_id is not None:
        body["externalId"] = external_id
    if version is not None:
        if extension:
            body[EXT] = {"directoryVersion": version}
        else:
            body["directoryVersion"] = version
    return body


def member_ids(resource):
    return sorted(m["value"] for m in resource.get("members", []))


@pytest.fixture
def users(client, scim):
    for name in (ALICE, BOB, CAROL):
        response = client.post(USERS, headers=scim, json=user_body(name))
        assert response.status_code == 201
    return ALICE, BOB, CAROL


def create_group(client, scim, name, members=(), **kwargs):
    response = client.post(GROUPS, headers=scim, json=group_body(name, members, **kwargs))
    assert response.status_code == 201, response.text
    return response.json()


def ledger_rows(store, **filters):
    with store.ManagedSessionMaker() as session:
        q = session.query(SqlScimGroupChange)
        for key, value in filters.items():
            q = q.filter(getattr(SqlScimGroupChange, key) == value)
        return [(r.external_id, r.version, r.status, r.old_name, r.new_name) for r in q.order_by(SqlScimGroupChange.id).all()]


def activity_versions(store, method=None):
    with store.ManagedSessionMaker() as session:
        q = session.query(SqlScimActivity.resource_version)
        if method:
            q = q.filter(SqlScimActivity.method == method)
        return [row[0] for row in q.all() if row[0] is not None]


@pytest.fixture
def enforce(monkeypatch):
    monkeypatch.setattr(config, "MANAGED_BY_ENFORCEMENT", Enforcement.ENFORCE)


class TestRenameGate:
    def test_rename_without_version_is_still_mutability(self, client, scim, users):
        create_group(client, scim, "eng", external_id="ext-eng")
        assert_scim_error(client.put(f"{GROUPS}/eng", headers=scim, json=group_body("eng-new", [], "ext-eng")), 400, "mutability")

    def test_rename_with_version_but_no_external_id_is_mutability(self, client, scim, users):
        create_group(client, scim, "eng")
        body = group_body("eng-new", [], version="1")
        assert_scim_error(client.put(f"{GROUPS}/eng", headers=scim, json=body), 400, "mutability")

    def test_rename_to_a_taken_name_conflicts(self, client, scim, users):
        create_group(client, scim, "eng", external_id="ext-eng")
        create_group(client, scim, "eng-new", external_id="ext-new")
        assert_scim_error(client.put(f"{GROUPS}/eng", headers=scim, json=group_body("eng-new", [], "ext-eng", "1")), 409, "uniqueness")

    def test_put_rename_and_replace_succeeds_and_echoes_version(self, client, scim, users, bound_store):
        create_group(client, scim, "eng", [ALICE], external_id="ext-eng")

        response = client.put(f"{GROUPS}/eng", headers=scim, json=group_body("eng-new", [BOB], "ext-eng", "2"))

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["id"] == body["displayName"] == "eng-new"
        assert body["externalId"] == "ext-eng"
        assert body["meta"]["location"].endswith("/Groups/eng-new")
        assert body[EXT]["directoryVersion"] == "2" and EXT in body["schemas"]
        assert member_ids(body) == [BOB]
        assert client.get(f"{GROUPS}/eng", headers=scim).status_code == 404
        current = bound_store.get_group_detail("eng-new")
        assert current["current_version"] == "2" and [m["username"] for m in current["members"]] == [BOB]
        assert ledger_rows(bound_store) == [("ext-eng", "2", "completed", "eng", "eng-new")]

    def test_patch_rename_takes_the_extension_object(self, client, scim, users):
        create_group(client, scim, "eng", [ALICE], external_id="ext-eng")
        body = patch_body({"op": "replace", "value": {"displayName": "eng-renamed", EXT: {"directoryVersion": "5"}, "members": [{"value": BOB}]}})

        response = client.patch(f"{GROUPS}/eng", headers=scim, json=body)

        assert response.status_code == 200, response.text
        resource = response.json()
        assert resource["id"] == "eng-renamed" and member_ids(resource) == [BOB]
        assert resource[EXT]["directoryVersion"] == "5"

    def test_versioned_member_only_update_without_rename(self, client, scim, users, bound_store):
        create_group(client, scim, "eng", [ALICE], external_id="ext-eng")

        response = client.patch(
            f"{GROUPS}/eng",
            headers=scim,
            json=patch_body(
                {"op": "add", "path": "members", "value": [{"value": BOB}]},
                {"op": "replace", "path": "directoryVersion", "value": "3"},
            ),
        )

        assert response.status_code == 200, response.text
        assert member_ids(response.json()) == [ALICE, BOB]
        assert response.json()[EXT]["directoryVersion"] == "3"
        assert ledger_rows(bound_store) == [("ext-eng", "3", "completed", "eng", "eng")]

    def test_version_requires_an_external_id_for_member_updates(self, client, scim, users):
        create_group(client, scim, "eng")
        response = client.patch(
            f"{GROUPS}/eng",
            headers=scim,
            json=patch_body(
                {"op": "add", "path": "members", "value": [{"value": BOB}]},
                {"op": "replace", "path": "directoryVersion", "value": "1"},
            ),
        )
        assert_scim_error(response, 400, "invalidValue")


class TestRenameValidation:
    @pytest.mark.parametrize("bad_name", ["eng/2", "eng?2", "eng#2", "eng%32"])
    def test_rename_rejects_url_reserved_characters_even_when_versioned(self, client, scim, users, bad_name):
        create_group(client, scim, "eng", [ALICE], external_id="ext-eng")
        assert_scim_error(client.put(f"{GROUPS}/eng", headers=scim, json=group_body(bad_name, [ALICE], "ext-eng", "1")), 400, "invalidValue")
        # The group is untouched and reachable under its name.
        assert client.get(f"{GROUPS}/eng", headers=scim).status_code == 200


class TestExternalIdReuse:
    def test_reused_external_id_binds_to_the_current_holder_not_history(self, client, scim, users, bound_store):
        # Group A holds E through v1, then moves to E2 in v2.
        create_group(client, scim, "eng", [ALICE], external_id="E")
        v1 = patch_body(
            {"op": "add", "path": "members", "value": [{"value": BOB}]},
            {"op": "replace", "path": "directoryVersion", "value": "1"},
        )
        assert client.patch(f"{GROUPS}/eng", headers=scim, json=v1).status_code == 200
        v2 = patch_body(
            {"op": "replace", "path": "externalId", "value": "E2"},
            {"op": "replace", "path": "directoryVersion", "value": "2"},
        )
        assert client.patch(f"{GROUPS}/eng", headers=scim, json=v2).status_code == 200

        # A new group B reuses E and starts its own version chain at 1.
        create_group(client, scim, "ops", [CAROL], external_id="E")
        response = client.put(f"{GROUPS}/ops", headers=scim, json=group_body("ops-new", [CAROL], "E", "1"))

        assert response.status_code == 200, response.text
        assert response.json()["id"] == "ops-new"
        # A's resource must not have been returned or rewritten.
        a = bound_store.get_group_detail("eng")
        assert a["external_id"] == "E2" and sorted(m["username"] for m in a["members"]) == [ALICE, BOB]
        assert [m["username"] for m in bound_store.get_group_detail("ops-new")["members"]] == [CAROL]


class TestIdempotentReplay:
    def test_replay_returns_the_settled_snapshot_not_later_state(self, client, scim, users):
        create_group(client, scim, "eng", [ALICE], external_id="ext-eng")

        def members_version(ids, v):
            return group_body("eng", ids, "ext-eng", v)

        assert client.put(f"{GROUPS}/eng", headers=scim, json=members_version([ALICE], "1")).status_code == 200
        assert client.put(f"{GROUPS}/eng", headers=scim, json=members_version([ALICE, BOB], "2")).status_code == 200

        replay = client.put(f"{GROUPS}/eng", headers=scim, json=members_version([ALICE], "1"))
        assert replay.status_code == 200
        body = replay.json()
        assert body[EXT]["directoryVersion"] == "1"
        assert member_ids(body) == [ALICE]

    def test_put_replayed_against_the_old_path_returns_the_completed_group(self, client, scim, users, bound_store, audit_events):
        create_group(client, scim, "eng", [ALICE], external_id="ext-eng")
        request_body = group_body("eng-new", [BOB], "ext-eng", "7")
        first = client.put(f"{GROUPS}/eng", headers=scim, json=request_body)
        assert first.status_code == 200

        # Response lost: the directory resends the identical request to the name it knew.
        replay = client.put(f"{GROUPS}/eng", headers=scim, json=request_body)
        assert replay.status_code == 200, replay.text
        assert replay.json() == first.json()

        renamed = [e for e in audit_events if e["event"] == "group.renamed"]
        changed = [e for e in audit_events if e["event"] == "group.members_changed"]
        assert len(renamed) == len(changed) == 1
        assert renamed[0]["detail"]["version"] == changed[0]["detail"]["version"] == "7"
        # An unversioned request still treats the old name as gone.
        assert client.get(f"{GROUPS}/eng", headers=scim).status_code == 404
        assert len(ledger_rows(bound_store)) == 1

    def test_patch_replay_by_external_id_and_version(self, client, scim, users, audit_events):
        create_group(client, scim, "eng", [ALICE], external_id="ext-eng")
        body = patch_body({"op": "add", "path": "members", "value": [{"value": BOB}], "directoryVersion": "4"})

        assert client.patch(f"{GROUPS}/eng", headers=scim, json=body).status_code == 200
        assert client.patch(f"{GROUPS}/eng", headers=scim, json=body).status_code == 200
        assert len([e for e in audit_events if e["event"] == "group.members_changed"]) == 1

    def test_repeated_version_after_a_newer_one_is_a_conflict(self, client, scim, users):
        create_group(client, scim, "eng", [ALICE], external_id="ext-eng")

        def add(v):
            return patch_body(
                {"op": "add", "path": "members", "value": [{"value": BOB}]},
                {"op": "replace", "path": "directoryVersion", "value": v},
            )

        assert client.patch(f"{GROUPS}/eng", headers=scim, json=add("10")).status_code == 200
        assert_scim_error(client.patch(f"{GROUPS}/eng", headers=scim, json=add("9")), 409, "versionConflict")
        # The same completed version replays instead of conflicting.
        assert client.patch(f"{GROUPS}/eng", headers=scim, json=add("10")).status_code == 200


class TestOwnership:
    @pytest.mark.parametrize("owner,seed", [("manual", None), ("oidc:default", "login")])
    def test_versioned_write_is_refused_on_another_sources_group(self, client, scim, users, bound_store, enforce, monkeypatch, owner, seed):
        if seed == "login":
            from .test_scim_groups import login

            login(ALICE, ["foreign"], monkeypatch)
        else:
            bound_store.populate_groups(["foreign"])
        body = group_body("foreign-renamed", [BOB], f"ext-{owner}", "1")

        assert_scim_error(client.put(f"{GROUPS}/foreign", headers=scim, json=body), 409, "mutability")
        assert bound_store.get_group_detail("foreign-renamed") is None
        assert ledger_rows(bound_store) == []

    def test_scim_owned_group_versioned_write_succeeds_under_enforce(self, client, scim, users, enforce):
        create_group(client, scim, "eng", [ALICE], external_id="ext-eng")
        response = client.put(f"{GROUPS}/eng", headers=scim, json=group_body("eng-new", [ALICE, BOB], "ext-eng", "1"))
        assert response.status_code == 200
        assert member_ids(response.json()) == [ALICE, BOB]

    def test_unknown_member_applies_nothing(self, client, scim, users, bound_store, audit_events):
        create_group(client, scim, "eng", [ALICE], external_id="ext-eng")
        body = group_body("eng-new", ["ghost@example.com"], "ext-eng", "1")

        assert_scim_error(client.put(f"{GROUPS}/eng", headers=scim, json=body), 400, "invalidValue")
        assert [m["username"] for m in bound_store.get_group_detail("eng")["members"]] == [ALICE]
        assert ledger_rows(bound_store) == []
        assert not [e for e in audit_events if e["event"].startswith(("group.renamed", "group.members_changed"))]


class TestRecoveryThroughHttp:
    def test_failed_apply_returns_500_then_the_same_key_completes(self, client, scim, users, bound_store, audit_events, monkeypatch):
        from mlflow_oidc_auth.repository import scim_group_change as change_module

        create_group(client, scim, "eng", [ALICE], external_id="ext-eng")
        real = change_module.ScimGroupChangeRepository._apply_ops

        def flaky(session, group, operations, outcome, *, written_by):
            flaky.calls += 1
            if flaky.calls == 1:
                raise RuntimeError("simulated permission migration failure")
            return real(session, group, operations, outcome, written_by=written_by)

        flaky.calls = 0
        monkeypatch.setattr(change_module.ScimGroupChangeRepository, "_apply_ops", staticmethod(flaky))

        body = group_body("eng-new", [BOB], "ext-eng", "1")
        assert client.put(f"{GROUPS}/eng", headers=scim, json=body).status_code == 500
        # The original group stayed usable while the change waited.
        assert [m["username"] for m in bound_store.get_group_detail("eng")["members"]] == [ALICE]

        response = client.put(f"{GROUPS}/eng", headers=scim, json=body)
        assert response.status_code == 200, response.text
        assert response.json()["id"] == "eng-new" and member_ids(response.json()) == [BOB]
        assert len([e for e in audit_events if e["event"] == "group.renamed"]) == 1


class TestDeleteMutex:
    def test_delete_refused_while_a_change_is_open(self, client, scim, users, bound_store, monkeypatch):
        from mlflow_oidc_auth.repository import scim_group_change as change_module

        create_group(client, scim, "eng", [ALICE], external_id="ext-eng")

        def stuck(session, group, operations, outcome, *, written_by):
            raise RuntimeError("stuck applying")

        monkeypatch.setattr(change_module.ScimGroupChangeRepository, "_apply_ops", staticmethod(stuck))
        assert client.put(f"{GROUPS}/eng", headers=scim, json=group_body("eng-new", [BOB], "ext-eng", "1")).status_code == 500

        assert_scim_error(client.delete(f"{GROUPS}/eng", headers=scim), 409)
        assert bound_store.get_group_detail("eng") is not None

    def test_delete_after_completion_cascades_the_ledger(self, client, scim, users, bound_store):
        create_group(client, scim, "eng", [ALICE], external_id="ext-eng")
        assert client.put(f"{GROUPS}/eng", headers=scim, json=group_body("eng-new", [BOB], "ext-eng", "1")).status_code == 200

        response = client.delete(f"{GROUPS}/eng-new", headers=scim)
        assert response.status_code == 204
        assert ledger_rows(bound_store) == []

    def test_a_stale_version_conflict_leaves_nothing_blocking_delete(self, client, scim, users):
        create_group(client, scim, "eng", [ALICE], external_id="ext-eng")

        def add(v):
            return patch_body(
                {"op": "add", "path": "members", "value": [{"value": BOB}]},
                {"op": "replace", "path": "directoryVersion", "value": v},
            )

        client.patch(f"{GROUPS}/eng", headers=scim, json=add("2"))
        assert_scim_error(client.patch(f"{GROUPS}/eng", headers=scim, json=add("1")), 409, "versionConflict")

        assert client.delete(f"{GROUPS}/eng", headers=scim).status_code == 204


class TestCreateSeedsVersion:
    def test_post_with_directory_version_seeds_current_version(self, client, scim, users, bound_store):
        body = group_body("eng", [ALICE], external_id="ext-eng", version="100")
        response = client.post(GROUPS, headers=scim, json=body)

        assert response.status_code == 201, response.text
        assert response.json()[EXT]["directoryVersion"] == "100"
        assert bound_store.get_group_detail("eng")["current_version"] == "100"
        assert ledger_rows(bound_store) == []


class TestActivityVersion:
    def test_resource_version_only_on_determined_outcomes(self, client, scim, users, bound_store):
        create_group(client, scim, "eng", [ALICE], external_id="ext-eng")
        # Determined versioned outcomes: one completion and one replay.
        body = group_body("eng", [BOB], "ext-eng", "1")
        client.put(f"{GROUPS}/eng", headers=scim, json=body)
        client.put(f"{GROUPS}/eng", headers=scim, json=body)
        # Pre-planning failures: syntax error and an unknown group.
        client.put(f"{GROUPS}/eng", headers=scim, json={"schemas": [GROUP_SCHEMA]})
        client.put(f"{GROUPS}/nope", headers=scim, json=group_body("nope", [], "ext-x", "1"))

        # The versioned rows (including the replay) carry the version; nothing else does.
        assert activity_versions(bound_store, method="PUT") == ["1", "1"]
