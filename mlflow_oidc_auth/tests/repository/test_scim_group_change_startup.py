"""The startup hook reconciling interrupted versioned SCIM group changes.

It must reconcile ``applying`` rows (completed when the target was reached, pending otherwise),
never apply a pending change, never emit audit events, and never let a recovery error block the
application from starting.
"""

import pytest

from mlflow_oidc_auth import audit
from mlflow_oidc_auth.app import _recover_group_changes_at_startup
from mlflow_oidc_auth.db.models import GROUP_CHANGE_APPLYING, GROUP_CHANGE_COMPLETED, GROUP_CHANGE_PENDING, SqlGroup, SqlScimGroupChange

ALICE = "alice@example.com"


@pytest.fixture
def store(tmp_path):
    import mlflow_oidc_auth.store as store_module
    from mlflow_oidc_auth.sqlalchemy_store import SqlAlchemyStore

    s = SqlAlchemyStore()
    s.init_db(f"sqlite:///{tmp_path / 'auth.db'}")
    previous = object.__getattribute__(store_module.store, "_instance")
    object.__setattr__(store_module.store, "_instance", s)
    yield s
    object.__setattr__(store_module.store, "_instance", previous)
    s.engine.dispose()


def _rows(store):
    with store.ManagedSessionMaker() as session:
        return {r.version: r.status for r in session.query(SqlScimGroupChange).all()}


def test_startup_reconciles_applying_rows_without_applying_or_auditing(store, monkeypatch):
    store.create_user(ALICE, "Alice")
    settled = store.create_directory_group("eng", "ext-eng", [ALICE], written_by="scim", current_version=None)
    store.create_directory_group("ops", "ext-ops", [], written_by="scim")
    r1 = store.plan_scim_group_change("eng", version="10", target_external_id="ext-eng", new_name="eng-a", operations=[], written_by="scim")
    r2 = store.plan_scim_group_change("ops", version="11", target_external_id="ext-ops", new_name="ops-b", operations=[], written_by="scim")
    with store.ManagedSessionMaker(read_only=False) as session:
        session.get(SqlScimGroupChange, r1.id).status = GROUP_CHANGE_APPLYING
        session.get(SqlScimGroupChange, r2.id).status = GROUP_CHANGE_APPLYING
        target = session.query(SqlGroup).filter(SqlGroup.group_name == "eng").one()
        target.group_name = "eng-a"
        target.current_version = "10"

    emitted = []
    monkeypatch.setattr(audit, "emit_audit_event", lambda *args, **kwargs: emitted.append((args, kwargs)))

    _recover_group_changes_at_startup()  # must not raise

    assert _rows(store) == {"10": GROUP_CHANGE_COMPLETED, "11": GROUP_CHANGE_PENDING}
    # pending rows are not auto-applied, and no audit accompanies recovery.
    assert store.get_group_detail("ops-b") is None
    assert emitted == []


def test_startup_recovery_swallows_errors(store, monkeypatch):
    def boom():
        raise RuntimeError("database unreachable")

    monkeypatch.setattr(store, "recover_scim_group_changes", boom)
    _recover_group_changes_at_startup()  # the exception must stay inside the hook
