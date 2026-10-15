"""Staged, recoverable service-account sign-in source changes (identity generations).

Covers the state machine in ``utils/service_accounts.py``: pin → revoke → publish → finalize,
resume by generation after a lost response or restart, the failure semantics of each phase, and
compatibility for people, unchanged accounts, external accounts, and the ordinary internal token
flow.
"""

from datetime import datetime, timedelta, timezone

import pytest
from mlflow.exceptions import MlflowException
from mlflow.protos.databricks_pb2 import INVALID_PARAMETER_VALUE, INVALID_STATE, RESOURCE_ALREADY_EXISTS, ErrorCode

import mlflow_oidc_auth.store as store_module
from mlflow_oidc_auth.config import config
from mlflow_oidc_auth.provider_registry import ProviderConfig

ADMIN = "root@corp.example"
CI = "ci-bot"
BOB = "bob@partner.example"


def _provider(provider_id, **overrides):
    fields = {
        "id": provider_id,
        "type": "oidc",
        "audience": "mlflow",
        "issuer": f"https://{provider_id}.invalid",
        "provisioning": "jit",
        "group_sync": "every_login",
        "group_sync_mode": "authoritative",
        "admin_source": "claims" if provider_id == "default" else "none",
    }
    fields.update(overrides)
    return ProviderConfig(**fields)


DEFAULT = _provider("default")
PARTNER = _provider("partner")


@pytest.fixture
def store(tmp_path):
    from mlflow_oidc_auth.sqlalchemy_store import SqlAlchemyStore

    s = SqlAlchemyStore()
    s.init_db(f"sqlite:///{tmp_path / 'auth.db'}")
    s.create_user(ADMIN, "Admin", is_admin=True)
    previous = object.__getattribute__(store_module.store, "_instance")
    object.__setattr__(store_module.store, "_instance", s)
    yield s
    object.__setattr__(store_module.store, "_instance", previous)
    s.engine.dispose()


@pytest.fixture(autouse=True)
def providers(monkeypatch):
    from mlflow_oidc_auth.provider_registry import RegistryLoadResult

    monkeypatch.setattr(config, "AUTH_PROVIDERS", RegistryLoadResult(providers=[DEFAULT, PARTNER], errors=[], source="test"))


@pytest.fixture(autouse=True)
def fresh_cache():
    from mlflow_oidc_auth.utils import bearer_identity_cache

    bearer_identity_cache._cache = None
    yield
    bearer_identity_cache._cache = None


@pytest.fixture
def audit_events(monkeypatch):
    import mlflow_oidc_auth.audit as audit

    events = []
    monkeypatch.setattr(audit, "emit_audit_event", lambda event, actor, **kw: events.append({"event": event, "actor": actor, **kw}))
    return events


def _service_account(store, name=CI, source="internal", *, is_admin=False):
    store.create_user(name, "CI", is_admin=is_admin, is_service_account=True, service_account_source=source)
    return name


def _session_expiry(hours=1):
    return datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=hours)


def _active(store, name=CI):
    return store.service_account_transition_repo.get_active(name)


def _all_transitions(store, name=CI):
    """``[(generation, target_source, phase), ...]`` read inside the session (no detached rows)."""
    from mlflow_oidc_auth.db.models import SqlServiceAccountSourceTransition, SqlUser

    with store.ManagedSessionMaker() as session:
        rows = (
            session.query(SqlServiceAccountSourceTransition)
            .join(SqlUser, SqlUser.id == SqlServiceAccountSourceTransition.user_id)
            .filter(SqlUser.username == name)
            .order_by(SqlServiceAccountSourceTransition.generation)
            .all()
        )
        return [(r.generation, r.target_source, r.phase) for r in rows]


def _apply(store, source="partner", subject="s1", name=CI, *, actor=ADMIN):
    from mlflow_oidc_auth.utils.service_accounts import apply_source

    return apply_source(name, source, subject, actor=actor)


class TestACompletedChange:
    def test_runs_every_phase_and_revokes_credentials(self, store, audit_events):
        from mlflow_oidc_auth.tests.token_helpers import set_known_token
        from mlflow_oidc_auth.utils.service_accounts import is_external

        _service_account(store)
        set_known_token(store, CI, "ci-bot-token")
        store.create_auth_session(CI, _session_expiry())

        result = _apply(store)

        assert result["status"] == "completed"
        assert result["generation"] == 1
        assert result["changed"] is True
        assert result["recovered"] is False
        assert result["revoked_tokens"] >= 1
        assert result["revoked_sessions"] >= 1
        profile = store.get_user_profile(CI)
        assert profile.service_account_source == "partner"
        assert is_external(profile.service_account_source)
        assert store.list_user_tokens(CI) == []
        assert store.user_identity_repo.list_identities_for_username(CI) == [("partner", "s1")]
        assert _active(store) is None
        assert _all_transitions(store)[0][2] == "completed"
        assert len(audit_events) == 1
        event = audit_events[0]
        assert event["event"] == "user.service_account_source"
        assert event["actor"] == ADMIN
        assert event["detail"]["generation"] == 1
        assert event["detail"]["source"] == "partner"
        assert event["detail"]["subject_bound"] is True

    def test_phases_are_ordered_pin_revoke_publish(self, store, monkeypatch):
        from mlflow_oidc_auth.tests.token_helpers import set_known_token

        _service_account(store)
        set_known_token(store, CI, "ci-bot-token")
        seen = []
        real_delete = store.delete_user_tokens
        real_publish = store.set_service_account_source

        def deleting(username):
            seen.append(("revoke", store.get_user_profile(username).service_account_source, _active(store).phase))
            return real_delete(username)

        def publishing(username, source):
            seen.append(("publish", store.get_user_profile(username).service_account_source, _active(store).phase, len(store.list_user_tokens(username))))
            return real_publish(username, source)

        monkeypatch.setattr(store, "delete_user_tokens", deleting)
        monkeypatch.setattr(store, "set_service_account_source", publishing)

        _apply(store)

        assert seen == [
            ("revoke", "internal", "pinned"),
            ("publish", "internal", "revoked", 0),
        ]

    def test_generations_increment_and_rows_are_history(self, store):
        _service_account(store)

        first = _apply(store, "partner", "s1")
        second = _apply(store, "internal", None)

        assert (first["generation"], second["generation"]) == (1, 2)
        rows = _all_transitions(store)
        assert [r[0] for r in rows] == [1, 2]
        assert [r[1] for r in rows] == ["partner", "internal"]
        assert all(r[2] == "completed" for r in rows)
        assert store.get_user_profile(CI).service_account_source == "internal"


class TestResumeByGeneration:
    def test_revocation_failure_keeps_source_unpublished_then_resumes(self, store, monkeypatch, audit_events):
        from mlflow_oidc_auth.tests.token_helpers import set_known_token
        from mlflow_oidc_auth.utils.service_accounts import ServiceAccountSourceTransitionError

        _service_account(store)
        set_known_token(store, CI, "ci-bot-token")
        real_delete = store.delete_user_tokens
        calls = {"n": 0}

        def flaky(username):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("database unavailable")
            return real_delete(username)

        monkeypatch.setattr(store, "delete_user_tokens", flaky)

        with pytest.raises(ServiceAccountSourceTransitionError) as exc:
            _apply(store)
        assert exc.value.stage == "revocation"
        assert exc.value.phase == "pinned"
        assert exc.value.generation == 1
        # The source must not display as completed while credentials are unrevoked.
        assert store.get_user_profile(CI).service_account_source == "internal"
        assert _active(store).phase == "pinned"
        assert store.list_user_tokens(CI) != []
        assert audit_events == []

        result = _apply(store)

        assert result["status"] == "completed"
        assert result["generation"] == 1
        assert result["recovered"] is True
        assert store.get_user_profile(CI).service_account_source == "partner"
        assert store.list_user_tokens(CI) == []
        assert _active(store) is None
        assert audit_events[0]["detail"]["resumed"] is True

    def test_publication_failure_leaves_revoked_then_resumes(self, store, monkeypatch):
        from mlflow_oidc_auth.tests.token_helpers import set_known_token
        from mlflow_oidc_auth.utils.service_accounts import ServiceAccountSourceTransitionError

        _service_account(store)
        set_known_token(store, CI, "ci-bot-token")
        real_publish = store.set_service_account_source
        calls = {"n": 0}

        def flaky(username, source):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("cannot write source")
            return real_publish(username, source)

        monkeypatch.setattr(store, "set_service_account_source", flaky)

        with pytest.raises(ServiceAccountSourceTransitionError) as exc:
            _apply(store)
        assert exc.value.stage == "publication"
        assert exc.value.phase == "revoked"
        assert store.get_user_profile(CI).service_account_source == "internal"
        assert store.list_user_tokens(CI) == []

        result = _apply(store)
        assert result["status"] == "completed"
        assert result["generation"] == 1
        assert store.get_user_profile(CI).service_account_source == "partner"

    def test_cache_failure_leaves_published_and_retry_only_finalizes(self, store, monkeypatch, audit_events):
        from mlflow_oidc_auth.tests.token_helpers import set_known_token
        from mlflow_oidc_auth.utils import bearer_identity_cache

        _service_account(store)
        set_known_token(store, CI, "ci-bot-token")
        monkeypatch.setattr(bearer_identity_cache, "invalidate_bearer_identity_cache", lambda: False)

        result = _apply(store)

        assert result["status"] == "finalization_pending"
        assert _active(store).phase == "published"
        assert store.get_user_profile(CI).service_account_source == "partner"
        assert audit_events == []

        # Retrying must not re-revoke; only invalidation and the audit are outstanding.
        def revoke_again(username):
            raise AssertionError("credentials must not be revoked again during finalization")

        monkeypatch.setattr(store, "delete_user_tokens", revoke_again)
        monkeypatch.setattr(store, "revoke_all_auth_sessions", revoke_again)
        monkeypatch.setattr(bearer_identity_cache, "invalidate_bearer_identity_cache", lambda: True)

        finished = _apply(store)
        assert finished["status"] == "completed"
        assert finished["generation"] == 1
        assert _active(store) is None
        assert len(audit_events) == 1

    def test_retry_after_completion_with_same_target_is_a_noop(self, store):
        _service_account(store)
        _apply(store, "partner", "s1")

        result = _apply(store, "partner", "s1")

        assert result["changed"] is False
        assert result["generation"] is None
        assert len(_all_transitions(store)) == 1

    def test_startup_sweep_recovers_a_pinned_generation(self, store):
        from mlflow_oidc_auth.tests.token_helpers import set_known_token
        from mlflow_oidc_auth.utils.service_accounts import recover_incomplete

        _service_account(store)
        set_known_token(store, CI, "ci-bot-token")
        transition, resumed = store.service_account_transition_repo.begin(CI, "partner", "s1", ADMIN)
        assert resumed is False
        assert transition.phase == "pinned"

        # A fresh process would know nothing but the row: the sweep reads the generation itself.
        counts = recover_incomplete()

        assert counts == {"completed": 1, "finalization_pending": 0, "failed": 0}
        assert store.get_user_profile(CI).service_account_source == "partner"
        assert store.list_user_tokens(CI) == []
        assert _active(store) is None

    def test_startup_sweep_recovers_a_published_generation(self, store, monkeypatch):
        from mlflow_oidc_auth.utils import bearer_identity_cache
        from mlflow_oidc_auth.utils.service_accounts import recover_incomplete

        _service_account(store)
        monkeypatch.setattr(bearer_identity_cache, "invalidate_bearer_identity_cache", lambda: False)
        _apply(store)
        assert _active(store).phase == "published"

        monkeypatch.setattr(bearer_identity_cache, "invalidate_bearer_identity_cache", lambda: True)
        counts = recover_incomplete()

        assert counts["completed"] == 1
        assert _active(store) is None

    def test_sweep_leaves_a_still_failing_generation_for_next_time(self, store, monkeypatch):
        from mlflow_oidc_auth.utils.service_accounts import recover_incomplete

        _service_account(store, "first-bot")
        _service_account(store, "second-bot")
        store.service_account_transition_repo.begin("first-bot", "partner", None, ADMIN)
        store.service_account_transition_repo.begin("second-bot", "partner", None, ADMIN)

        def flaky(username):
            raise RuntimeError("database unavailable")

        monkeypatch.setattr(store, "delete_user_tokens", flaky)

        counts = recover_incomplete()

        assert counts["failed"] == 2
        assert {t.username for t in store.service_account_transition_repo.list_incomplete()} == {"first-bot", "second-bot"}


class TestConflictsAndGuards:
    def test_a_different_target_while_open_is_refused_and_identity_kept(self, store):
        _service_account(store)
        store.service_account_transition_repo.begin(CI, "partner", "s1", ADMIN)

        with pytest.raises(MlflowException) as exc:
            _apply(store, "internal", None)
        assert exc.value.error_code == ErrorCode.Name(INVALID_STATE)
        assert store.get_user_profile(CI).service_account_source == "internal"
        active = _active(store)
        assert active.phase == "pinned"
        assert active.target_source == "partner"

    def test_subject_conflict_is_refused_before_anything_is_pinned(self, store):
        store.create_user(BOB, "Bob")
        store.user_identity_repo.link("partner", "claimed-sub", BOB)
        _service_account(store)

        with pytest.raises(MlflowException) as exc:
            _apply(store, "partner", "claimed-sub")
        assert exc.value.error_code == ErrorCode.Name(RESOURCE_ALREADY_EXISTS)
        assert store.get_user_profile(CI).service_account_source == "internal"
        assert _all_transitions(store) == []
        assert store.user_identity_repo.get_username_by_identity("partner", "claimed-sub") == BOB

    def test_a_person_account_is_rejected(self, store):
        store.create_user(BOB, "Bob")

        with pytest.raises(MlflowException) as exc:
            from mlflow_oidc_auth.utils.service_accounts import apply_source

            apply_source(BOB, "internal", None, actor=ADMIN)
        assert exc.value.error_code == ErrorCode.Name(INVALID_PARAMETER_VALUE)
        assert _all_transitions(store, BOB) == []

    def test_an_unknown_source_is_a_value_error(self, store):
        _service_account(store)
        with pytest.raises(ValueError):
            _apply(store, "nope", None)

    def test_internal_source_with_subject_is_a_value_error(self, store):
        _service_account(store)
        with pytest.raises(ValueError):
            _apply(store, "internal", "s1")


class TestCredentialIssuanceBlocking:
    def test_repository_refuses_any_token_while_a_generation_is_open(self, store):
        _service_account(store)
        store.service_account_transition_repo.begin(CI, "partner", None, ADMIN)

        with pytest.raises(MlflowException) as exc:
            store.create_user_token(CI, "ci", datetime.now(timezone.utc) + timedelta(days=1), created_by=ADMIN)
        assert exc.value.error_code == ErrorCode.Name(INVALID_STATE)

    def test_issuance_works_again_once_the_generation_completes(self, store):
        _service_account(store)
        store.service_account_transition_repo.begin(CI, "partner", None, ADMIN)
        # Drive the open generation to completion by running the same request.
        _apply(store, "partner", None)

        record, _ = store.create_user_token(CI, "ci", datetime.now(timezone.utc) + timedelta(days=1), created_by=ADMIN)
        assert record.name == "ci"

    def test_router_refuses_a_token_while_a_change_is_open(self, store, monkeypatch):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        import mlflow_oidc_auth.dependencies as dependencies
        import mlflow_oidc_auth.routers.users as users_router

        async def username(request=None):
            return ADMIN

        async def is_admin(request=None):
            return True

        monkeypatch.setattr(dependencies, "get_username", username)
        monkeypatch.setattr(dependencies, "get_is_admin", is_admin)
        app = FastAPI()
        app.include_router(users_router.users_router)
        app.dependency_overrides[dependencies.require_interactive_login] = lambda: None
        _service_account(store)
        store.service_account_transition_repo.begin(CI, "partner", None, ADMIN)

        with TestClient(app) as client:
            response = client.post(
                "/api/2.0/mlflow/users/ci-bot/tokens",
                json={"name": "t", "expiration": (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")},
            )
        assert response.status_code == 409, response.text
        assert "source change in progress" in response.json()["detail"]


class TestHttpSemantics:
    @pytest.fixture
    def admin_api(self, store, monkeypatch):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        import mlflow_oidc_auth.dependencies as dependencies
        import mlflow_oidc_auth.routers.users as users_router
        from mlflow_oidc_auth import utils

        async def username(request=None):
            return ADMIN

        async def is_admin(request=None):
            return True

        monkeypatch.setattr(dependencies, "get_username", username)
        monkeypatch.setattr(dependencies, "get_is_admin", is_admin)
        monkeypatch.setattr(utils, "get_username", username)
        monkeypatch.setattr(utils, "get_is_admin", is_admin)
        app = FastAPI()
        app.include_router(users_router.users_router)
        app.dependency_overrides[dependencies.require_interactive_login] = lambda: None
        with TestClient(app) as client:
            yield client

    URL = f"/api/2.0/mlflow/users/{CI}/service-account-source"

    def test_success_body_carries_generation_and_status(self, store, admin_api, audit_events):
        from mlflow_oidc_auth.tests.token_helpers import set_known_token

        _service_account(store)
        set_known_token(store, CI, "ci-bot-token")

        response = admin_api.put(self.URL, json={"source": "partner", "subject": "s1"})

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["service_account_source"] == "partner"
        assert body["generation"] == 1
        assert body["status"] == "completed"
        assert body["changed"] is True
        assert body["recovered"] is False
        assert body["revoked_tokens"] >= 1
        # The audit is emitted by the staged operation, not after the response.
        assert len(audit_events) == 1

    def test_revocation_failure_is_503_and_retry_completes(self, store, admin_api, monkeypatch):
        from mlflow_oidc_auth.tests.token_helpers import set_known_token

        _service_account(store)
        set_known_token(store, CI, "ci-bot-token")
        real_delete = store.delete_user_tokens
        calls = {"n": 0}

        def flaky(username):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("database unavailable")
            return real_delete(username)

        monkeypatch.setattr(store, "delete_user_tokens", flaky)

        failed = admin_api.put(self.URL, json={"source": "partner"})
        assert failed.status_code == 503, failed.text
        body = failed.json()
        assert body["generation"] == 1
        assert body["phase"] == "pinned"
        assert body["failed_stage"] == "revocation"
        assert "resume" in body
        # Not shown as completed while the old credential could still work.
        assert store.get_user_profile(CI).service_account_source == "internal"

        retried = admin_api.put(self.URL, json={"source": "partner"})
        assert retried.status_code == 200, retried.text
        assert retried.json()["generation"] == 1
        assert retried.json()["recovered"] is True
        assert store.list_user_tokens(CI) == []

    def test_cache_failure_is_200_finalization_pending_then_completes(self, store, admin_api, monkeypatch, audit_events):
        from mlflow_oidc_auth.utils import bearer_identity_cache

        _service_account(store)
        monkeypatch.setattr(bearer_identity_cache, "invalidate_bearer_identity_cache", lambda: False)

        pending = admin_api.put(self.URL, json={"source": "partner"})
        assert pending.status_code == 200, pending.text
        body = pending.json()
        assert body["status"] == "finalization_pending"
        assert body["generation"] == 1
        assert "resume" in body
        assert audit_events == []

        monkeypatch.setattr(bearer_identity_cache, "invalidate_bearer_identity_cache", lambda: True)
        finished = admin_api.put(self.URL, json={"source": "partner"})
        assert finished.status_code == 200, finished.text
        assert finished.json()["status"] == "completed"
        assert len(audit_events) == 1

    def test_open_change_to_a_different_target_is_409(self, store, admin_api):
        _service_account(store)
        store.service_account_transition_repo.begin(CI, "partner", None, ADMIN)

        response = admin_api.put(self.URL, json={"source": "internal"})

        assert response.status_code == 409, response.text
        assert "already in phase" in response.json()["detail"]
        assert store.get_user_profile(CI).service_account_source == "internal"

    def test_subject_conflict_is_409_and_changes_nothing(self, store, admin_api):
        store.create_user(BOB, "Bob")
        store.user_identity_repo.link("partner", "claimed-sub", BOB)
        _service_account(store)

        response = admin_api.put(self.URL, json={"source": "partner", "subject": "claimed-sub"})

        assert response.status_code == 409, response.text
        assert store.get_user_profile(CI).service_account_source == "internal"
        assert _all_transitions(store) == []

    def test_a_person_account_is_409(self, store, admin_api):
        store.create_user(BOB, "Bob")
        response = admin_api.put(f"/api/2.0/mlflow/users/{BOB}/service-account-source", json={"source": "internal"})
        assert response.status_code == 409, response.text


class TestCompatibility:
    def test_unchanged_internal_source_revokes_nothing(self, store):
        from mlflow_oidc_auth.tests.token_helpers import set_known_token

        _service_account(store)
        set_known_token(store, CI, "ci-bot-token")

        result = _apply(store, "internal", None)

        assert result["changed"] is False
        assert result["generation"] is None
        assert store.list_user_tokens(CI) != []
        assert _all_transitions(store) == []

    def test_unchanged_external_source_keeps_credentials_and_reconciles_subject(self, store):
        from mlflow_oidc_auth.tests.token_helpers import set_known_token

        _service_account(store, source="partner")
        store.user_identity_repo.link("partner", "s1", CI, allow_additional_provider=True)
        set_known_token(store, CI, "legacy-token")  # e.g. minted before this release

        result = _apply(store, "partner", "s2")

        assert result["changed"] is False
        assert store.user_identity_repo.list_identities_for_username(CI) == [("partner", "s2")]
        # A no-change request never revoked: same semantics as before generations existed.
        assert store.list_user_tokens(CI) != []
        assert _all_transitions(store) == []

    def test_switching_back_internal_never_restores_old_tokens(self, store):
        from mlflow_oidc_auth.tests.token_helpers import set_known_token

        _service_account(store)
        set_known_token(store, CI, "the-old-secret")

        _apply(store, "partner", None)
        assert store.authenticate_user(CI, "the-old-secret") is False
        _apply(store, "internal", None)
        assert store.authenticate_user(CI, "the-old-secret") is False

        from mlflow_oidc_auth.tests.token_helpers import issue_token

        new_secret = issue_token(store, CI)
        assert store.authenticate_user(CI, new_secret) is True
        assert store.list_user_tokens(CI)[0].name == "default"

    def test_external_account_is_refused_for_token_creation(self, store):
        from fastapi import HTTPException

        from mlflow_oidc_auth.routers.users import _refuse_tokens_for_external_service_account

        _service_account(store, source="partner")
        with pytest.raises(HTTPException) as exc:
            _refuse_tokens_for_external_service_account(CI)
        assert exc.value.status_code == 409

    def test_normal_internal_token_flow_is_unaffected(self, store):
        from mlflow_oidc_auth.tests.token_helpers import issue_token

        _service_account(store)
        secret = issue_token(store, CI)
        assert store.authenticate_user(CI, secret) is True

    def test_a_person_can_still_issue_tokens(self, store):
        from mlflow_oidc_auth.tests.token_helpers import issue_token

        store.create_user(BOB, "Bob")
        secret = issue_token(store, BOB)
        assert store.authenticate_user(BOB, secret) is True
