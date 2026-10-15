"""The credential rotation service: idempotency, validation gating, failure containment."""

import asyncio

import pytest
from authlib.integrations.base_client.errors import OAuthError

from mlflow_oidc_auth import oauth as oauth_module
from mlflow_oidc_auth.config import config
from mlflow_oidc_auth.credentials import generations as gen_service
from mlflow_oidc_auth.credentials.generations import (
    REASON_CLEANUP,
    REASON_CONFLICT,
    REASON_INVALID_CREDENTIALS,
    REASON_DISCOVERY,
    REASON_UNKNOWN_PROVIDER,
    RESULT_FAILED,
    RESULT_ROTATED,
    RESULT_UNCHANGED,
    CredentialSnapshot,
    publish_refresh,
    validate_new_credentials,
)
from mlflow_oidc_auth.credentials.vault import get_credential_vault
from mlflow_oidc_auth.provider_registry import DEFAULT_PROVIDER_ID, ProviderConfig, RegistryLoadResult
from mlflow_oidc_auth.repository.credential_generation import ActiveGenerationConflict

DISCOVERY = "https://idp.example/.well-known/openid-configuration"
METADATA = {"token_endpoint": "https://idp.example/token", "issuer": "https://idp.example"}
SETTINGS = {"scope": "openid", "code_challenge_method": "S256", "verify": True, "public_client": False, "redirect_uri": None}


@pytest.fixture
def store(tmp_path):
    from mlflow_oidc_auth.sqlalchemy_store import SqlAlchemyStore

    s = SqlAlchemyStore()
    s.init_db(f"sqlite:///{tmp_path / 'auth.db'}")
    yield s
    s.engine.dispose()


@pytest.fixture(autouse=True)
def harness(monkeypatch, store):
    oauth_module.reset_oauth()
    monkeypatch.setattr(gen_service, "store", store)
    monkeypatch.setattr(
        config,
        "AUTH_PROVIDERS",
        RegistryLoadResult(providers=[ProviderConfig(id="default", type="oidc", audience="mlflow")], errors=[], source="legacy"),
        raising=False,
    )
    monkeypatch.setattr(config, "OIDC_CREDENTIAL_VALIDATION_TIMEOUT_SECONDS", 5, raising=False)
    audits = []
    monkeypatch.setattr(gen_service, "emit_audit_event", lambda *a, **kw: audits.append((a, kw)))
    yield audits
    oauth_module.reset_oauth()


def _snapshot(*, secret="secret-version-1", fingerprint="a" * 64, public=False):
    return CredentialSnapshot(
        provider_id=DEFAULT_PROVIDER_ID,
        client_id="client-1",
        client_secret=None if public else secret,
        public_client=public,
        discovery_url=DISCOVERY,
        settings=dict(SETTINGS, public_client=public),
        fingerprint=fingerprint,
    )


class SimpleGeneration:
    """The fields an ActiveGenerationConflict winner needs."""

    def __init__(self, generation_id, fingerprint):
        self.generation_id = generation_id
        self.fingerprint = fingerprint


def _bootstrap(store, snapshot):
    encrypted = get_credential_vault().encrypt_secret(snapshot.client_secret) if snapshot.client_secret else None
    return store.bootstrap_credential_generation(
        DEFAULT_PROVIDER_ID,
        client_id=snapshot.client_id,
        encrypted_secret=encrypted,
        discovery_url=snapshot.discovery_url,
        client_settings=snapshot.settings,
        fingerprint=snapshot.fingerprint,
    )


class TestRefreshResults:
    @pytest.mark.asyncio
    async def test_identical_material_is_unchanged_and_touches_no_rows(self, store, monkeypatch, harness):
        snapshot = _snapshot()
        active = _bootstrap(store, snapshot)
        monkeypatch.setattr(gen_service, "snapshot_provider_credentials", lambda pid: snapshot)

        result = await publish_refresh(DEFAULT_PROVIDER_ID, actor="admin")

        assert result.result == RESULT_UNCHANGED
        assert result.active.generation_id == active.generation_id
        assert len(store.list_credential_generations(DEFAULT_PROVIDER_ID)) == 1
        assert any("auth.credential_refresh" == a[0] for a, _ in harness)

    @pytest.mark.asyncio
    async def test_unknown_provider_fails_without_touching_the_store(self, store, monkeypatch):
        snapshot = _snapshot()
        _bootstrap(store, snapshot)
        monkeypatch.setattr(gen_service, "snapshot_provider_credentials", lambda pid: snapshot)

        result = await publish_refresh("nope")

        assert result.result == RESULT_FAILED
        assert result.reason == REASON_UNKNOWN_PROVIDER

    @pytest.mark.asyncio
    async def test_no_generation_yet_is_bootstrapped_without_a_probe(self, store, monkeypatch):
        snapshot = _snapshot(fingerprint="a" * 64)
        monkeypatch.setattr(gen_service, "snapshot_provider_credentials", lambda pid: snapshot)

        async def _must_not_probe(*args, **kwargs):
            raise AssertionError("bootstrap must not probe the IdP")

        monkeypatch.setattr(gen_service, "validate_new_credentials", _must_not_probe)

        result = await publish_refresh(DEFAULT_PROVIDER_ID)

        assert result.result == RESULT_ROTATED
        assert store.get_active_credential_generation(DEFAULT_PROVIDER_ID).fingerprint == "a" * 64

    @pytest.mark.asyncio
    async def test_unusable_configuration_keeps_the_active_generation(self, store, monkeypatch):
        active = _bootstrap(store, _snapshot())
        monkeypatch.setattr(gen_service, "snapshot_provider_credentials", lambda pid: None)

        result = await publish_refresh(DEFAULT_PROVIDER_ID)

        assert result.result == RESULT_FAILED
        assert store.get_active_credential_generation(DEFAULT_PROVIDER_ID).generation_id == active.generation_id
        assert len(store.list_credential_generations(DEFAULT_PROVIDER_ID)) == 1


class TestValidationGating:
    @pytest.mark.asyncio
    async def test_invalid_client_rejects_the_rotation(self, store, monkeypatch, harness):
        old = _bootstrap(store, _snapshot(fingerprint="a" * 64))
        new = _snapshot(secret="secret-version-2", fingerprint="b" * 64)
        monkeypatch.setattr(gen_service, "snapshot_provider_credentials", lambda pid: new)

        async def _validate(snapshot, timeout_seconds=None):
            return f"invalid:{REASON_INVALID_CREDENTIALS}"

        monkeypatch.setattr(gen_service, "validate_new_credentials", _validate)

        result = await publish_refresh(DEFAULT_PROVIDER_ID, actor="admin")

        assert result.result == RESULT_FAILED
        assert result.reason == REASON_INVALID_CREDENTIALS
        assert store.get_active_credential_generation(DEFAULT_PROVIDER_ID).generation_id == old.generation_id
        assert len(store.list_credential_generations(DEFAULT_PROVIDER_ID)) == 1
        assert any("auth.credential_refresh_failed" == a[0] for a, _ in harness)

    @pytest.mark.asyncio
    async def test_validated_new_material_is_published(self, store, monkeypatch):
        old = _bootstrap(store, _snapshot(fingerprint="a" * 64))
        new = _snapshot(secret="secret-version-2", fingerprint="b" * 64)
        monkeypatch.setattr(gen_service, "snapshot_provider_credentials", lambda pid: new)
        monkeypatch.setattr(gen_service, "validate_new_credentials", lambda snapshot, timeout_seconds=None: _accepted())

        result = await publish_refresh(DEFAULT_PROVIDER_ID, actor="admin")

        assert result.result == RESULT_ROTATED
        assert result.active.fingerprint == "b" * 64
        assert result.retired_generation_id == old.generation_id
        generations = store.list_credential_generations(DEFAULT_PROVIDER_ID)
        assert [g.status for g in generations] == ["active", "retired"]
        # The switch happened in one transaction: the retired row already has its deadline.
        retired = store.get_credential_generation(DEFAULT_PROVIDER_ID, old.generation_id)
        assert retired.retired_at is not None and retired.retain_until > retired.retired_at


class TestFailureContainmentAndConcurrency:
    @pytest.mark.asyncio
    async def test_a_failed_rotation_transaction_reports_failure_and_keeps_active(self, store, monkeypatch):
        active = _bootstrap(store, _snapshot(fingerprint="a" * 64))
        new = _snapshot(secret="secret-version-2", fingerprint="b" * 64)
        monkeypatch.setattr(gen_service, "snapshot_provider_credentials", lambda pid: new)
        monkeypatch.setattr(gen_service, "validate_new_credentials", lambda snapshot, timeout_seconds=None: _accepted())

        def _boom(*args, **kwargs):
            raise RuntimeError("cleanup failed")

        monkeypatch.setattr(store, "rotate_credential_generation", _boom)

        result = await publish_refresh(DEFAULT_PROVIDER_ID)

        assert result.result == RESULT_FAILED
        assert result.reason == REASON_CLEANUP
        assert store.get_active_credential_generation(DEFAULT_PROVIDER_ID).generation_id == active.generation_id
        assert len(store.list_credential_generations(DEFAULT_PROVIDER_ID)) == 1

    @pytest.mark.asyncio
    async def test_losing_a_race_to_the_same_material_adopts_the_winner(self, store, monkeypatch):
        # The loser read the old active row (fingerprint a) while another process was committing
        # fingerprint b — which is exactly the material the loser validated. It adopts it.
        old = _bootstrap(store, _snapshot(fingerprint="a" * 64))
        winner = SimpleGeneration("g-winner", "b" * 64)
        monkeypatch.setattr(store, "get_active_credential_generation", lambda pid: old)
        monkeypatch.setattr(gen_service, "snapshot_provider_credentials", lambda pid: _snapshot(secret="secret-version-2", fingerprint="b" * 64))
        monkeypatch.setattr(gen_service, "validate_new_credentials", lambda snapshot, timeout_seconds=None: _accepted())
        monkeypatch.setattr(store, "rotate_credential_generation", lambda *a, **k: (_ for _ in ()).throw(ActiveGenerationConflict(winner)))
        monkeypatch.setattr(oauth_module, "register_generation_client", lambda generation: object())

        result = await publish_refresh(DEFAULT_PROVIDER_ID)

        assert result.result == RESULT_ROTATED
        assert result.active.generation_id == "g-winner"

    @pytest.mark.asyncio
    async def test_losing_a_race_to_different_material_is_a_conflict_failure(self, store, monkeypatch):
        old = _bootstrap(store, _snapshot(fingerprint="a" * 64))
        winner = SimpleGeneration("g-winner", "d" * 64)
        monkeypatch.setattr(store, "get_active_credential_generation", lambda pid: old)
        monkeypatch.setattr(gen_service, "snapshot_provider_credentials", lambda pid: _snapshot(secret="secret-version-2", fingerprint="b" * 64))
        monkeypatch.setattr(gen_service, "validate_new_credentials", lambda snapshot, timeout_seconds=None: _accepted())
        monkeypatch.setattr(store, "rotate_credential_generation", lambda *a, **k: (_ for _ in ()).throw(ActiveGenerationConflict(winner)))

        result = await publish_refresh(DEFAULT_PROVIDER_ID)

        assert result.result == RESULT_FAILED
        assert result.reason == REASON_CONFLICT

    @pytest.mark.asyncio
    async def test_the_rotation_switches_clients_scoped_to_one_provider(self, store, monkeypatch):
        from mlflow_oidc_auth.auth import _provider_jwks_cache

        old = _bootstrap(store, _snapshot(fingerprint="a" * 64))
        oauth_module.register_generation_client(old)
        # Another provider keeps its own cache entry.
        _provider_jwks_cache[("other", "https://other/disc")] = {"keys": ["other-key"]}

        new = _snapshot(secret="secret-version-2", fingerprint="b" * 64)
        monkeypatch.setattr(gen_service, "snapshot_provider_credentials", lambda pid: new)
        monkeypatch.setattr(gen_service, "validate_new_credentials", lambda snapshot, timeout_seconds=None: _accepted())

        result = await publish_refresh(DEFAULT_PROVIDER_ID)

        active_client = oauth_module.get_generation_client(DEFAULT_PROVIDER_ID, result.active.generation_id)
        retired_client = oauth_module.get_generation_client(DEFAULT_PROVIDER_ID, old.generation_id)
        assert active_client is not None and retired_client is not None
        assert active_client is not retired_client
        # The legacy alias follows the active generation.
        assert oauth_module.oauth.oidc is active_client
        # Only this provider's bearer JWKS cache was evicted.
        assert ("other", "https://other/disc") in _provider_jwks_cache

    @pytest.mark.asyncio
    async def test_pruned_generations_release_their_in_process_clients(self, store, monkeypatch):
        _bootstrap(store, _snapshot(fingerprint="a" * 64))
        new = _snapshot(secret="secret-version-2", fingerprint="b" * 64)
        monkeypatch.setattr(gen_service, "snapshot_provider_credentials", lambda pid: new)
        monkeypatch.setattr(gen_service, "validate_new_credentials", lambda snapshot, timeout_seconds=None: _accepted())
        monkeypatch.setattr(config, "OIDC_CREDENTIAL_GENERATION_RETENTION_SECONDS", 0, raising=False)
        discarded = []
        monkeypatch.setattr(oauth_module, "discard_generation_client", lambda pid, gid: discarded.append((pid, gid)))

        result = await publish_refresh(DEFAULT_PROVIDER_ID)

        # Zero retention: the old generation was pruned inside the rotation and its client
        # released in this process.
        assert result.pruned_generation_ids
        assert all((DEFAULT_PROVIDER_ID, gid) in discarded for gid in result.pruned_generation_ids)


class TestCrossProcessReconciliation:
    @pytest.mark.asyncio
    async def test_a_restarted_process_rebuilds_the_same_clients_and_sees_the_rotation(self, store, monkeypatch):
        # Process A bootstraps, rotates, and holds both client names.
        g1 = _bootstrap(store, _snapshot(fingerprint="a" * 64))
        oauth_module.register_generation_client(g1)
        new = _snapshot(secret="secret-version-2", fingerprint="b" * 64)
        monkeypatch.setattr(gen_service, "snapshot_provider_credentials", lambda pid: new)
        monkeypatch.setattr(gen_service, "validate_new_credentials", lambda snapshot, timeout_seconds=None: _accepted())
        outcome = await publish_refresh(DEFAULT_PROVIDER_ID)

        name_a_active = oauth_module.generation_client_name(DEFAULT_PROVIDER_ID, outcome.active.generation_id)
        name_a_retired = oauth_module.generation_client_name(DEFAULT_PROVIDER_ID, g1.generation_id)

        # "Process B": a fresh OAuth registry with only the shared rows to rebuild from.
        oauth_module.reset_oauth()
        rebuilt_active = gen_service.get_active_generation(DEFAULT_PROVIDER_ID)
        rebuilt_client = gen_service.generation_client(DEFAULT_PROVIDER_ID, rebuilt_active.generation_id)
        rebuilt_retired = gen_service.generation_client(DEFAULT_PROVIDER_ID, g1.generation_id)

        assert rebuilt_active.generation_id == outcome.active.generation_id
        assert rebuilt_client.name == name_a_active
        assert rebuilt_retired.name == name_a_retired
        assert rebuilt_client.client_id == "client-1"
        assert rebuilt_retired is not rebuilt_client
        # The legacy alias follows the active generation on the restarted process too.
        assert oauth_module.oauth.oidc is rebuilt_client

    @pytest.mark.asyncio
    async def test_two_refresh_calls_with_the_same_material_publish_one_generation(self, store, monkeypatch):
        snapshot = _snapshot()
        monkeypatch.setattr(gen_service, "snapshot_provider_credentials", lambda pid: snapshot)

        first = await publish_refresh(DEFAULT_PROVIDER_ID)
        second = await publish_refresh(DEFAULT_PROVIDER_ID)

        assert first.result == RESULT_ROTATED  # first-ever bootstrap
        assert second.result == RESULT_UNCHANGED
        assert second.active.generation_id == first.active.generation_id
        assert len(store.list_credential_generations(DEFAULT_PROVIDER_ID)) == 1


class TestPinnedClientRetention:
    def test_maintenance_uses_the_pinned_generation_while_retained_and_not_after(self, store):
        from datetime import timedelta

        old = _bootstrap(store, _snapshot(fingerprint="a" * 64))
        outcome = store.rotate_credential_generation(
            DEFAULT_PROVIDER_ID,
            client_id="client-1",
            encrypted_secret=get_credential_vault().encrypt_secret("secret-version-2"),
            discovery_url=DISCOVERY,
            client_settings=dict(SETTINGS),
            fingerprint="b" * 64,
            retention_seconds=3600,
            in_flight_ttl_seconds=900,
        )
        oauth_module.register_generation_client(outcome.retired)

        # Both the retained old generation and the active one serve maintenance.
        assert gen_service.usable_pinned_client(DEFAULT_PROVIDER_ID, old.generation_id) is not None
        assert gen_service.usable_pinned_client(DEFAULT_PROVIDER_ID, outcome.active.generation_id) is not None
        # A purged/unknown generation gives None so the caller falls back.
        assert gen_service.usable_pinned_client(DEFAULT_PROVIDER_ID, "gone") is None

        # After the retention deadline (and the resulting prune), maintenance no longer
        # materialises the old generation.
        later = outcome.retired.retain_until + timedelta(seconds=1)
        store.prune_credential_generations(DEFAULT_PROVIDER_ID, in_flight_ttl_seconds=900, moment=later)
        assert gen_service.usable_pinned_client(DEFAULT_PROVIDER_ID, old.generation_id) is None


class TestProbeSemantics:
    def _install_probe(self, monkeypatch, *, metadata=METADATA, fetch=None, load_delay=None):
        discarded = []

        class _ProbeClient:
            def __init__(self):
                self.fetch_calls = []

            async def load_server_metadata(self):
                if load_delay is not None:
                    await asyncio.sleep(load_delay)
                if isinstance(metadata, Exception):
                    raise metadata
                return metadata

            async def fetch_access_token(self, **kwargs):
                self.fetch_calls.append(kwargs)
                if callable(fetch):
                    return await fetch()
                if fetch is None:
                    return {"access_token": "probe-at", "token_type": "Bearer"}
                raise fetch

        probe = _ProbeClient()

        def _build(name, *args, **kwargs):
            probe.name = name
            return probe

        monkeypatch.setattr(oauth_module, "build_ephemeral_client", _build)
        monkeypatch.setattr(oauth_module, "discard_client", lambda name: discarded.append(name))
        return probe, discarded

    @pytest.mark.asyncio
    async def test_successful_probe_is_accepted_and_client_is_discarded(self, monkeypatch):
        probe, discarded = self._install_probe(monkeypatch)

        verdict = await validate_new_credentials(_snapshot(), timeout_seconds=5)

        assert verdict == "accepted"
        assert discarded == [probe.name]
        # The probe never entered the generation maps.
        assert oauth_module.get_generation_client(DEFAULT_PROVIDER_ID, probe.name) is None

    @pytest.mark.asyncio
    async def test_invalid_client_error_is_invalid(self, monkeypatch):
        self._install_probe(monkeypatch, fetch=OAuthError("invalid_client", "bad secret"))

        verdict = await validate_new_credentials(_snapshot(), timeout_seconds=5)

        assert verdict == f"invalid:{REASON_INVALID_CREDENTIALS}"

    @pytest.mark.asyncio
    async def test_grant_disabled_errors_are_accepted(self, monkeypatch):
        for code in ("invalid_grant", "unauthorized_client", "unsupported_grant_type"):
            self._install_probe(monkeypatch, fetch=OAuthError(code, "not allowed"))
            assert await validate_new_credentials(_snapshot(), timeout_seconds=5) == "accepted", code

    @pytest.mark.asyncio
    async def test_discovery_timeout_is_invalid(self, monkeypatch):
        self._install_probe(monkeypatch, load_delay=0.2)

        verdict = await validate_new_credentials(_snapshot(), timeout_seconds=0.05)

        assert verdict == f"invalid:{REASON_DISCOVERY}"

    @pytest.mark.asyncio
    async def test_a_discovery_document_without_a_token_endpoint_is_invalid(self, monkeypatch):
        self._install_probe(monkeypatch, metadata={"issuer": "https://idp.example"})

        verdict = await validate_new_credentials(_snapshot(), timeout_seconds=5)

        assert verdict == f"invalid:{REASON_DISCOVERY}"

    @pytest.mark.asyncio
    async def test_a_public_client_skips_the_secret_probe(self, monkeypatch):
        probe, _discarded = self._install_probe(monkeypatch)

        verdict = await validate_new_credentials(_snapshot(public=True), timeout_seconds=5)

        assert verdict == "accepted"
        assert probe.fetch_calls == []


async def _accepted():
    return "accepted"
