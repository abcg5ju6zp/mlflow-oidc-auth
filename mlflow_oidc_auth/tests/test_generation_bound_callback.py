"""The credential-generation pinning of the OIDC callback.

A login started against generation G1 must exchange its code exactly once with G1's client even
when G2 is active by the time the callback arrives; an unregistered/expired generation ends the
attempt with a stable error and zero token requests; a failed exchange never tries another
generation's credentials.
"""

from types import SimpleNamespace

import pytest

import mlflow_oidc_auth.routers.auth as auth_router_mod
from mlflow_oidc_auth.provider_registry import ProviderConfig, RegistryLoadResult
from mlflow_oidc_auth.repository.auth_state import AuthAttempt

ENTRA = "https://login.entra.invalid/tenant"
TOKEN_RESPONSE = {
    "access_token": "at",
    "userinfo": {"sub": "auth0|1", "email": "alice@corp.com", "name": "Alice", "groups": ["mlflow"]},
}


class DummyRequest:
    def __init__(self, **query):
        self.session = {}
        self.base_url = "http://testserver"
        self.query_params = _Query(query)
        self.scope = {"root_path": ""}
        self.state = SimpleNamespace()


class _Query(dict):
    def getlist(self, key):
        value = self.get(key)
        if value is None:
            return []
        return value if isinstance(value, list) else [value]


@pytest.fixture
def default_provider(monkeypatch):
    registry = RegistryLoadResult(
        providers=[ProviderConfig(id="default", type="oidc", audience="mlflow", issuer=ENTRA)],
        errors=[],
        source="legacy",
    )
    monkeypatch.setattr(auth_router_mod.config, "AUTH_PROVIDERS", registry, raising=False)
    monkeypatch.setattr(auth_router_mod.config, "OIDC_GROUP_DETECTION_PLUGIN", None, raising=False)
    monkeypatch.setattr(auth_router_mod.config, "OIDC_GROUPS_ATTRIBUTE", "groups", raising=False)
    monkeypatch.setattr(auth_router_mod.config, "OIDC_GROUP_NAME", ["mlflow"], raising=False)
    monkeypatch.setattr(auth_router_mod.config, "OIDC_ADMIN_GROUP_NAME", ["mlflow-admin"], raising=False)
    monkeypatch.setattr(auth_router_mod.config, "MLFLOW_ENABLE_WORKSPACES", False, raising=False)

    async def _no_iss(provider):
        return False

    monkeypatch.setattr(auth_router_mod, "_iss_parameter_supported", _no_iss)
    return registry


@pytest.fixture
def provisioning(monkeypatch):
    """Stub everything after the exchange so the callback can complete successfully."""
    monkeypatch.setattr(auth_router_mod.store, "has_user", lambda username: True, raising=False)
    monkeypatch.setattr(auth_router_mod.store, "get_groups_for_user", lambda username: ["mlflow"], raising=False)
    monkeypatch.setattr("mlflow_oidc_auth.user.create_user", lambda **kwargs: None)
    monkeypatch.setattr("mlflow_oidc_auth.user.populate_groups", lambda **kwargs: None)
    monkeypatch.setattr("mlflow_oidc_auth.user.update_user", lambda **kwargs: None)

    class _Identities:
        def list_providers_for_username(self, username):
            return ["default"]

        def get_username_by_identity(self, provider_id, subject):
            return "alice@corp.com"

        def link(self, *args, **kwargs):
            return True

    monkeypatch.setattr(auth_router_mod.store, "user_identity_repo", _Identities(), raising=False)


def _install_attempt(monkeypatch, generation_id="g1"):
    monkeypatch.setattr(
        auth_router_mod.store,
        "consume_auth_state",
        lambda state: AuthAttempt(state=state, provider_id="default", credential_generation_id=generation_id) if state == "state-1" else None,
        raising=False,
    )


def _fake_client(exchange_impl):
    return SimpleNamespace(authorize_access_token=exchange_impl, name="pinned-client", load_server_metadata=None)


class TestExchangeIsPinned:
    @pytest.mark.asyncio
    async def test_the_callback_exchanges_with_the_pinned_generation_exactly_once(self, default_provider, provisioning, monkeypatch):
        _install_attempt(monkeypatch, "g1")
        calls = {"g1": 0, "g2": 0}
        materialised: dict = {}

        async def _g1(request):
            calls["g1"] += 1
            return dict(TOKEN_RESPONSE)

        async def _g2(request):
            calls["g2"] += 1
            return {"access_token": "should-never-happen"}

        g1 = _fake_client(_g1)
        g2 = _fake_client(_g2)
        loaded = SimpleNamespace(provider_id="default", generation_id="g1", usable_at=lambda moment=None: True)
        get_calls = []

        def _get(provider_id, generation_id):
            get_calls.append(generation_id)
            return loaded

        def _materialise(provider_id, generation_id, generation=None):
            materialised["row"] = generation
            return {"g1": g1, "g2": g2}[generation_id]

        monkeypatch.setattr(auth_router_mod.credential_generations, "get_generation", _get)
        monkeypatch.setattr(auth_router_mod.credential_generations, "generation_client", _materialise)

        request = DummyRequest(state="state-1", code="the-code")
        username, errors = await auth_router_mod._process_oidc_callback_fastapi(request, request.session)

        assert errors == []
        assert username == "alice@corp.com"
        assert calls == {"g1": 1, "g2": 0}
        # The generation row is read once and handed to materialisation (no second row read),
        # and the session that opens next is pinned to the same generation.
        assert get_calls == ["g1"]
        assert materialised["row"] is loaded
        assert request.state.pending_credential_generation_id == "g1"

    @pytest.mark.asyncio
    async def test_a_failed_exchange_never_tries_another_generation(self, default_provider, monkeypatch):
        _install_attempt(monkeypatch, "g1")
        calls = {"g1": 0, "g2": 0}

        async def _boom(request):
            calls["g1"] += 1
            raise RuntimeError("invalid_client")

        async def _g2(request):
            calls["g2"] += 1
            return {}

        g1 = _fake_client(_boom)
        g2 = _fake_client(_g2)
        monkeypatch.setattr(
            auth_router_mod.credential_generations,
            "get_generation",
            lambda provider_id, generation_id: SimpleNamespace(provider_id=provider_id, generation_id=generation_id, usable_at=lambda moment=None: True),
        )
        monkeypatch.setattr(
            auth_router_mod.credential_generations,
            "generation_client",
            lambda provider_id, generation_id, generation=None: {"g1": g1, "g2": g2}[generation_id],
        )

        request = DummyRequest(state="state-1", code="the-code")
        _, errors = await auth_router_mod._process_oidc_callback_fastapi(request, request.session)

        assert errors
        assert calls == {"g1": 1, "g2": 0}
        assert not hasattr(request.state, "pending_credential_generation_id")


class TestExpiredOrMissingGenerations:
    @pytest.mark.asyncio
    async def test_a_purged_generation_ends_the_attempt_without_a_token_request(self, default_provider, monkeypatch):
        _install_attempt(monkeypatch, "gone")
        exchange_calls = []

        async def _exchange(request):
            exchange_calls.append(1)
            return {}

        fake = _fake_client(_exchange)
        monkeypatch.setattr(auth_router_mod.credential_generations, "get_generation", lambda provider_id, generation_id: None)
        monkeypatch.setattr(auth_router_mod.credential_generations, "generation_client", lambda provider_id, generation_id: fake)

        request = DummyRequest(state="state-1", code="the-code")
        _, errors = await auth_router_mod._process_oidc_callback_fastapi(request, request.session)

        assert auth_router_mod.LOGIN_GENERATION_EXPIRED_ERROR in errors
        assert exchange_calls == []

    @pytest.mark.asyncio
    async def test_a_generation_past_its_retention_deadline_is_refused(self, default_provider, monkeypatch):
        _install_attempt(monkeypatch, "g-old")
        exchange_calls = []
        expired = SimpleNamespace(provider_id="default", generation_id="g-old", usable_at=lambda moment=None: False)
        monkeypatch.setattr(auth_router_mod.credential_generations, "get_generation", lambda provider_id, generation_id: expired)
        monkeypatch.setattr(
            auth_router_mod.credential_generations,
            "generation_client",
            lambda provider_id, generation_id: _fake_client(lambda request: exchange_calls.append(1)),
        )

        request = DummyRequest(state="state-1", code="the-code")
        _, errors = await auth_router_mod._process_oidc_callback_fastapi(request, request.session)

        assert auth_router_mod.LOGIN_GENERATION_EXPIRED_ERROR in errors
        assert exchange_calls == []

    @pytest.mark.asyncio
    async def test_an_attempt_without_a_generation_id_is_refused_closed(self, default_provider, monkeypatch):
        """A row naming no generation (older release mid-upgrade) is not silently upgraded to active."""
        _install_attempt(monkeypatch, None)
        resolved = []
        monkeypatch.setattr(
            auth_router_mod.credential_generations,
            "get_generation",
            lambda provider_id, generation_id: resolved.append(generation_id) or None,
        )

        request = DummyRequest(state="state-1", code="the-code")
        _, errors = await auth_router_mod._process_oidc_callback_fastapi(request, request.session)

        assert auth_router_mod.LOGIN_GENERATION_EXPIRED_ERROR in errors
