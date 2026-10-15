"""Admin API for credential generations: auth, status mapping, and no-secret responses."""

from datetime import datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mlflow_oidc_auth.dependencies import check_admin_permission
from mlflow_oidc_auth.credentials import generations as gen_service
from mlflow_oidc_auth.credentials.generations import (
    REASON_CLEANUP,
    REASON_CONFLICT,
    REASON_DISCOVERY,
    REASON_INVALID_CONFIG,
    REASON_INVALID_CREDENTIALS,
    REASON_UNKNOWN_PROVIDER,
    RESULT_FAILED,
    RESULT_ROTATED,
    RESULT_UNCHANGED,
    RefreshResult,
)
from mlflow_oidc_auth.repository.credential_generation import CredentialGeneration
from mlflow_oidc_auth.routers.oidc_credentials import OIDC_CREDENTIALS_ROUTER_PREFIX, oidc_credentials_router

REFRESH_URL = OIDC_CREDENTIALS_ROUTER_PREFIX + "/providers/default/refresh"
LIST_URL = OIDC_CREDENTIALS_ROUTER_PREFIX + "/providers/default/generations"


def _generation(*, status="active", generation_id="g1", fingerprint="a" * 64):
    return CredentialGeneration(
        provider_id="default",
        generation_id=generation_id,
        client_id="client-1",
        discovery_url="https://idp.example/.well-known/openid-configuration",
        client_settings={"scope": "openid"},
        fingerprint=fingerprint,
        status=status,
        effective_at=datetime(2030, 1, 1),
        retired_at=datetime(2030, 1, 2) if status == "retired" else None,
        retain_until=datetime(2030, 2, 1) if status == "retired" else None,
        encrypted_secret="gAAAAA-ciphertext-must-never-serialize",
    )


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(oidc_credentials_router)
    # Admin by default; a test overrides to exercise the gate.
    app.dependency_overrides[check_admin_permission] = lambda: "admin@example.com"
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def forbidden_client(client):
    client.app.dependency_overrides[check_admin_permission] = lambda: (_ for _ in ()).throw(_forbidden())
    return client


def _forbidden():
    from fastapi import HTTPException

    return HTTPException(status_code=403, detail="Administrator privileges required")


class TestRefreshEndpoint:
    def test_a_rotation_returns_its_non_secret_payload(self, client, monkeypatch):
        active = _generation(generation_id="g2", fingerprint="b" * 64)
        result = RefreshResult("default", RESULT_ROTATED, active=active, retired_generation_id="g1", pruned_generation_ids=("g0",))

        async def _refresh(provider_id, *, actor):
            assert actor == "admin@example.com"
            return result

        monkeypatch.setattr(gen_service, "publish_refresh", _refresh)

        response = client.post(REFRESH_URL)

        assert response.status_code == 200
        body = response.json()
        assert body["result"] == RESULT_ROTATED
        assert body["active"]["generation_id"] == "g2"
        assert body["active"]["fingerprint_prefix"] == "b" * 8
        assert body["retired_generation_id"] == "g1"
        assert body["pruned_generation_ids"] == ["g0"]
        serialized = response.text
        assert "ciphertext" not in serialized
        assert "client_secret" not in serialized

    def test_unchanged_returns_200(self, client, monkeypatch):
        result = RefreshResult("default", RESULT_UNCHANGED, active=_generation())
        monkeypatch.setattr(gen_service, "publish_refresh", lambda *a, **k: _coro(result))

        response = client.post(REFRESH_URL)

        assert response.status_code == 200
        assert response.json()["result"] == RESULT_UNCHANGED

    @pytest.mark.parametrize(
        "reason,status_code",
        [
            (REASON_UNKNOWN_PROVIDER, 404),
            (REASON_INVALID_CREDENTIALS, 422),
            (REASON_DISCOVERY, 422),
            (REASON_CONFLICT, 409),
            (REASON_CLEANUP, 500),
            (REASON_INVALID_CONFIG, 503),
        ],
    )
    def test_failure_reasons_map_to_stable_status_codes(self, client, monkeypatch, reason, status_code):
        result = RefreshResult("default", RESULT_FAILED, reason=reason, active=_generation())
        monkeypatch.setattr(gen_service, "publish_refresh", lambda *a, **k: _coro(result))

        response = client.post(REFRESH_URL)

        assert response.status_code == status_code
        assert response.json()["detail"]["reason"] == reason

    def test_a_non_admin_is_forbidden(self, forbidden_client, monkeypatch):
        called = []
        monkeypatch.setattr(gen_service, "publish_refresh", lambda *a, **k: called.append(1) or _coro(None))

        response = forbidden_client.post(REFRESH_URL)

        assert response.status_code == 403
        assert called == []

    def test_an_unauthenticated_request_is_rejected(self, monkeypatch):
        app = FastAPI()
        app.include_router(oidc_credentials_router)  # no dependency override → the real gate
        # The gate reads request.state and raises when nobody is authenticated.
        with TestClient(app) as unauthenticated:
            response = unauthenticated.post(REFRESH_URL)
        assert response.status_code in (401, 403)


class TestListEndpoint:
    def test_lists_metadata_without_secrets(self, client, monkeypatch):
        active = _generation(status="active", generation_id="g2", fingerprint="b" * 64)
        retired = _generation(status="retired", generation_id="g1", fingerprint="a" * 64)
        monkeypatch.setattr(gen_service, "provider_is_refreshable", lambda pid: True)
        monkeypatch.setattr(gen_service, "list_generations", lambda pid: [active, retired])

        response = client.get(LIST_URL)

        assert response.status_code == 200
        body = response.json()
        assert [g["generation_id"] for g in body["generations"]] == ["g2", "g1"]
        first = body["generations"][0]
        assert set(first) == {"generation_id", "status", "client_id", "discovery_url", "fingerprint_prefix", "effective_at", "retired_at", "retain_until"}
        assert first["fingerprint_prefix"] == "b" * 8
        assert "ciphertext" not in response.text
        assert "encrypted" not in response.text

    def test_an_unknown_provider_is_404(self, client, monkeypatch):
        monkeypatch.setattr(gen_service, "provider_is_refreshable", lambda pid: False)

        response = client.get(OIDC_CREDENTIALS_ROUTER_PREFIX + "/providers/nope/generations")

        assert response.status_code == 404


async def _coro(value):
    return value
