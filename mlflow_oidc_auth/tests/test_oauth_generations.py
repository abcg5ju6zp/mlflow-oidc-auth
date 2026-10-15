"""Generation-scoped authlib clients: deterministic names, pinned settings, alias rules."""

from datetime import datetime

import pytest

from mlflow_oidc_auth.credentials.vault import CredentialVault, get_credential_vault
from mlflow_oidc_auth import oauth as oauth_module
from mlflow_oidc_auth.oauth import GENERATION_CLIENT_SEPARATOR, generation_client_name, register_generation_client, reset_oauth
from mlflow_oidc_auth.provider_registry import DEFAULT_PROVIDER_ID
from mlflow_oidc_auth.repository.credential_generation import (
    STATUS_ACTIVE,
    STATUS_RETIRED,
    CredentialGeneration,
)

DISCOVERY = "https://idp.example/.well-known/openid-configuration"
DISCOVERY2 = "https://idp2.example/.well-known/openid-configuration"
CLIENT_SECRET = "oidc-client-secret-test-value"


@pytest.fixture(autouse=True)
def clean_oauth():
    reset_oauth()
    yield
    reset_oauth()


def _settings(**overrides):
    values = {"scope": "openid email", "code_challenge_method": "S256", "verify": True, "public_client": False, "redirect_uri": None}
    values.update(overrides)
    return values


def _generation(
    provider_id=DEFAULT_PROVIDER_ID,
    generation_id="gen-1",
    *,
    client_id="client-1",
    status=STATUS_ACTIVE,
    secret=CLIENT_SECRET,
    public=False,
    discovery=DISCOVERY,
    fingerprint="a" * 64,
    **settings,
):
    # Encrypt with the same vault the registration path decrypts with (current key material).
    encrypted = get_credential_vault().encrypt_secret(secret) if secret else None
    return CredentialGeneration(
        provider_id=provider_id,
        generation_id=generation_id,
        client_id=client_id,
        discovery_url=discovery,
        client_settings=_settings(**settings) | {"public_client": public},
        fingerprint=fingerprint,
        status=status,
        effective_at=datetime(2030, 1, 1),
        encrypted_secret=encrypted,
    )


class TestGenerationNames:
    def test_default_provider_keeps_the_oidc_slug(self):
        name = generation_client_name(DEFAULT_PROVIDER_ID, "abc")
        assert name.startswith("oidc" + GENERATION_CLIENT_SEPARATOR)

    def test_named_provider_is_slugified_deterministically(self):
        # The same (provider, generation) must name the same client in every process, and
        # punctuation collapses the same way the secret-key derivation does.
        assert generation_client_name("okta-eu", "g1") == "okta_eu__gen__g1"
        assert generation_client_name("okta-eu", "g1") == generation_client_name("okta_eu", "g1")

    def test_different_generations_name_different_clients(self):
        assert generation_client_name("okta", "g1") != generation_client_name("okta", "g2")
        assert generation_client_name("a", "g") != generation_client_name("b", "g")


class TestRegistration:
    def test_confidential_generation_registers_with_its_pinned_settings(self):
        gen = _generation(scope="openid profile custom", verify=False)
        client = register_generation_client(gen)
        assert client is not None
        assert client.client_id == "client-1"
        assert client.name == generation_client_name(DEFAULT_PROVIDER_ID, "gen-1")
        assert client.client_kwargs["scope"] == "openid profile custom"
        assert client.client_kwargs["verify"] is False
        assert client.client_kwargs["code_challenge_method"] == "S256"

    def test_public_generation_registers_without_a_secret(self):
        gen = _generation(generation_id="gen-pub", secret=None, public=True)
        client = register_generation_client(gen)
        assert client is not None
        # The registration kwargs carried no secret; authlib then uses the "none" auth method.
        _, kwargs = oauth_module.oauth._registry[client.name]
        assert "client_secret" not in kwargs

    def test_registering_twice_returns_the_same_client(self):
        gen = _generation()
        first = register_generation_client(gen)
        second = register_generation_client(gen)
        assert first is second

    def test_two_generations_are_distinct_clients(self):
        g1 = _generation(generation_id="g1")
        g2 = _generation(generation_id="g2", discovery=DISCOVERY2)
        c1 = register_generation_client(g1)
        c2 = register_generation_client(g2)
        assert c1 is not c2
        assert c1.name != c2.name
        assert oauth_module.get_generation_client(DEFAULT_PROVIDER_ID, "g1") is c1
        assert oauth_module.get_generation_client(DEFAULT_PROVIDER_ID, "g2") is c2

    def test_undecryptable_secret_fails_closed(self):
        # A ciphertext produced under a different key than this process holds.
        foreign = CredentialVault("a-different-test-secret-not-a-credential").encrypt_secret(CLIENT_SECRET)
        gen = CredentialGeneration(
            provider_id=DEFAULT_PROVIDER_ID,
            generation_id="gen-bad",
            client_id="client-1",
            discovery_url=DISCOVERY,
            client_settings=_settings(),
            fingerprint="a" * 64,
            status=STATUS_ACTIVE,
            effective_at=datetime(2030, 1, 1),
            encrypted_secret=foreign,
        )
        assert register_generation_client(gen) is None
        assert oauth_module.get_generation_client(DEFAULT_PROVIDER_ID, "gen-bad") is None

    def test_a_public_generation_with_undecryptable_null_secret_still_registers(self):
        gen = _generation(generation_id="gen-pub2", secret=None, public=True)
        assert register_generation_client(gen) is not None


class TestActivePointerAndAlias:
    def test_active_default_generation_repoints_the_legacy_oidc_alias(self):
        g1 = _generation(generation_id="g1")
        c1 = register_generation_client(g1)
        assert oauth_module.get_active_generation_client(DEFAULT_PROVIDER_ID) is c1
        assert oauth_module.oauth.oidc is c1

        g2 = _generation(generation_id="g2", client_id="client-2", discovery=DISCOVERY2, fingerprint="b" * 64)
        c2 = register_generation_client(g2)
        assert oauth_module.oauth.oidc is c2
        assert c2.client_id == "client-2"
        # The retired client remains registered under its own generation name for in-flight
        # logins and sessions that still need it, and keeps its own client id.
        assert oauth_module.get_generation_client(DEFAULT_PROVIDER_ID, "g1") is c1
        assert c1.client_id == "client-1"

    def test_retired_generation_does_not_move_the_active_pointer(self):
        g1 = _generation(generation_id="g1")
        c1 = register_generation_client(g1)
        retired = _generation(generation_id="g0", status=STATUS_RETIRED)
        c0 = register_generation_client(retired)
        assert oauth_module.get_active_generation_client(DEFAULT_PROVIDER_ID) is c1
        assert oauth_module.oauth.oidc is c1
        assert c0 is not None and c0 is not c1

    def test_named_provider_does_not_touch_the_legacy_alias(self):
        gen = _generation(provider_id="okta", generation_id="g1")
        register_generation_client(gen)
        assert oauth_module.get_active_generation_client("okta") is oauth_module.get_generation_client("okta", "g1")
        # No "oidc" registration happened just from registering a named provider.
        assert oauth_module.oauth.create_client("oidc") is None

    def test_get_client_prefers_the_active_generation(self):
        gen = _generation(provider_id="okta", generation_id="g1")
        client = register_generation_client(gen)
        assert oauth_module.get_client("okta") is client

    def test_get_client_falls_back_to_legacy_registration(self):
        # With no generation bootstrapped, the legacy path still resolves a registered client.
        oauth_module.oauth.register(name="okta", client_id="legacy-id", server_metadata_url=DISCOVERY, client_kwargs={"scope": "openid"})
        assert oauth_module.get_client("okta").client_id == "legacy-id"


class TestCrossProcessReconstruction:
    def test_the_same_row_rebuilds_the_same_client_in_a_fresh_process(self):
        gen = _generation(provider_id="okta-eu", generation_id="g7", scope="openid email")
        first = register_generation_client(gen)
        first_name = first.name
        first_registry = dict(oauth_module.oauth._registry[first_name][1])

        # Simulate a restart: a new OAuth instance with only the persisted row to rebuild from.
        reset_oauth()
        rebuilt = register_generation_client(gen)

        assert rebuilt.name == first_name == generation_client_name("okta-eu", "g7")
        rebuilt_registry = dict(oauth_module.oauth._registry[first_name][1])
        assert rebuilt_registry["client_id"] == first_registry["client_id"] == "client-1"
        assert rebuilt_registry["server_metadata_url"] == first_registry["server_metadata_url"] == DISCOVERY
        assert rebuilt.client_kwargs["scope"] == "openid email"
