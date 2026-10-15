"""Per-provider JWKS cache eviction on credential rotation: scoped, never cross-provider."""

from mlflow_oidc_auth import auth as auth_module
from mlflow_oidc_auth.auth import invalidate_provider_jwks_cache
from mlflow_oidc_auth.provider_registry import DEFAULT_PROVIDER_ID


def test_eviction_removes_only_the_named_providers_entries():
    auth_module._provider_jwks_cache.clear()
    auth_module._provider_jwks_cache[("corp-a", "https://a/disc")] = {"keys": ["a1"]}
    auth_module._provider_jwks_cache[("corp-a", "jwks_inline", "hash")] = {"keys": ["a2"]}
    auth_module._provider_jwks_cache[("corp-b", "https://b/disc")] = {"keys": ["b1"]}

    invalidate_provider_jwks_cache("corp-a")

    assert set(auth_module._provider_jwks_cache) == {("corp-b", "https://b/disc")}


def test_evicting_a_named_provider_leaves_the_deployment_flat_cache_intact():
    auth_module._provider_jwks_cache.clear()
    with auth_module._jwks_cache_lock:
        auth_module._jwks_cache.clear()
        auth_module._jwks_cache["jwks"] = {"keys": ["flat"]}
    auth_module._provider_jwks_cache[("okta", "https://okta/disc")] = {"keys": ["o"]}

    invalidate_provider_jwks_cache("okta")

    assert auth_module._jwks_cache.get("jwks") == {"keys": ["flat"]}


def test_evicting_default_clears_the_deployment_flat_cache():
    with auth_module._jwks_cache_lock:
        auth_module._jwks_cache.clear()
        auth_module._jwks_cache["jwks"] = {"keys": ["flat"]}

    invalidate_provider_jwks_cache("default")

    assert auth_module._jwks_cache.get("jwks") is None
