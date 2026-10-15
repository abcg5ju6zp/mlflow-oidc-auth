"""Credential-generation service: snapshots, bootstrap and client resolution.

This is the seam between the shared generation rows (``repository/credential_generation.py``),
the authlib clients pinned to them (``oauth.py``) and the live configuration chain. A worker
never trusts its own memory about which generation is current: it reads the row, materialises
the client deterministically, and caches only the client object — never the answer.

Rotation (validation, publication, pruning coordination) lives in :func:`publish_refresh` in
this module as well; this initial surface covers what login needs before any rotation exists.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Optional, Tuple

from mlflow_oidc_auth import oauth as oauth_module
from mlflow_oidc_auth.audit import emit_audit_event
from mlflow_oidc_auth.credentials.vault import get_credential_vault
from mlflow_oidc_auth.config import config
from mlflow_oidc_auth.config_providers import config_manager
from mlflow_oidc_auth.logger import get_logger
from mlflow_oidc_auth.provider_registry import DEFAULT_PROVIDER_ID
from mlflow_oidc_auth.repository.auth_state import DEFAULT_STATE_LIFETIME_SECONDS
from mlflow_oidc_auth.repository.credential_generation import (
    ActiveGenerationConflict,
    CredentialGeneration,
    provider_rotation_lock,
)
from mlflow_oidc_auth.store import store

logger = get_logger()

# Public result codes for the refresh API and audit log.
RESULT_UNCHANGED = "unchanged"
RESULT_ROTATED = "rotated"
RESULT_FAILED = "failed"

# Machine-readable failure reasons. Never carry secret material.
REASON_UNKNOWN_PROVIDER = "unknown_provider"
REASON_INVALID_CONFIG = "invalid_configuration"
REASON_INVALID_CREDENTIALS = "invalid_credentials"
REASON_DISCOVERY = "discovery_unreachable"
REASON_CONFLICT = "concurrent_refresh"
REASON_CLEANUP = "cleanup_failed"

# Token-endpoint error codes that prove the client authenticated: the grant type is simply not
# enabled for this client. Everything else (invalid_client, network/timeout, unknown) fails.
_PROBE_GRANT_DISABLED_CODES = frozenset({"invalid_grant", "unauthorized_client", "unsupported_grant_type"})


@dataclass(frozen=True)
class RefreshResult:
    """The outcome of one refresh call; safe to serialise to the admin API."""

    provider_id: str
    result: str
    reason: Optional[str] = None
    active: Optional[CredentialGeneration] = None
    retired_generation_id: Optional[str] = None
    pruned_generation_ids: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def succeeded(self) -> bool:
        return self.result != RESULT_FAILED


@dataclass(frozen=True)
class CredentialSnapshot:
    """The credential material currently configured for a provider, ready to fingerprint.

    Attributes:
        provider_id: Provider the snapshot belongs to.
        client_id: OAuth client id.
        client_secret: Plain-text client secret held only in this process for encryption;
            None for a public client.
        public_client: Whether this is a secret-less PKCE client.
        discovery_url: OIDC discovery URL.
        settings: The client/callback settings to pin.
        fingerprint: SHA-256 hex over the normalized material.
    """

    provider_id: str
    client_id: str
    client_secret: Optional[str]
    public_client: bool
    discovery_url: str
    settings: dict
    fingerprint: str


def compute_fingerprint(client_id: str, client_secret: Optional[str], public_client: bool, discovery_url: str, settings: dict) -> str:
    """SHA-256 over the normalized credential material.

    Every pinned field participates, so a rotated secret, a changed client id or a repointed
    discovery address is a new generation. The secret is hashed only, never logged; the hash
    itself is shown to operators solely as a short prefix.
    """
    material = json.dumps(
        {
            "client_id": client_id,
            "client_secret": client_secret or "",
            "public_client": bool(public_client),
            "discovery_url": discovery_url,
            "settings": settings,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def snapshot_provider_credentials(provider_id: str) -> Optional[CredentialSnapshot]:
    """Resolve the provider's current configured material as a fingerprintable snapshot.

    Returns None exactly where the legacy registration refused: unknown/non-OIDC provider,
    incomplete configuration, or incoherent credentials (missing secret without a public-client
    declaration, public client with PKCE off, and so on).
    """
    resolved = oauth_module.resolve_provider_credentials(provider_id)
    if resolved is None:
        return None
    settings = oauth_module.current_client_settings_snapshot(resolved.public_client)
    fingerprint = compute_fingerprint(
        resolved.client_id,
        resolved.client_secret,
        resolved.public_client,
        resolved.discovery_url,
        settings,
    )
    return CredentialSnapshot(
        provider_id=provider_id,
        client_id=resolved.client_id,
        client_secret=resolved.client_secret,
        public_client=resolved.public_client,
        discovery_url=resolved.discovery_url,
        settings=settings,
        fingerprint=fingerprint,
    )


def bootstrap_provider(provider_id: str) -> Optional[CredentialGeneration]:
    """Ensure the provider has an active generation row matching current config, and register it.

    This is the upgrade path for a deployment that had no generations and the lazy path for a
    worker that has served none yet: it performs no IdP probe (preserving the old
    register-from-configuration semantics), and it is idempotent under concurrency — a losing
    bootstrap adopts the winner's row instead of creating a second generation.

    Returns:
        The active generation, or None when the provider currently has no usable configuration.
    """
    existing = store.get_active_credential_generation(provider_id)
    if existing is not None:
        oauth_module.register_generation_client(existing)
        return existing

    snapshot = snapshot_provider_credentials(provider_id)
    if snapshot is None:
        return None

    encrypted_secret = get_credential_vault().encrypt_secret(snapshot.client_secret) if snapshot.client_secret else None
    generation = store.bootstrap_credential_generation(
        provider_id,
        client_id=snapshot.client_id,
        encrypted_secret=encrypted_secret,
        discovery_url=snapshot.discovery_url,
        client_settings=snapshot.settings,
        fingerprint=snapshot.fingerprint,
    )
    registered = oauth_module.register_generation_client(generation)
    if registered is None:
        logger.error("Bootstrapped credential generation for provider '%s' could not be registered", provider_id)
    return generation


def bootstrap_all() -> dict[str, bool]:
    """Bootstrap and register every configured OIDC provider, independently.

    Mirrors ``oauth.ensure_all_clients_registered``: one provider failing must not disable the
    others.
    """
    from mlflow_oidc_auth.config import config

    results: dict[str, bool] = {}
    for provider in config.AUTH_PROVIDERS.providers:
        if provider.type != "oidc":
            continue
        results[provider.id] = bootstrap_provider(provider.id) is not None
    if not results and config.AUTH_PROVIDERS.source == "legacy":
        if oauth_module._has_required_config():  # noqa: SLF001 - same legacy gate registration uses
            results[DEFAULT_PROVIDER_ID] = bootstrap_provider(DEFAULT_PROVIDER_ID) is not None
    return results


def get_active_generation(provider_id: str) -> Optional[CredentialGeneration]:
    """The provider's active generation from shared state, bootstrapping it on first use."""
    return bootstrap_provider(provider_id)


def get_generation(provider_id: str, generation_id: str) -> Optional[CredentialGeneration]:
    """A specific generation row, or None when it never existed or has been purged."""
    return store.get_credential_generation(provider_id, generation_id)


def active_client(provider_id: str):
    """The authlib client for the provider's active generation, bootstrapping if needed.

    Returns None when the provider cannot be configured (the caller answers with its existing
    "OIDC not available" error).
    """
    generation = get_active_generation(provider_id)
    if generation is None:
        return None
    client = oauth_module.get_generation_client(provider_id, generation.generation_id)
    if client is not None:
        return client
    # Registered in another code path but not yet materialised in this process.
    registered = oauth_module.register_generation_client(generation)
    return registered


def generation_client(provider_id: str, generation_id: str, generation: Optional[CredentialGeneration] = None):
    """Materialise and return the client for a specific persisted generation.

    Used by the callback and by session refresh/revocation, which must use the generation a
    login was pinned to rather than whatever is active now. ``generation`` may be the row the
    caller already loaded (the callback does, to avoid a second read). Returns None when the
    generation is gone or cannot be registered; callers fail closed and never fall through to
    another generation's credentials (callback) or, for best-effort session maintenance, fall
    back in the caller with explicit intent.
    """
    cached = oauth_module.get_generation_client(provider_id, generation_id)
    if cached is not None:
        return cached
    row = generation if generation is not None else get_generation(provider_id, generation_id)
    if row is None or row.generation_id != generation_id or row.provider_id != provider_id:
        return None
    return oauth_module.register_generation_client(row)


def usable_pinned_client(provider_id: str, generation_id: Optional[str]):
    """The pinned generation's client for session maintenance, only while it is retained.

    Refresh and revocation belong to the generation the session opened with; once that
    generation passed its retention deadline (or has been purged) maintenance falls back to the
    active client instead of presenting stale credentials. Returns None when there is nothing
    pinned — the caller uses its own fallback. The *callback* deliberately does not take this
    fallback and fails closed instead.
    """
    if not generation_id:
        return None
    row = get_generation(provider_id, generation_id)
    if row is None or not row.usable_at():
        return None
    return generation_client(provider_id, generation_id, generation=row)


def provider_is_refreshable(provider_id: str) -> bool:
    """Whether ``provider_id`` names an interactive OIDC provider a refresh could target.

    The legacy ``default`` provider counts when the deployment has no explicit registry; the
    other registry types (SAML, Kubernetes) are not credential-generation providers.
    """
    provider = config.AUTH_PROVIDERS.by_id(provider_id)
    if provider is not None:
        return provider.type == "oidc"
    return provider_id == DEFAULT_PROVIDER_ID and config.AUTH_PROVIDERS.source == "legacy"


def list_generations(provider_id: str):
    """Non-secret generation metadata for one provider (admin status endpoint)."""
    return store.list_credential_generations(provider_id)


def _classify_probe_error(exc: Exception) -> str:
    """Map a client_credentials probe failure to ``accepted`` (validate) or ``invalid``.

    Only the structured OAuth ``error`` code (and an explicit 401/403 status) decides:
    ``invalid_client`` means the new secret did not authenticate, while the grant-disabled
    family means it *did* authenticate but the client is not allowed that grant, which is all
    the probe needed to establish. Free-form error descriptions are never parsed — an IdP whose
    description merely mentioned one of these words must not be able to validate bad secrets.
    Network/timeout and anything unrecognised fail closed.
    """
    code = getattr(exc, "error", None)
    if isinstance(code, str) and code.strip():
        normalized = code.strip().lower()
        if normalized in _PROBE_GRANT_DISABLED_CODES:
            return "accepted"
        if normalized == "invalid_client":
            return "invalid"
    if getattr(exc, "status_code", None) in (401, 403):
        return "invalid"
    return "invalid"


async def validate_new_credentials(snapshot: CredentialSnapshot, timeout_seconds: Optional[float] = None) -> str:
    """Validate rotated material before it can become the active generation.

    (a) the new discovery document must load with a token endpoint; (b) a confidential client's
    credentials must authenticate at that token endpoint through a ``client_credentials`` probe.
    Public clients skip (b) — PKCE is their authentication and was already coherence-checked.

    Returns:
        ``"accepted"`` or an ``"invalid[:reason]"`` token. The probe client is always discarded.
    """
    timeout = timeout_seconds or float(config.OIDC_CREDENTIAL_VALIDATION_TIMEOUT_SECONDS)
    probe_name = f"_probe_{secrets.token_hex(8)}"
    client = oauth_module.build_ephemeral_client(
        probe_name,
        snapshot.client_id,
        snapshot.client_secret,
        snapshot.discovery_url,
        snapshot.settings,
    )
    try:
        try:
            metadata = await asyncio.wait_for(client.load_server_metadata(), timeout=timeout)
        except Exception as exc:
            logger.warning("Discovery validation for provider '%s' failed: %s", snapshot.provider_id, type(exc).__name__)
            return f"invalid:{REASON_DISCOVERY}"
        if not isinstance(metadata, dict) or not metadata.get("token_endpoint"):
            logger.warning("Discovery document for provider '%s' advertises no token endpoint", snapshot.provider_id)
            return f"invalid:{REASON_DISCOVERY}"

        if snapshot.public_client:
            return "accepted"

        try:
            await asyncio.wait_for(client.fetch_access_token(grant_type="client_credentials"), timeout=timeout)
            return "accepted"
        except Exception as exc:
            verdict = _classify_probe_error(exc)
            logger.warning(
                "Credential probe for provider '%s' classified as %s: %s",
                snapshot.provider_id,
                verdict,
                type(exc).__name__,
            )
            if verdict == "accepted":
                return "accepted"
            return f"invalid:{REASON_INVALID_CREDENTIALS}"
    finally:
        oauth_module.discard_client(probe_name)


def _audit(result: RefreshResult, actor: str, *, status: str) -> None:
    detail = {"result": result.result, "fingerprint_prefix": result.active.fingerprint[:8] if result.active else None}
    if result.retired_generation_id:
        detail["retired_generation_id"] = result.retired_generation_id
    if result.reason:
        detail["reason"] = result.reason
    emit_audit_event(
        "auth.credential_refresh" if result.succeeded else "auth.credential_refresh_failed",
        actor,
        resource_type="oidc_provider",
        resource_id=result.provider_id,
        detail=detail,
        status=status,
    )


def _materialise_after_rotation(provider_id: str, outcome) -> None:
    """Register the new clients this process will need and release purged ones."""
    oauth_module.register_generation_client(outcome.active)
    if outcome.retired is not None:
        # Registering a retired generation never moves the active pointer.
        oauth_module.register_generation_client(outcome.retired)
    for purged_id in outcome.pruned_generation_ids:
        oauth_module.discard_generation_client(provider_id, purged_id)
    # The new generation's caches are independent instances; drop the bearer JWKS entries of
    # this provider only.
    from mlflow_oidc_auth.auth import invalidate_provider_jwks_cache

    invalidate_provider_jwks_cache(provider_id)


async def publish_refresh(provider_id: str, *, actor: str = "system") -> RefreshResult:
    """Re-read the provider's credentials and publish a new generation when they changed.

    Serialised per provider in this process and by the active row lock across processes;
    idempotent — a repeat with identical material, or a call that loses a race to the same
    material, reports the generation the other caller committed. New credentials are validated
    before publication; a validation or cleanup failure leaves the active generation untouched
    and reports failure (the HTTP layer must never turn that into a success response).
    """
    if not provider_is_refreshable(provider_id):
        result = RefreshResult(provider_id, RESULT_FAILED, reason=REASON_UNKNOWN_PROVIDER)
        _audit(result, actor, status="denied")
        return result

    with provider_rotation_lock(provider_id):
        # Re-read every provider backend (mounted files, Vault, cloud) before comparing; scoped
        # to this provider's fingerprint afterwards so other providers are never touched.
        config_manager.refresh()

        snapshot = snapshot_provider_credentials(provider_id)
        if snapshot is None:
            result = RefreshResult(provider_id, RESULT_FAILED, reason=REASON_INVALID_CONFIG)
            _audit(result, actor, status="denied")
            logger.error("Credential refresh for provider '%s' found no usable configuration; active generation kept", provider_id)
            return result

        active = store.get_active_credential_generation(provider_id)
        if active is None:
            # First generation: bootstrap from current configuration, no probe — preserving the
            # old startup semantics for an upgrade that never rotated anything.
            generation = store.bootstrap_credential_generation(
                provider_id,
                client_id=snapshot.client_id,
                encrypted_secret=get_credential_vault().encrypt_secret(snapshot.client_secret) if snapshot.client_secret else None,
                discovery_url=snapshot.discovery_url,
                client_settings=snapshot.settings,
                fingerprint=snapshot.fingerprint,
            )
            oauth_module.register_generation_client(generation)
            result = RefreshResult(provider_id, RESULT_ROTATED, active=generation)
            _audit(result, actor, status="success")
            return result

        if active.fingerprint == snapshot.fingerprint:
            result = RefreshResult(provider_id, RESULT_UNCHANGED, active=active)
            _audit(result, actor, status="success")
            return result

        verdict = await validate_new_credentials(snapshot)
        if verdict != "accepted":
            reason = verdict.split(":", 1)[1] if ":" in verdict else REASON_INVALID_CREDENTIALS
            result = RefreshResult(provider_id, RESULT_FAILED, reason=reason, active=active)
            _audit(result, actor, status="denied")
            logger.error("Credential refresh for provider '%s' rejected new credentials (%s); active generation kept", provider_id, reason)
            return result

        encrypted_secret = get_credential_vault().encrypt_secret(snapshot.client_secret) if snapshot.client_secret else None
        try:
            outcome = store.rotate_credential_generation(
                provider_id,
                client_id=snapshot.client_id,
                encrypted_secret=encrypted_secret,
                discovery_url=snapshot.discovery_url,
                client_settings=snapshot.settings,
                fingerprint=snapshot.fingerprint,
                retention_seconds=int(config.OIDC_CREDENTIAL_GENERATION_RETENTION_SECONDS),
                in_flight_ttl_seconds=DEFAULT_STATE_LIFETIME_SECONDS,
            )
        except ActiveGenerationConflict as conflict:
            # Another process committed a rotation first. Adopt it if it published the same
            # material the caller validated; otherwise this is a genuine conflict.
            current = conflict.current
            if current is not None and current.fingerprint == snapshot.fingerprint:
                try:
                    oauth_module.register_generation_client(current)
                except Exception as exc:  # pragma: no cover - in-process cache only
                    logger.warning("Adopting concurrent generation for provider '%s' failed: %s", provider_id, type(exc).__name__)
                result = RefreshResult(provider_id, RESULT_ROTATED, active=current)
                _audit(result, actor, status="success")
                return result
            result = RefreshResult(provider_id, RESULT_FAILED, reason=REASON_CONFLICT, active=current)
            _audit(result, actor, status="denied")
            return result
        except Exception as exc:
            # Switch/retirement/cleanup failed inside the transaction, which has rolled back:
            # the active generation is unchanged and this cannot be reported as success.
            logger.error("Credential rotation transaction failed for provider '%s': %s", provider_id, type(exc).__name__)
            result = RefreshResult(provider_id, RESULT_FAILED, reason=REASON_CLEANUP, active=active)
            _audit(result, actor, status="error")
            return result

        # In-process materialisation happens after the commit: the rotation itself cannot be
        # undone by it. A failure here only affects this process' client caches (the next
        # login rebuilds them from the committed rows), so it never downgrades the result.
        try:
            _materialise_after_rotation(provider_id, outcome)
        except Exception as exc:  # pragma: no cover - defensive around post-commit bookkeeping
            logger.warning("Post-rotation client materialisation for provider '%s' failed: %s", provider_id, type(exc).__name__)
        result = RefreshResult(
            provider_id,
            RESULT_ROTATED,
            active=outcome.active,
            retired_generation_id=outcome.retired.generation_id if outcome.retired else None,
            pruned_generation_ids=outcome.pruned_generation_ids,
        )
        _audit(result, actor, status="success")
        return result


def startup_sweep() -> None:
    """Best-effort startup pruning of generations past their use, across every provider."""
    try:
        store.prune_credential_generations(None, in_flight_ttl_seconds=DEFAULT_STATE_LIFETIME_SECONDS)
    except Exception as exc:  # pragma: no cover - startup convenience must not stop the app
        logger.warning("Startup credential-generation sweep failed: %s", type(exc).__name__)
