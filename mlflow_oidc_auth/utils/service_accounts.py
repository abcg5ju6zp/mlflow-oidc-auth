"""How a service account signs in, and the staged change of that setting.

``users.service_account_source`` holds, for a service account:

* :data:`INTERNAL_SOURCE` — it signs in only with access tokens this plugin issues for it; no
  identity provider's token reaches it, whatever username the token claims;
* a provider id — it signs in only with that provider's tokens, for the subject bound to it (the
  first token binds one when none is). Its lifecycle lives in the IdP, so access tokens this
  plugin issued do not work for it, and none can be issued.

A Kubernetes service account is created for, and recorded as, its cluster provider; its tokens are
authorized on their own path. The check itself runs on every authenticated request in
``middleware/auth_middleware._service_account_denial``, from the profile row already fetched there.

Changing the setting is a **recoverable operation with an identity generation**
(:func:`apply_source`). A change is pinned (target source and subject durable, new local
credentials refused), then the account's existing tokens and sessions are revoked, then the new
source and bindings are published, and only then are caches invalidated and the audit event
emitted. Every finished phase is recorded on the generation row
(``service_account_source_transitions``); a lost response or a restart resumes from that phase.
"""

from typing import Optional

INTERNAL_SOURCE = "internal"

#: Recorded by the migration on Kubernetes service accounts created before sources existed.
KUBERNETES_SOURCE = "kubernetes"

#: Outcome of :func:`apply_source`. The change ran to its last phase (cache invalidated, audited).
STATUS_COMPLETED = "completed"
#: The source is published and credentials are revoked, but cache invalidation failed; only that
#: invalidation and the audit remain, and a retry or the startup sweep finishes them.
STATUS_FINALIZATION_PENDING = "finalization_pending"

#: Actor recorded when the startup sweep (rather than the original request) finishes a generation.
STARTUP_RECOVERY_ACTOR = "system:startup-recovery"


def is_external(source) -> bool:
    """Whether a service account with this source signs in through an identity provider."""
    return bool(source) and source != INTERNAL_SOURCE


def selectable_sources() -> list:
    """The sources an administrator may give a service account: internal, and each OIDC provider.

    A Kubernetes provider's service accounts are created by that provider itself, and a SAML
    provider has no bearer tokens, so neither is offered.

    Returns:
        ``[{"id", "display_name", "type"}]``, internal first.
    """
    from mlflow_oidc_auth.config import config

    sources = [{"id": INTERNAL_SOURCE, "display_name": "Internal (issued access tokens only)", "type": "internal"}]
    for provider in config.AUTH_PROVIDERS.providers:
        # ``kubernetes`` is reserved for the migration's Kubernetes accounts.
        if provider.type == "oidc" and provider.id != KUBERNETES_SOURCE:
            sources.append({"id": provider.id, "display_name": provider.display_name or provider.id, "type": provider.type})
    return sources


def validate_source(source: str, subject, *, is_admin: bool = False) -> str:
    """Normalise and check a source (and subject) an administrator asked for.

    An external administrator account must be bound to its subject now: left to the provider's
    first token, whoever can mint a token naming it first would hold administrator rights.

    Returns:
        The source.

    Raises:
        ValueError: An unknown source, a subject for an internal account, or an external
            administrator account without one.
    """
    source = (source or "").strip()
    if source not in {entry["id"] for entry in selectable_sources()}:
        raise ValueError(f"unknown service account source {source!r}: 'internal' or the id of an OIDC provider")
    if source == INTERNAL_SOURCE and subject:
        raise ValueError("an internal service account has no provider subject")
    if is_external(source) and is_admin and not (subject or "").strip():
        raise ValueError("an external administrator service account needs its subject bound now")
    return source


class ServiceAccountSourceTransitionError(Exception):
    """A staged source change could not leave the phase its generation is stuck at.

    The generation row remains in the database at ``phase``; the visible source was not published
    past it. The same request retried resumes from that phase.

    Attributes:
        username: The service account.
        generation: The identity generation that could not finish.
        phase: The phase it is stuck at (``pinned`` or ``revoked``).
        stage: ``"revocation"`` (tokens/sessions could not be revoked) or ``"publication"``
            (the new source/bindings could not be written).
    """

    def __init__(self, username: str, generation: int, phase: str, stage: str, detail: str = ""):
        self.username = username
        self.generation = generation
        self.phase = phase
        self.stage = stage
        self.detail = detail
        super().__init__(f"service account source change generation {generation} for {username!r} failed at {stage} ({phase}): {detail}")


def _reconcile_identities(username: str, source: str, subject: Optional[str]) -> None:
    """Make the bound identities match ``source``/``subject`` the way a published source needs.

    Drops the migration placeholder, every identity of another provider, and a non-matching
    subject; binds a named subject to an external account.
    """
    from mlflow_oidc_auth.store import store

    profile = store.get_user_profile(username)
    for provider_id, bound in store.user_identity_repo.list_identities_for_username(username):
        placeholder = provider_id == "default" and bound == profile.username
        if placeholder or source == INTERNAL_SOURCE or provider_id != source or (subject and bound != subject):
            store.user_identity_repo.unlink(provider_id, bound, username)
    if is_external(source) and subject:
        store.user_identity_repo.link(source, subject, username, allow_additional_provider=True)


def _audit_completion(transition, *, actor, previous_source, resumed, finalized_by) -> None:
    from mlflow_oidc_auth.audit import emit_audit_event

    emit_audit_event(
        "user.service_account_source",
        actor=actor,
        resource_type="user",
        resource_id=transition.username,
        detail={
            "generation": transition.generation,
            "source": transition.target_source,
            **({"previous_source": previous_source} if previous_source else {}),
            "subject_bound": bool(transition.target_subject),
            "revoked_tokens": transition.revoked_tokens,
            "revoked_sessions": transition.revoked_sessions,
            "resumed": bool(resumed),
            **({"finalized_by": finalized_by} if finalized_by else {}),
        },
    )


def _run_generation(transition, *, actor, resumed: bool, previous_source: Optional[str] = None):
    """Advance one generation from the phase recorded on it to completion.

    Every side effect is idempotent, and the phase only advances with a conditional update, so a
    crashed call and a concurrent resumer both converge on one finished generation.

    Returns:
        The result dict :func:`apply_source` returns.

    Raises:
        ServiceAccountSourceTransitionError: Revocation or publication failed. The generation
            stays at the phase named on the exception for another attempt.
    """
    from mlflow_oidc_auth.db.models.service_account import (
        PHASE_COMPLETED,
        PHASE_PINNED,
        PHASE_PUBLISHED,
        PHASE_REVOKED,
    )
    from mlflow_oidc_auth.logger import get_logger
    from mlflow_oidc_auth.store import store
    from mlflow_oidc_auth.utils.bearer_identity_cache import invalidate_bearer_identity_cache

    logger = get_logger()
    repo = store.service_account_transition_repo
    username = transition.username

    def result(status, *, recovered, revoked_tokens=0, revoked_sessions=0):
        return {
            "username": username,
            "generation": transition.generation,
            "changed": True,
            "recovered": bool(recovered),
            "status": status,
            "source": transition.target_source,
            "subject_bound": bool(transition.target_subject),
            "revoked_tokens": revoked_tokens,
            "revoked_sessions": revoked_sessions,
            "phase": transition.phase if status != STATUS_COMPLETED else PHASE_COMPLETED,
        }

    # Phase 2: revoke every credential of the old way. The visible source is still the old one —
    # a failure here must never present the account as externally managed.
    if transition.phase == PHASE_PINNED:
        try:
            revoked_tokens = store.delete_user_tokens(username)
            revoked_sessions = store.revoke_all_auth_sessions(username)
        except Exception as e:
            logger.warning(
                "Revoking credentials for service account %r source change generation %s failed: %s",
                username,
                transition.generation,
                type(e).__name__,
            )
            raise ServiceAccountSourceTransitionError(username, transition.generation, PHASE_PINNED, "revocation", str(e)) from e
        if not repo.mark_revoked(transition.id, revoked_tokens, revoked_sessions):
            # Another replica already recorded revocation; take its word for the counts.
            return _run_generation(repo.get(transition.id), actor=actor, resumed=True, previous_source=previous_source)
        transition = repo.get(transition.id)

    # Phase 3: publish the new source and the bindings it implies.
    if transition.phase == PHASE_REVOKED:
        try:
            store.set_service_account_source(username, transition.target_source)
            _reconcile_identities(username, transition.target_source, transition.target_subject)
        except Exception as e:
            logger.warning(
                "Publishing source for service account %r generation %s failed: %s",
                username,
                transition.generation,
                type(e).__name__,
            )
            raise ServiceAccountSourceTransitionError(username, transition.generation, PHASE_REVOKED, "publication", str(e)) from e
        if not repo.mark_published(transition.id):
            return _run_generation(repo.get(transition.id), actor=actor, resumed=True, previous_source=previous_source)
        transition = repo.get(transition.id)

    # Phase 4: cached decisions must not outlive the change, and the audit is the closing record.
    # A failure here leaves only these two steps outstanding — never a re-revocation.
    if transition.phase == PHASE_PUBLISHED:
        if not invalidate_bearer_identity_cache():
            logger.warning(
                "Source of service account %r generation %s is published but cache invalidation failed; "
                "the generation awaits finalization (retry or startup recovery)",
                username,
                transition.generation,
            )
            return result(
                STATUS_FINALIZATION_PENDING,
                recovered=resumed,
                revoked_tokens=transition.revoked_tokens,
                revoked_sessions=transition.revoked_sessions,
            )
        finalized_by = None
        audit_actor = transition.actor or actor or STARTUP_RECOVERY_ACTOR
        if actor and transition.actor and actor != transition.actor:
            finalized_by = actor
        elif not transition.actor:
            finalized_by = actor or STARTUP_RECOVERY_ACTOR
        _audit_completion(transition, actor=audit_actor, previous_source=previous_source, resumed=resumed, finalized_by=finalized_by)
        if not repo.mark_completed(transition.id):
            # A concurrent resumer already closed it; its audit carries the same generation.
            transition = repo.get(transition.id)
        return result(
            STATUS_COMPLETED,
            recovered=resumed,
            revoked_tokens=transition.revoked_tokens,
            revoked_sessions=transition.revoked_sessions,
        )

    # Already completed (e.g. a retry arriving after another replica's sweep).
    return result(
        STATUS_COMPLETED,
        recovered=resumed,
        revoked_tokens=transition.revoked_tokens,
        revoked_sessions=transition.revoked_sessions,
    )


def apply_source(username: str, source: str, subject=None, *, actor: Optional[str] = None) -> dict:
    """Change how service account ``username`` signs in, as a staged, recoverable operation.

    A changed source gets an identity generation: the target source and subject are pinned and new
    local credentials are refused, the account's existing access tokens and sessions are revoked,
    the new source and identity bindings are published, and then caches are invalidated and the
    audit event emitted. Each finished phase persists, so retrying this call after a lost
    response — or the startup recovery sweep — resumes from the recorded phase.

    A request that names the source already in place changes nothing and revokes no credentials;
    it only reconciles the account's identity bindings (and binds a named subject), exactly as a
    no-change request always did.

    Returns:
        ``{"username", "generation", "changed", "recovered", "status", "source",
        "subject_bound", "revoked_tokens", "revoked_sessions", "phase"}``.

    Raises:
        ValueError: As :func:`validate_source`.
        MlflowException: An unknown user or non-service account; a subject already bound to
            another account (refused before anything is pinned); a different change of the same
            account already in progress.
        ServiceAccountSourceTransitionError: Revocation or publication failed; the generation is
            left at its phase for the same request to resume.
    """
    from mlflow.exceptions import MlflowException
    from mlflow.protos.databricks_pb2 import INVALID_PARAMETER_VALUE, RESOURCE_ALREADY_EXISTS

    from mlflow_oidc_auth.store import store
    from mlflow_oidc_auth.utils.bearer_identity_cache import flush_bearer_identity_cache

    profile = store.get_user_profile(username)
    if profile.is_service_account is not True:
        raise MlflowException(f"'{username}' is not a service account", INVALID_PARAMETER_VALUE)
    source = validate_source(source, subject, is_admin=profile.is_admin is True)
    subject = (subject or "").strip() or None
    # Everything that can refuse before the pin is pinned is checked now.
    if subject and store.user_identity_repo.get_username_by_identity(source, subject) not in (None, profile.username):
        raise MlflowException("That subject is already bound to another account", RESOURCE_ALREADY_EXISTS)

    current = profile.service_account_source or INTERNAL_SOURCE
    active = store.service_account_transition_repo.get_active(username)
    if active is None and current == source:
        # Same source and nothing open: no generation, and never a revocation — binding
        # reconciliation only.
        _reconcile_identities(username, source, subject)
        flush_bearer_identity_cache()
        return {
            "username": username,
            "generation": None,
            "changed": False,
            "recovered": False,
            "status": STATUS_COMPLETED,
            "source": source,
            "subject_bound": bool(subject),
            "revoked_tokens": 0,
            "revoked_sessions": 0,
            "phase": "completed",
        }

    # Either this is a new change, or a generation is open — including one already published,
    # whose source now matches the retry: that retry must still finish its cache invalidation and
    # audit. ``begin`` hands the open same-target generation back (or refuses a different one).
    transition, resumed = store.service_account_transition_repo.begin(username, source, subject, actor)
    return _run_generation(transition, actor=actor, resumed=resumed or active is not None, previous_source=current)


def bind_new_service_account(username: str, source: str, subject) -> None:
    """Bind the subject a service account was *created* with.

    Creation already recorded the source and there are no credentials of an old way to revoke, so
    this deliberately bypasses the staged change :func:`apply_source` runs.

    Raises:
        MlflowException: The subject is already bound elsewhere.
    """
    from mlflow.exceptions import MlflowException
    from mlflow.protos.databricks_pb2 import RESOURCE_ALREADY_EXISTS

    from mlflow_oidc_auth.store import store

    subject = (subject or "").strip()
    if not subject:
        return
    if store.user_identity_repo.get_username_by_identity(source, subject) not in (None, username):
        raise MlflowException("That subject is already bound to another account", RESOURCE_ALREADY_EXISTS)
    store.user_identity_repo.link(source, subject, username, allow_additional_provider=True)


def recover_incomplete(*, actor: str = STARTUP_RECOVERY_ACTOR) -> dict:
    """Resume every source change that did not complete (a restart sweep, or operator recovery).

    Each generation is resumed independently from its recorded phase; one that still cannot finish
    is logged and left for the next sweep.

    Returns:
        ``{"completed", "finalization_pending", "failed"}`` counts.
    """
    from mlflow_oidc_auth.logger import get_logger
    from mlflow_oidc_auth.store import store

    logger = get_logger()
    counts = {"completed": 0, "finalization_pending": 0, "failed": 0}
    for transition in store.service_account_transition_repo.list_incomplete():
        try:
            result = _run_generation(transition, actor=actor, resumed=True)
        except ServiceAccountSourceTransitionError as e:
            logger.warning("Service account source generation %s for %r still stuck: %s", e.generation, e.username, e)
            counts["failed"] += 1
        except Exception as e:  # pragma: no cover - defensive: one bad row never stops the sweep
            logger.exception("Recovery of service account source generation %s failed: %s", transition.id, type(e).__name__)
            counts["failed"] += 1
        else:
            counts["completed" if result["status"] == STATUS_COMPLETED else "finalization_pending"] += 1
    if any(counts.values()):
        logger.info(
            "Recovered incomplete service account source changes: %s completed, %s awaiting cache finalization, %s still failing",
            counts["completed"],
            counts["finalization_pending"],
            counts["failed"],
        )
    return counts
