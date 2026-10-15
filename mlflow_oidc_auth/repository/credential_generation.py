"""Persistence for OIDC client-credential generations.

A generation is an immutable version of one provider's interactive OIDC credentials. The table
is the shared state every worker reconciles against: a rotation publishes one new ``active`` row
and retires the previous one in a single transaction, so repeated refreshes, lost responses and
process restarts all converge on the same active/retired set instead of producing conflicting
OAuth clients.

**Cross-process coordination.** Two layers, same pattern as the session refresh guard
(``auth_session.py``): a process lock held by the service layer and, on databases with row
locks, the active row taken ``FOR UPDATE`` for the duration of the rotation. SQLite has neither
row locks nor (typically) more than one writer process; the partial unique index on one-active-
per-provider is what settles a race there, and a losing writer adopts the winner's row.

**Secrets.** This repository stores and returns only the *ciphertext*
(``encrypted_secret``); encryption happens at the service edge. The entity keeps the field out
of its repr so it cannot reach a log line by accident.
"""

from __future__ import annotations

import json
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple

from mlflow.exceptions import MlflowException
from mlflow.protos.databricks_pb2 import RESOURCE_ALREADY_EXISTS
from sqlalchemy import and_, exists, or_
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from mlflow_oidc_auth.db.models import SqlAuthSession, SqlAuthState, SqlOidcCredentialGeneration

#: 128 bits. Opaque and unguessable: it appears in state rows and travels into client names, but
#: it is not itself a capability — the row it names is.
GENERATION_ID_BYTES = 16

#: Lifecycle states.
STATUS_ACTIVE = "active"
STATUS_RETIRED = "retired"

#: Snapshot keys pinned per generation. Only these are (de)serialised; an unknown key is
#: dropped on read rather than honoured, so a value a future release wrote cannot steer an older
#: replica into behaviour it does not know.
SETTING_SCOPE = "scope"
SETTING_CODE_CHALLENGE = "code_challenge_method"
SETTING_VERIFY = "verify"
SETTING_PUBLIC_CLIENT = "public_client"
SETTING_REDIRECT_URI = "redirect_uri"
_KNOWN_SETTINGS = frozenset({SETTING_SCOPE, SETTING_CODE_CHALLENGE, SETTING_VERIFY, SETTING_PUBLIC_CLIENT, SETTING_REDIRECT_URI})


@dataclass(frozen=True)
class CredentialGeneration:
    """One immutable credential generation as read back from the table.

    Attributes:
        provider_id: Provider this generation belongs to.
        generation_id: Opaque version identifier.
        client_id: OAuth client id.
        discovery_url: OIDC discovery document URL.
        client_settings: Snapshot of the registration/callback settings.
        fingerprint: SHA-256 hex of the normalized credential material.
        status: ``active`` or ``retired``.
        effective_at: When it became active (naive UTC).
        retired_at: When it was retired, if it was (naive UTC).
        retain_until: Until when a retired generation remains usable (naive UTC).
        created_at: Row creation time (naive UTC).
        encrypted_secret: Fernet ciphertext of the client secret, or None for a public client.
            Kept out of repr.
    """

    provider_id: str
    generation_id: str
    client_id: str
    discovery_url: str
    client_settings: Dict[str, object]
    fingerprint: str
    status: str
    effective_at: datetime
    retired_at: Optional[datetime] = None
    retain_until: Optional[datetime] = None
    created_at: Optional[datetime] = None
    encrypted_secret: Optional[str] = field(default=None, repr=False)

    def usable_at(self, moment: Optional[datetime] = None) -> bool:
        """Whether this generation may still serve a callback/refresh at ``moment``.

        Active generations are usable while they remain the active row. A retired one is usable
        only until its retention deadline — after that an in-flight callback must fail with a
        stable error rather than exchange the code against purged credentials.
        """
        now = moment or _now()
        if self.status == STATUS_ACTIVE:
            return True
        if self.status != STATUS_RETIRED or self.retain_until is None:
            return False
        return self.retain_until > now

    @property
    def is_public_client(self) -> bool:
        """Whether the snapshot declares a public (secret-less, PKCE-bound) client."""
        return bool(self.client_settings.get(SETTING_PUBLIC_CLIENT))


@dataclass(frozen=True)
class RotationOutcome:
    """What one rotation transaction committed.

    Attributes:
        active: The generation that is now active.
        retired: The generation this rotation retired, or None if there was no previous one.
        pruned_generation_ids: Generations physically deleted within the same transaction.
    """

    active: CredentialGeneration
    retired: Optional[CredentialGeneration]
    pruned_generation_ids: Tuple[str, ...]


class ActiveGenerationConflict(MlflowException):
    """Another writer committed a different active generation while a rotation was in flight.

    Subclasses :class:`MlflowException` so MLflow's managed session re-raises it unchanged
    through the store facade instead of wrapping it in a generic internal error: the service
    layer must receive the type so it can adopt or reject the winner. The loser adopts the
    winner: ``current`` is the active row as re-read after the conflict.
    """

    def __init__(self, current: Optional[CredentialGeneration]):
        super().__init__("a concurrent credential generation was committed", RESOURCE_ALREADY_EXISTS)
        self.current = current


def _now() -> datetime:
    """Naive UTC, matching the DateTime columns the migration created."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def serialize_settings(settings: Dict[str, object]) -> str:
    """Serialize a generation's settings snapshot deterministically."""
    known = {key: value for key, value in settings.items() if key in _KNOWN_SETTINGS}
    return json.dumps(known, separators=(",", ":"), sort_keys=True)


def parse_settings(blob: str) -> Dict[str, object]:
    """Parse a settings snapshot, dropping anything this release does not know."""
    raw = json.loads(blob)
    if not isinstance(raw, dict):
        raise ValueError("credential generation settings snapshot is not an object")
    return {key: value for key, value in raw.items() if key in _KNOWN_SETTINGS}


class _ProviderLocks:
    """Process-wide per-provider mutual exclusion for rotations (see module docstring).

    ``threading.Lock`` rather than an asyncio lock for the same reason the session guard uses
    one: the repository is synchronous and a process may run several event loops/threads.
    """

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._locks: Dict[str, threading.Lock] = {}

    def hold(self, provider_id: str) -> "threading.Lock":
        """Return (and lazily create) the process-wide rotation lock for a provider."""
        with self._guard:
            return self._locks.setdefault(provider_id, threading.Lock())


_LOCKS = _ProviderLocks()


def provider_rotation_lock(provider_id: str) -> "threading.Lock":
    """The process-wide lock serialising rotations of one provider in this process."""
    return _LOCKS.hold(provider_id)


class CredentialGenerationRepository:
    """Reads and writes credential generations for every OIDC provider."""

    def __init__(self, session_maker):
        self._Session: Callable[[], Session] = session_maker

    # ------------------------------------------------------------------ reads

    def _to_entity(self, row: SqlOidcCredentialGeneration) -> CredentialGeneration:
        return CredentialGeneration(
            provider_id=row.provider_id,
            generation_id=row.generation_id,
            client_id=row.client_id,
            discovery_url=row.discovery_url,
            client_settings=parse_settings(row.client_settings_json),
            fingerprint=row.fingerprint,
            status=row.status,
            effective_at=row.effective_at,
            retired_at=row.retired_at,
            retain_until=row.retain_until,
            created_at=row.created_at,
            encrypted_secret=row.encrypted_secret,
        )

    def get_active(self, provider_id: str) -> Optional[CredentialGeneration]:
        """The provider's active generation, or None when none has been bootstrapped yet."""
        with self._Session() as session:
            row = (
                session.query(SqlOidcCredentialGeneration)
                .filter(
                    SqlOidcCredentialGeneration.provider_id == provider_id,
                    SqlOidcCredentialGeneration.status == STATUS_ACTIVE,
                )
                .one_or_none()
            )
            return self._to_entity(row) if row is not None else None

    def get(self, provider_id: str, generation_id: str) -> Optional[CredentialGeneration]:
        """A specific generation of a specific provider; None when it does not exist."""
        with self._Session() as session:
            row = (
                session.query(SqlOidcCredentialGeneration)
                .filter(
                    SqlOidcCredentialGeneration.provider_id == provider_id,
                    SqlOidcCredentialGeneration.generation_id == generation_id,
                )
                .one_or_none()
            )
            return self._to_entity(row) if row is not None else None

    def list_for_provider(self, provider_id: str) -> List[CredentialGeneration]:
        """Every generation of a provider, active first then newest retired first."""
        with self._Session() as session:
            rows = (
                session.query(SqlOidcCredentialGeneration)
                .filter(SqlOidcCredentialGeneration.provider_id == provider_id)
                .order_by(
                    # Active before retired regardless of timestamps, then newest first.
                    SqlOidcCredentialGeneration.status.asc(),
                    SqlOidcCredentialGeneration.effective_at.desc(),
                )
                .all()
            )
            return [self._to_entity(row) for row in rows]

    # ------------------------------------------------------------- bootstrap

    def bootstrap(
        self,
        provider_id: str,
        *,
        client_id: str,
        encrypted_secret: Optional[str],
        discovery_url: str,
        client_settings: Dict[str, object],
        fingerprint: str,
        moment: Optional[datetime] = None,
    ) -> CredentialGeneration:
        """Create the first active generation for a provider from current configuration.

        Idempotent under concurrency: when another writer already bootstrapped an active row
        (the partial unique index settles it), that row is returned unchanged rather than
        producing a second generation. Never probes the IdP — bootstrap preserves the old
        "register from configuration at startup" semantics.

        Parameters:
            provider_id: Provider to bootstrap.
            client_id: Configured OAuth client id.
            encrypted_secret: Encrypted client secret, or None for a public client.
            discovery_url: Configured discovery URL.
            client_settings: Registration/callback settings snapshot.
            fingerprint: Fingerprint of the credential material.
            moment: Override the effective time (tests).

        Returns:
            The existing or newly created active generation.
        """
        now = moment or _now()
        generation_id = new_generation_id()
        with self._Session(read_only=False) as session:
            row = SqlOidcCredentialGeneration(
                provider_id=provider_id,
                generation_id=generation_id,
                client_id=client_id,
                encrypted_secret=encrypted_secret,
                discovery_url=discovery_url,
                client_settings_json=serialize_settings(client_settings),
                fingerprint=fingerprint,
                status=STATUS_ACTIVE,
                effective_at=now,
            )
            session.add(row)
            try:
                session.flush()
            except IntegrityError:
                # Concurrent bootstrap/rotation won the one-active slot. Adopt it.
                session.rollback()
                existing = self.get_active(provider_id)
                if existing is None:  # pragma: no cover - the index guarantees an active row
                    raise
                return existing
            return self._to_entity(row)

    # -------------------------------------------------------------- rotation

    def rotate(
        self,
        provider_id: str,
        *,
        client_id: str,
        encrypted_secret: Optional[str],
        discovery_url: str,
        client_settings: Dict[str, object],
        fingerprint: str,
        retention_seconds: int,
        in_flight_ttl_seconds: int,
        moment: Optional[datetime] = None,
    ) -> RotationOutcome:
        """Publish a new active generation, retire the old one and prune dead generations.

        One transaction on purpose: the switch, the retirement (with its retention deadline)
        and the physical deletion of generations past their use are either all visible or none
        are, so a failure deleting an old secret can never leave a response claiming success.

        Parameters:
            provider_id: Provider whose credentials rotate.
            client_id: New OAuth client id.
            encrypted_secret: New encrypted client secret, or None for a public client.
            discovery_url: New discovery URL.
            client_settings: New registration/callback settings snapshot.
            fingerprint: Fingerprint of the new material.
            retention_seconds: How long the retired generation stays usable.
            in_flight_ttl_seconds: In-flight login lifetime; a retired generation older than
                this with nothing referencing it may be pruned early.
            moment: Override the switch time (tests).

        Returns:
            The committed rotation outcome.

        Raises:
            ActiveGenerationConflict: A concurrent writer committed a different active
                generation first; the caller adopts ``exception.current``.
        """
        now = moment or _now()
        retain_until = now + timedelta(seconds=max(0, retention_seconds))
        in_flight_cutoff = now - timedelta(seconds=max(0, in_flight_ttl_seconds))
        generation_id = new_generation_id()

        with self._Session(read_only=False) as session:
            if session.get_bind().dialect.name == "postgresql":
                current = (
                    session.query(SqlOidcCredentialGeneration)
                    .filter(
                        SqlOidcCredentialGeneration.provider_id == provider_id,
                        SqlOidcCredentialGeneration.status == STATUS_ACTIVE,
                    )
                    .with_for_update()
                    .one_or_none()
                )
            else:
                current = (
                    session.query(SqlOidcCredentialGeneration)
                    .filter(
                        SqlOidcCredentialGeneration.provider_id == provider_id,
                        SqlOidcCredentialGeneration.status == STATUS_ACTIVE,
                    )
                    .one_or_none()
                )

            new_row = SqlOidcCredentialGeneration(
                provider_id=provider_id,
                generation_id=generation_id,
                client_id=client_id,
                encrypted_secret=encrypted_secret,
                discovery_url=discovery_url,
                client_settings_json=serialize_settings(client_settings),
                fingerprint=fingerprint,
                status=STATUS_ACTIVE,
                effective_at=now,
            )
            session.add(new_row)

            if current is not None:
                current.status = STATUS_RETIRED
                current.retired_at = now
                current.retain_until = retain_until

            try:
                session.flush()
            except (IntegrityError, OperationalError):
                # Another process published an active generation first (partial unique index),
                # or SQLite serialised the writers with a write lock. Either way the loser's
                # transaction is rolled back and it converges on whatever is active now.
                session.rollback()
                raise ActiveGenerationConflict(self.get_active(provider_id))

            # Mapped after the flush so the snapshots carry the values this transaction commits.
            active_entity = self._to_entity(new_row)
            retired_entity = self._to_entity(current) if current is not None else None
            pruned = self._prune(session, provider_id, now=now, in_flight_cutoff=in_flight_cutoff)
            return RotationOutcome(active=active_entity, retired=retired_entity, pruned_generation_ids=tuple(pruned))

    # ---------------------------------------------------------------- pruning

    def prune_retired(
        self,
        provider_id: Optional[str] = None,
        *,
        in_flight_ttl_seconds: int,
        moment: Optional[datetime] = None,
    ) -> Tuple[str, ...]:
        """Physically delete retired generations that are past use.

        A retired row is deletable when its retention deadline passed, or when it has been
        retired longer than an in-flight login may live *and* no in-flight state and no live
        session references it. Deletion removes the ciphertext too: an old secret retained for
        nothing is an old secret exposed for nothing.

        Parameters:
            provider_id: Limit to one provider, or prune every provider (startup sweep).
            in_flight_ttl_seconds: In-flight login lifetime for the early-deletion rule.
            moment: Override the sweep time (tests).

        Returns:
            The generation ids deleted.
        """
        now = moment or _now()
        in_flight_cutoff = now - timedelta(seconds=max(0, in_flight_ttl_seconds))
        with self._Session(read_only=False) as session:
            return tuple(self._prune(session, provider_id, now=now, in_flight_cutoff=in_flight_cutoff))

    def _prune(self, session: Session, provider_id: Optional[str], *, now: datetime, in_flight_cutoff: datetime) -> List[str]:
        model = SqlOidcCredentialGeneration
        conditions = [
            model.status == STATUS_RETIRED,
            or_(
                model.retain_until <= now,
                and_(
                    model.retired_at <= in_flight_cutoff,
                    ~exists().where(
                        and_(
                            SqlAuthState.credential_generation_id == model.generation_id,
                            SqlAuthState.provider_id == model.provider_id,
                        )
                    ),
                    ~exists().where(
                        and_(
                            SqlAuthSession.credential_generation_id == model.generation_id,
                            SqlAuthSession.provider_id == model.provider_id,
                            SqlAuthSession.revoked_at.is_(None),
                            SqlAuthSession.expires_at > now,
                        )
                    ),
                ),
            ),
        ]
        if provider_id is not None:
            conditions.insert(0, model.provider_id == provider_id)
        rows = session.query(model.generation_id).filter(*conditions).all()
        generation_ids = [row[0] for row in rows]
        if generation_ids:
            # Delete with the same predicate the ids were selected with — never a bare id IN.
            session.query(model).filter(*conditions).delete(synchronize_session=False)
            session.flush()
        return generation_ids


def new_generation_id() -> str:
    """A fresh opaque generation identifier (128 bits, url-safe text)."""
    return secrets.token_urlsafe(GENERATION_ID_BYTES)
