"""Persistence for staged, recoverable service-account source changes.

Each change of how a service account signs in (``utils/service_accounts.py``) is one row: a
per-account **generation** carrying the pinned target source/subject and the phase the staged
operation last reached. The phases advance strictly

``pinned`` → ``revoked`` → ``published`` → ``completed``

and every advance is a conditional UPDATE on the previous phase, so two replicas resuming the same
generation can never apply the same phase twice. A row that has not reached ``completed`` is what a
lost response or a restart resumes from — and what the token-issuance path checks to refuse new
local credentials while a change is open.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, List, Optional, Tuple

from mlflow.exceptions import MlflowException
from mlflow.protos.databricks_pb2 import INVALID_PARAMETER_VALUE, INVALID_STATE, RESOURCE_DOES_NOT_EXIST
from sqlalchemy.orm import Session

from mlflow_oidc_auth.db.models import SqlServiceAccountSourceTransition, SqlUser
from mlflow_oidc_auth.db.models.service_account import (
    PHASE_COMPLETED,
    PHASE_PINNED,
    PHASE_PUBLISHED,
    PHASE_REVOKED,
)
from mlflow_oidc_auth.repository.user import normalize_username


def _now() -> datetime:
    """Naive UTC, matching how every timestamp in this schema is stored."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass(frozen=True)
class ServiceAccountSourceTransition:
    """One generation of a source change, as the rest of the system sees it."""

    id: int
    user_id: int
    generation: int
    target_source: str
    target_subject: Optional[str]
    phase: str
    revoked_tokens: int
    revoked_sessions: int
    actor: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    completed_at: Optional[datetime]
    username: Optional[str] = None

    @property
    def complete(self) -> bool:
        return self.phase == PHASE_COMPLETED


def _record(row: SqlServiceAccountSourceTransition, username: Optional[str] = None) -> ServiceAccountSourceTransition:
    return ServiceAccountSourceTransition(
        id=row.id,
        user_id=row.user_id,
        generation=row.generation,
        target_source=row.target_source,
        target_subject=row.target_subject,
        phase=row.phase,
        revoked_tokens=row.revoked_tokens,
        revoked_sessions=row.revoked_sessions,
        actor=row.actor,
        created_at=row.created_at,
        updated_at=row.updated_at,
        completed_at=row.completed_at,
        username=username,
    )


def _lock_service_account(session: Session, username: str) -> SqlUser:
    """The user row locked for the rest of the transaction.

    Same locking convention as ``UserTokenRepository._lock_user`` — ``FOR UPDATE`` on PostgreSQL
    and a no-op write to take SQLite's database write lock — so pinning a change and issuing a
    token for the same account can never interleave.
    """
    user = session.query(SqlUser).filter(SqlUser.username == username).with_for_update().one_or_none()
    if user is None:
        raise MlflowException(f"User '{username}' not found", RESOURCE_DOES_NOT_EXIST)
    if not user.is_service_account:
        raise MlflowException(f"'{username}' is not a service account", INVALID_PARAMETER_VALUE)
    session.query(SqlUser).filter(SqlUser.id == user.id).update({SqlUser.id: SqlUser.id}, synchronize_session=False)
    session.refresh(user)
    return user


def incomplete_transition_exists(session: Session, user_id: int) -> bool:
    """Whether ``user_id`` has a source change that has not completed.

    Off the hot path: called inside the token-issuance transaction, which already holds the
    user's lock. A pinned row is what makes "no new local credentials while the source changes"
    survive the gap between pinning and revocation.
    """
    return (
        session.query(SqlServiceAccountSourceTransition.id)
        .filter(SqlServiceAccountSourceTransition.user_id == user_id, SqlServiceAccountSourceTransition.phase != PHASE_COMPLETED)
        .first()
        is not None
    )


class ServiceAccountTransitionRepository:
    """Reads and writes ``service_account_source_transitions``."""

    def __init__(self, session_maker):
        self._Session: Callable[..., Session] = session_maker

    def begin(
        self,
        username: str,
        target_source: str,
        target_subject: Optional[str],
        actor: Optional[str],
    ) -> Tuple[ServiceAccountSourceTransition, bool]:
        """Pin a new generation for a change, or hand back the open one to resume.

        An open generation naming the same target source and subject is returned as a resume
        (``resumed=True``) so a retried request after a lost response stays idempotent; one naming
        a different target is refused — the open generation finishes first.

        Returns:
            ``(transition, resumed)``.

        Raises:
            MlflowException: ``RESOURCE_DOES_NOT_EXIST`` for an unknown user,
                ``INVALID_PARAMETER_VALUE`` for an account that is not a service account,
                ``INVALID_STATE`` for an open generation pinned to a different target.
        """
        username = normalize_username(username)
        subject = (target_subject or "").strip() or None
        with self._Session(read_only=False) as session:
            user = _lock_service_account(session, username)
            latest = (
                session.query(SqlServiceAccountSourceTransition)
                .filter(SqlServiceAccountSourceTransition.user_id == user.id)
                .order_by(SqlServiceAccountSourceTransition.generation.desc())
                .first()
            )
            if latest is not None and latest.phase != PHASE_COMPLETED:
                if latest.target_source == target_source and (latest.target_subject or None) == subject:
                    return _record(latest, username), True
                raise MlflowException(
                    f"a change of how '{username}' signs in (generation {latest.generation}, target "
                    f"'{latest.target_source}') is already in phase '{latest.phase}'; let it finish or retry its target",
                    INVALID_STATE,
                )
            generation = (latest.generation + 1) if latest is not None else 1
            row = SqlServiceAccountSourceTransition(
                user_id=user.id,
                generation=generation,
                target_source=target_source,
                target_subject=subject,
                phase=PHASE_PINNED,
                actor=actor,
            )
            session.add(row)
            session.flush()
            return _record(row, username), False

    def _advance(self, transition_id: int, expected_phase: str, next_phase: str, **values) -> bool:
        """Move one generation forward only while it is in ``expected_phase``.

        Returns:
            Whether this call performed the advance. ``False`` means another process already did
            so — the caller re-reads the row instead of repeating its side effects.
        """
        values["phase"] = next_phase
        with self._Session(read_only=False) as session:
            return (
                session.query(SqlServiceAccountSourceTransition)
                .filter(SqlServiceAccountSourceTransition.id == transition_id, SqlServiceAccountSourceTransition.phase == expected_phase)
                .update(values, synchronize_session=False)
                == 1
            )

    def mark_revoked(self, transition_id: int, tokens: int, sessions: int) -> bool:
        """Record the revoked credential counts and advance ``pinned`` → ``revoked``."""
        with self._Session(read_only=False) as session:
            return (
                session.query(SqlServiceAccountSourceTransition)
                .filter(SqlServiceAccountSourceTransition.id == transition_id, SqlServiceAccountSourceTransition.phase == PHASE_PINNED)
                .update(
                    {
                        SqlServiceAccountSourceTransition.phase: PHASE_REVOKED,
                        SqlServiceAccountSourceTransition.revoked_tokens: SqlServiceAccountSourceTransition.revoked_tokens + int(tokens),
                        SqlServiceAccountSourceTransition.revoked_sessions: SqlServiceAccountSourceTransition.revoked_sessions + int(sessions),
                    },
                    synchronize_session=False,
                )
                == 1
            )

    def mark_published(self, transition_id: int) -> bool:
        """Advance ``revoked`` → ``published``."""
        return self._advance(transition_id, PHASE_REVOKED, PHASE_PUBLISHED)

    def mark_completed(self, transition_id: int) -> bool:
        """Advance ``published`` → ``completed``, stamping the finish time."""
        return self._advance(transition_id, PHASE_PUBLISHED, PHASE_COMPLETED, completed_at=_now())

    def get(self, transition_id: int) -> Optional[ServiceAccountSourceTransition]:
        """One transition by id, with its account's username."""
        with self._Session() as session:
            row = (
                session.query(SqlServiceAccountSourceTransition, SqlUser.username)
                .join(SqlUser, SqlUser.id == SqlServiceAccountSourceTransition.user_id)
                .filter(SqlServiceAccountSourceTransition.id == transition_id)
                .one_or_none()
            )
            return _record(row[0], row[1]) if row else None

    def get_active(self, username: str) -> Optional[ServiceAccountSourceTransition]:
        """The account's generation that has not completed yet, or None."""
        username = normalize_username(username)
        with self._Session() as session:
            row = (
                session.query(SqlServiceAccountSourceTransition)
                .join(SqlUser, SqlUser.id == SqlServiceAccountSourceTransition.user_id)
                .filter(SqlUser.username == username, SqlServiceAccountSourceTransition.phase != PHASE_COMPLETED)
                .order_by(SqlServiceAccountSourceTransition.generation.desc())
                .first()
            )
            return _record(row, username) if row else None

    def list_incomplete(self) -> List[ServiceAccountSourceTransition]:
        """Every generation that has not completed, oldest first — the startup recovery sweep."""
        with self._Session() as session:
            rows = (
                session.query(SqlServiceAccountSourceTransition, SqlUser.username)
                .join(SqlUser, SqlUser.id == SqlServiceAccountSourceTransition.user_id)
                .filter(SqlServiceAccountSourceTransition.phase != PHASE_COMPLETED)
                .order_by(SqlServiceAccountSourceTransition.id)
                .all()
            )
            return [_record(row, username) for row, username in rows]
