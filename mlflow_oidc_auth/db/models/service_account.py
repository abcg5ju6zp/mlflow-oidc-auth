"""Recoverable service-account sign-in source changes (identity generations).

One row is one administrator-requested change of how a service account signs in
(``utils/service_accounts.py``). It records the generation (per account, starting
at 1), the pinned target source/subject, and the phase the staged operation last
finished, so a lost response or a restart can resume from that phase instead of
leaving an account that reads externally managed while its old credentials still
work.

Completed rows are kept as the history of an account's identity generations.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from mlflow_oidc_auth.db.models._base import Base

#: Target and subject are pinned; new local credentials are refused; old credentials are not yet
#: revoked. The account still displays its previous source.
PHASE_PINNED = "pinned"
#: The account's access tokens were deleted and its server-side sessions revoked.
PHASE_REVOKED = "revoked"
#: ``users.service_account_source`` and the identity bindings now reflect the target.
PHASE_PUBLISHED = "published"
#: Caches were invalidated and the audit event emitted.
PHASE_COMPLETED = "completed"

#: A phase later than another in the staged order.
PHASE_ORDER = (PHASE_PINNED, PHASE_REVOKED, PHASE_PUBLISHED, PHASE_COMPLETED)


class SqlServiceAccountSourceTransition(Base):
    """One generation of a service account's change of sign-in source."""

    __tablename__ = "service_account_source_transitions"
    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    generation: Mapped[int] = mapped_column(Integer(), nullable=False)
    target_source: Mapped[str] = mapped_column(String(255), nullable=False)
    target_subject: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    phase: Mapped[str] = mapped_column(String(32), nullable=False, default=PHASE_PINNED)
    revoked_tokens: Mapped[int] = mapped_column(Integer(), nullable=False, server_default="0", default=0)
    revoked_sessions: Mapped[int] = mapped_column(Integer(), nullable=False, server_default="0", default=0)
    actor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(), nullable=True, default=func.now())
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(), nullable=True, default=func.now(), onupdate=func.now())
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(), nullable=True)
    __table_args__ = (
        UniqueConstraint("user_id", "generation", name="uq_sa_source_transitions_user_generation"),
        Index("ix_sa_source_transitions_user_id", "user_id"),
        # The startup recovery sweep reads every row that has not completed.
        Index("ix_sa_source_transitions_phase", "phase"),
    )
