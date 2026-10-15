"""SCIM bearer tokens (issue #321).

A SCIM client — Entra, Okta, a script — authenticates with a long-lived bearer token that an
administrator issues and hands to the directory. It is not a user credential: it identifies a
*directory*, never resolves to a ``users`` row, and is accepted on ``/scim/v2`` only.

Only a hash is stored. ``token_prefix`` is the random, non-secret handle embedded in the token
(``scim_<prefix>_<secret>``); it is what lets ``authenticate`` find the one row to verify
instead of hashing against every token, and what an administrator sees to tell tokens apart.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from mlflow_oidc_auth.db.models._base import Base


class SqlScimToken(Base):
    """One issued SCIM token. Rows are revoked, never deleted, so the audit trail keeps a name."""

    __tablename__ = "scim_tokens"
    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    token_prefix: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(), nullable=False, server_default=func.now())
    created_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(), nullable=True)
    __table_args__ = (
        UniqueConstraint("name", name="uq_scim_tokens_name"),
        Index("ix_scim_tokens_token_prefix", "token_prefix", unique=True),
    )


class SqlScimActivity(Base):
    """One request to ``/scim/v2``, as the admin UI's provisioning status sees it (issue #325).

    What is recorded is deliberately narrow: the route *template* (``/Users/{user_id}``), never
    the concrete path, with the SCIM ``id`` in ``resource_id``; the status, an outcome class and
    the short SCIM error ``detail``. Never a token, never a header, never a request or response
    body. ``token_id`` is not a foreign key: a token row is never deleted, but the activity must
    also outlive a table rebuild, and ``token_name`` keeps the row readable on its own.
    """

    __tablename__ = "scim_activity"
    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    token_id: Mapped[Optional[int]] = mapped_column(Integer(), nullable=True)
    token_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    path: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # The directory version a versioned group change settled on for this request — set only once
    # the outcome is determined (completed, replay, conflict, refused); NULL for pre-planning
    # failures and for every non-versioned request.
    resource_version: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[int] = mapped_column(Integer(), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    error: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer(), nullable=True)
    __table_args__ = (
        Index("ix_scim_activity_at", "at"),
        Index("ix_scim_activity_token_id_at", "token_id", "at"),
    )


#: Lifecycle values for :class:`SqlScimGroupChange.status`.
GROUP_CHANGE_PENDING = "pending"
GROUP_CHANGE_APPLYING = "applying"
GROUP_CHANGE_COMPLETED = "completed"
#: The request lost the optimistic-concurrency race (or replayed an older base): it can never
#: apply, does not block a group delete, and stays for the audit trail.
GROUP_CHANGE_SUPERSEDED = "superseded"


class SqlScimGroupChange(Base):
    """One versioned, recoverable directory change to a group (rename and/or membership sync).

    The row is written *before* anything it describes is applied, so an interleaved failure,
    retry or restart can always answer "what was asked, on top of which version": ``external_id``
    + ``version`` is the directory's idempotency key (unique), ``base_version`` the group's
    ``current_version`` at planning time, ``old_name``/``new_name`` the rename (equal when the
    change only touches membership), and ``ops_json`` the normalized add/remove/replace snapshot
    the resume applies without needing the original request body.

    Lifecycle: ``pending`` (planned) -> ``applying`` (the apply transaction is in flight) ->
    ``completed`` (group reached the target; ``result_json`` holds the rendered-agnostic group
    snapshot for idempotent replays). A crash in ``applying`` is reconciled at startup: the row is
    completed when the group already reached the target, otherwise returned to ``pending`` for the
    directory's retry with the same key. Nothing here is swept: it is an operational ledger.

    Never holds a request or response body, token, or member display data beyond usernames —
    ``ops_json``/``result_json`` carry group names, usernames, versions and timestamps only.
    """

    __tablename__ = "scim_group_changes"
    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    # The group's stable id: rename keeps it, so memberships and every group permission (FK by
    # id) stay referenced throughout the change. DB-level cascade for backends that enforce it;
    # the group-delete path also removes these rows explicitly for SQLite.
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id", name="fk_scim_group_changes_group_id", ondelete="CASCADE"), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(255), nullable=False)
    base_version: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    old_name: Mapped[str] = mapped_column(String(255), nullable=False)
    new_name: Mapped[str] = mapped_column(String(255), nullable=False)
    ops_json: Mapped[str] = mapped_column(Text(), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=GROUP_CHANGE_PENDING)
    result_json: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer(), nullable=False, server_default="0", default=0)
    last_error: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    actor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    token_id: Mapped[Optional[int]] = mapped_column(Integer(), nullable=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(), nullable=True, default=func.now())
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(), nullable=True, default=func.now(), onupdate=func.now())
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(), nullable=True)
    __table_args__ = (
        # One directory version settles at most once per group. externalId is only unique among
        # live groups and can be reused after a group moves off it, so it is not part of the
        # constraint — it stays an index for the idempotency lookup (joined to the group's CURRENT
        # external id, so a historical holder no longer matches).
        UniqueConstraint("group_id", "version", name="uq_scim_group_changes_group_version"),
        Index("ix_scim_group_changes_external_version", "external_id", "version"),
        Index("ix_scim_group_changes_group_status", "group_id", "status"),
        Index("ix_scim_group_changes_status", "status"),
    )
