"""OIDC client-credential generations.

A row is one immutable version of one provider's interactive OIDC client credentials: the
client id, its secret (encrypted, see ``credentials/vault.py``), the discovery URL and a
snapshot of the client/callback settings the client is registered with. A login is pinned to a
row through ``auth_state.credential_generation_id`` and a session through
``auth_sessions.credential_generation_id``; a callback may only exchange the code with the
generation its login started, and a rotation therefore cannot make an in-flight login redeem
its code against a secret it was not bound to.

At most one row per provider is ``active``; the rest are ``retired`` and kept only until their
``retain_until`` (or until nothing in flight references them). The partial unique index is the
cross-process guarantee of that, not application bookkeeping two workers could disagree about.

Nothing here references ``auth_state``/``auth_sessions`` by foreign key: a generation is
deleted wholesale once nothing references it, and a state/session row must survive the deletion
of the generation it names (the callback then fails closed with a stable error).
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Index, Integer, String, Text, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column

from mlflow_oidc_auth.db.models._base import Base

#: One provider may have exactly one active generation. Enforced in the database itself so two
#: workers rotating concurrently can never both publish an "active" row.
ACTIVE_PARTIAL_INDEX = "ix_oidc_cred_generations_one_active"


class SqlOidcCredentialGeneration(Base):
    """One version of one provider's OIDC client credentials.

    Attributes:
        provider_id: Registry id of the provider these credentials belong to.
        generation_id: Opaque, unguessable identifier of this version. Pinned on login state
            and session rows.
        client_id: OAuth client id at the provider.
        encrypted_secret: Fernet ciphertext of the client secret, or null for a public client.
        discovery_url: The OIDC discovery document URL this generation was built from.
        client_settings_json: Snapshot of registration settings (scope, PKCE, TLS verify,
            public-client flag, statically configured redirect URI).
        fingerprint: SHA-256 hex over the normalized credential material; change detection.
        status: ``active`` or ``retired``.
        effective_at: When this generation became (or becomes) the one new logins use.
        retired_at: When it was replaced; null while active.
        retain_until: Until when a retired generation stays usable for in-flight logins and
            sessions that need it; null while active.
    """

    __tablename__ = "oidc_credential_generations"

    id: Mapped[int] = mapped_column(Integer(), primary_key=True)
    provider_id: Mapped[str] = mapped_column(String(255), nullable=False)
    generation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    encrypted_secret: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)
    discovery_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    client_settings_json: Mapped[str] = mapped_column(Text(), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    effective_at: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    retired_at: Mapped[Optional[datetime]] = mapped_column(DateTime(), nullable=True)
    retain_until: Mapped[Optional[datetime]] = mapped_column(DateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("provider_id", "generation_id", name="uq_oidc_cred_generations_provider_generation"),
        # Partial unique index: one active row per provider on every backend this plugin
        # supports. The dialect-paired predicates are literal status values, never user input.
        Index(
            ACTIVE_PARTIAL_INDEX,
            "provider_id",
            unique=True,
            sqlite_where=text("status = 'active'"),
            postgresql_where=text("status = 'active'"),
        ),
        Index("ix_oidc_cred_generations_provider_status", "provider_id", "status"),
        Index("ix_oidc_cred_generations_retain_until", "retain_until"),
    )
