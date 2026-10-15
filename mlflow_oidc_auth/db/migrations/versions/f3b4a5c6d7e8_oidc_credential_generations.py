"""oidc credential generations

Revision ID: f3b4a5c6d7e8
Revises: e1f2a3b4c5d6
Create Date: 2026-10-14 00:00:00.000000

Credential generations pin an OIDC provider's client id, secret (encrypted), discovery URL and
client/callback settings to an opaque version id, so a login started before a secret rotation
exchanges its code against the same generation it started with. This revision creates the
generation table — with a partial unique index allowing one active generation per provider —
and adds a nullable ``credential_generation_id`` to the in-flight ``auth_state`` rows and to
``auth_sessions``. Both are nullable on purpose: existing rows, SAML attempts and pre-feature
sessions stay valid. Neither column is a foreign key, because a generation is purged wholesale
once its retention window passes while rows naming it may still exist.
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "f3b4a5c6d7e8"
down_revision = "e1f2a3b4c5d6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "oidc_credential_generations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("provider_id", sa.String(length=255), nullable=False),
        sa.Column("generation_id", sa.String(length=64), nullable=False),
        sa.Column("client_id", sa.String(length=255), nullable=False),
        sa.Column("encrypted_secret", sa.Text(), nullable=True),
        sa.Column("discovery_url", sa.String(length=2048), nullable=False),
        sa.Column("client_settings_json", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("effective_at", sa.DateTime(), nullable=False),
        sa.Column("retired_at", sa.DateTime(), nullable=True),
        sa.Column("retain_until", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("provider_id", "generation_id", name="uq_oidc_cred_generations_provider_generation"),
    )
    # The predicates are fixed enum literals, never user input.
    op.create_index(
        "ix_oidc_cred_generations_one_active",
        "oidc_credential_generations",
        ["provider_id"],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
        postgresql_where=sa.text("status = 'active'"),
    )
    op.create_index("ix_oidc_cred_generations_provider_status", "oidc_credential_generations", ["provider_id", "status"])
    op.create_index("ix_oidc_cred_generations_retain_until", "oidc_credential_generations", ["retain_until"])

    with op.batch_alter_table("auth_sessions") as batch_op:
        batch_op.add_column(sa.Column("credential_generation_id", sa.String(length=64), nullable=True))
        batch_op.create_index("ix_auth_sessions_credential_generation_id", ["credential_generation_id"])

    with op.batch_alter_table("auth_state") as batch_op:
        batch_op.add_column(sa.Column("credential_generation_id", sa.String(length=64), nullable=True))
        batch_op.create_index("ix_auth_state_credential_generation_id", ["credential_generation_id"])


def downgrade() -> None:
    with op.batch_alter_table("auth_state") as batch_op:
        batch_op.drop_index("ix_auth_state_credential_generation_id")
        batch_op.drop_column("credential_generation_id")

    with op.batch_alter_table("auth_sessions") as batch_op:
        batch_op.drop_index("ix_auth_sessions_credential_generation_id")
        batch_op.drop_column("credential_generation_id")

    op.drop_index("ix_oidc_cred_generations_retain_until", table_name="oidc_credential_generations")
    op.drop_index("ix_oidc_cred_generations_provider_status", table_name="oidc_credential_generations")
    op.drop_index("ix_oidc_cred_generations_one_active", table_name="oidc_credential_generations")
    op.drop_table("oidc_credential_generations")
