"""service account source transitions

Revision ID: f7b8c9d0e1f3
Revises: e1f2a3b4c5d6
Create Date: 2026-10-14 12:00:00.000000

A change of how a service account signs in becomes a staged, recoverable operation. Each request
gets a per-account generation in ``service_account_source_transitions`` recording the pinned target
source/subject and the phase last finished (``pinned`` → ``revoked`` → ``published`` →
``completed``), so a lost response or a restart resumes by generation rather than leaving an
account that reads externally managed while its old access tokens and sessions still work.

A new table only — nothing existing is touched, an account that never changes source never gets a
row, and the downgrade is a plain drop.
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "f7b8c9d0e1f3"
down_revision = "e1f2a3b4c5d6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "service_account_source_transitions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("target_source", sa.String(length=255), nullable=False),
        sa.Column("target_subject", sa.String(length=255), nullable=True),
        sa.Column("phase", sa.String(length=32), nullable=False),
        sa.Column("revoked_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("revoked_sessions", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("actor", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "generation", name="uq_sa_source_transitions_user_generation"),
    )
    op.create_index("ix_sa_source_transitions_user_id", "service_account_source_transitions", ["user_id"])
    op.create_index("ix_sa_source_transitions_phase", "service_account_source_transitions", ["phase"])


def downgrade() -> None:
    op.drop_index("ix_sa_source_transitions_phase", table_name="service_account_source_transitions")
    op.drop_index("ix_sa_source_transitions_user_id", table_name="service_account_source_transitions")
    op.drop_table("service_account_source_transitions")
