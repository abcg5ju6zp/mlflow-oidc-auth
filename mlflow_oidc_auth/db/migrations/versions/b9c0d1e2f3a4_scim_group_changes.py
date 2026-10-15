"""scim group changes

Revision ID: b9c0d1e2f3a4
Revises: e1f2a3b4c5d6
Create Date: 2026-10-14 00:00:00.000000

The recoverable ledger for versioned SCIM group changes (directory rename plus membership sync):

* ``groups.current_version`` — the directory version of the last completed versioned change; the
  optimistic-concurrency base. NULL for every group that never saw a versioned write, so a
  deployment that changes nothing changes nothing.
* ``scim_group_changes`` — one row per ``(group_id, version)`` change, written before anything
  is applied, carrying the base version, old/new names and the normalized operations snapshot,
  through ``pending`` -> ``applying`` -> ``completed`` (or ``superseded`` when it loses the
  version race). ``(external_id, version)`` is an index, not a constraint: an externalId is
  unique only among live groups and may be reused after a group moves off it, so idempotency
  lookups join to the group's current external id.
* ``scim_activity.resource_version`` — which version a request settled on, once determined.

All three are additive and nullable; nothing reads them yet outside the versioned path. The
downgrade drops them in reverse order.
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "b9c0d1e2f3a4"
down_revision = "e1f2a3b4c5d6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("groups") as batch_op:
        batch_op.add_column(sa.Column("current_version", sa.String(length=255), nullable=True))

    with op.batch_alter_table("scim_activity") as batch_op:
        batch_op.add_column(sa.Column("resource_version", sa.String(length=255), nullable=True))

    op.create_table(
        "scim_group_changes",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("group_id", sa.Integer(), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("version", sa.String(length=255), nullable=False),
        sa.Column("base_version", sa.String(length=255), nullable=True),
        sa.Column("old_name", sa.String(length=255), nullable=False),
        sa.Column("new_name", sa.String(length=255), nullable=False),
        sa.Column("ops_json", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.String(length=500), nullable=True),
        sa.Column("actor", sa.String(length=255), nullable=True),
        sa.Column("token_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["group_id"], ["groups.id"], name="fk_scim_group_changes_group_id", ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("group_id", "version", name="uq_scim_group_changes_group_version"),
    )
    op.create_index("ix_scim_group_changes_external_version", "scim_group_changes", ["external_id", "version"])
    op.create_index("ix_scim_group_changes_group_status", "scim_group_changes", ["group_id", "status"])
    op.create_index("ix_scim_group_changes_status", "scim_group_changes", ["status"])


def downgrade() -> None:
    op.drop_index("ix_scim_group_changes_status", table_name="scim_group_changes")
    op.drop_index("ix_scim_group_changes_group_status", table_name="scim_group_changes")
    op.drop_index("ix_scim_group_changes_external_version", table_name="scim_group_changes")
    op.drop_table("scim_group_changes")

    with op.batch_alter_table("scim_activity") as batch_op:
        batch_op.drop_column("resource_version")

    with op.batch_alter_table("groups") as batch_op:
        batch_op.drop_column("current_version")
