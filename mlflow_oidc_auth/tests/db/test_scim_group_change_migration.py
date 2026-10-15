"""``scim_group_changes`` migration: single head, round trip, existing data untouched.

Runs on SQLite, and on PostgreSQL when ``MLFLOW_OIDC_TEST_POSTGRES_URI`` is set (skipped
otherwise) — the same fixture as the Phase 0 migration tests.
"""

from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text

from mlflow_oidc_auth.db.utils import _get_alembic_config
from mlflow_oidc_auth.tests.db.test_phase0_migration import (  # noqa: F401  (fixtures)
    _downgrade,
    _sqlite_uri,
    _upgrade,
    db_uri,
    engine,
)

PREVIOUS_REVISION = "e1f2a3b4c5d6"
CHANGE_REVISION = "b9c0d1e2f3a4"


class TestRevisionChain:
    def test_change_migration_follows_the_previous_head(self, tmp_path):
        script = ScriptDirectory.from_config(_get_alembic_config(_sqlite_uri(tmp_path))).get_revision(CHANGE_REVISION)
        assert script.down_revision == PREVIOUS_REVISION

    def test_exactly_one_head(self, tmp_path):
        heads = ScriptDirectory.from_config(_get_alembic_config(_sqlite_uri(tmp_path))).get_heads()
        assert len(heads) == 1, f"expected a single head, got {heads}"
        assert heads[0] == CHANGE_REVISION


class TestUpgrade:
    def test_creates_the_ledger_table_columns_indexes_and_fk(self, engine):
        _upgrade(engine, CHANGE_REVISION)

        inspector = inspect(engine)
        columns = {c["name"]: c for c in inspector.get_columns("scim_group_changes")}
        assert set(columns) == {
            "id",
            "group_id",
            "external_id",
            "version",
            "base_version",
            "old_name",
            "new_name",
            "ops_json",
            "status",
            "result_json",
            "attempts",
            "last_error",
            "actor",
            "token_id",
            "created_at",
            "updated_at",
            "completed_at",
        }
        assert columns["group_id"]["nullable"] is False
        assert columns["external_id"]["nullable"] is False
        assert columns["version"]["nullable"] is False
        assert columns["base_version"]["nullable"] is True
        assert columns["result_json"]["nullable"] is True

        index_names = {i["name"]: [c for c in i["column_names"]] for i in inspector.get_indexes("scim_group_changes")}
        assert index_names["ix_scim_group_changes_external_version"] == ["external_id", "version"]
        assert index_names["ix_scim_group_changes_group_status"] == ["group_id", "status"]
        assert index_names["ix_scim_group_changes_status"] == ["status"]
        uniques = {tuple(u["column_names"]) for u in inspector.get_unique_constraints("scim_group_changes")}
        # Idempotency correlation is per group; (external_id, version) stays a non-unique lookup
        # index because externalIds can be reused after a group moves off them.
        assert ("group_id", "version") in uniques
        assert ("external_id", "version") not in uniques
        # And the external-id lookup index itself is non-unique.
        assert all(not i.get("unique") for i in inspector.get_indexes("scim_group_changes"))
        # SQLAlchemy versions differ on where ondelete is reflected: top level or ``options``.
        foreign_keys = {
            (tuple(fk["constrained_columns"]), fk["referred_table"], fk.get("ondelete") or fk.get("options", {}).get("ondelete"))
            for fk in inspector.get_foreign_keys("scim_group_changes")
        }
        assert (("group_id",), "groups", "CASCADE") in foreign_keys

    def test_adds_group_current_version_and_activity_resource_version(self, engine):
        _upgrade(engine, CHANGE_REVISION)

        group_columns = {c["name"]: c for c in inspect(engine).get_columns("groups")}
        assert "current_version" in group_columns and group_columns["current_version"]["nullable"] is True
        activity_columns = {c["name"]: c for c in inspect(engine).get_columns("scim_activity")}
        assert "resource_version" in activity_columns and activity_columns["resource_version"]["nullable"] is True

    def test_upgrade_over_existing_data_touches_nothing(self, engine):
        _upgrade(engine, PREVIOUS_REVISION)
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO groups (group_name, managed_by) VALUES ('eng', 'scim')"))

        _upgrade(engine, CHANGE_REVISION)

        with engine.connect() as conn:
            row = conn.execute(text("SELECT group_name, managed_by, current_version FROM groups")).one()
            assert tuple(row) == ("eng", "scim", None)
            assert conn.execute(text("SELECT count(*) FROM scim_group_changes")).scalar() == 0


class TestRoundTrip:
    def test_downgrade_then_upgrade(self, engine):
        _upgrade(engine, CHANGE_REVISION)
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO groups (group_name, managed_by, current_version) VALUES ('eng', 'scim', '7')"))
            conn.execute(
                text(
                    "INSERT INTO scim_group_changes (group_id, external_id, version, old_name, new_name, ops_json, status, attempts) "
                    "VALUES (1, 'ext', '7', 'eng', 'eng', '[]', 'completed', 1)"
                )
            )

        _downgrade(engine, PREVIOUS_REVISION)

        inspector = inspect(engine)
        assert "scim_group_changes" not in inspector.get_table_names()
        assert "current_version" not in {c["name"] for c in inspector.get_columns("groups")}
        assert "resource_version" not in {c["name"] for c in inspector.get_columns("scim_activity")}
        # The group itself survives the downgrade.
        with engine.connect() as conn:
            assert conn.execute(text("SELECT group_name FROM groups")).scalars().all() == ["eng"]

        _upgrade(engine, CHANGE_REVISION)
        with engine.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM scim_group_changes")).scalar() == 0
            assert conn.execute(text("SELECT count(*) FROM groups")).scalar() == 1
