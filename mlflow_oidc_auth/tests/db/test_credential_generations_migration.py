"""Credential-generations migration: single head, table/columns, round trip on SQLite.

Mirrors ``test_auth_state_binding_migration.py``: the schema is mechanical; what matters is the
single-head invariant, the partial unique index surviving the migration, existing rows staying
readable, and a clean downgrade.
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
GENERATIONS_REVISION = "f3b4a5c6d7e8"
TABLE = "oidc_credential_generations"


def _columns(engine, table: str):
    return {c["name"]: c for c in inspect(engine).get_columns(table)}


def _indexes(engine, table: str):
    return {index["name"]: index for index in inspect(engine).get_indexes(table)}


class TestRevisionChain:
    def test_generations_follow_the_previous_head(self, tmp_path):
        script = ScriptDirectory.from_config(_get_alembic_config(_sqlite_uri(tmp_path))).get_revision(GENERATIONS_REVISION)
        assert script.down_revision == PREVIOUS_REVISION

    def test_exactly_one_head(self, tmp_path):
        heads = ScriptDirectory.from_config(_get_alembic_config(_sqlite_uri(tmp_path))).get_heads()
        assert len(heads) == 1, f"expected a single head, got {heads}"
        assert heads[0] == GENERATIONS_REVISION


class TestUpgrade:
    def test_creates_the_table_with_every_column(self, engine):
        _upgrade(engine, GENERATIONS_REVISION)
        columns = _columns(engine, TABLE)
        assert {
            "id",
            "provider_id",
            "generation_id",
            "client_id",
            "encrypted_secret",
            "discovery_url",
            "client_settings_json",
            "fingerprint",
            "status",
            "effective_at",
            "retired_at",
            "retain_until",
            "created_at",
        } <= set(columns)

    def test_partial_unique_index_is_unique(self, engine):
        _upgrade(engine, GENERATIONS_REVISION)
        active_index = _indexes(engine, TABLE)["ix_oidc_cred_generations_one_active"]
        # SQLite reports uniqueness as the integer 1 rather than a Python bool.
        assert bool(active_index["unique"]) is True

    def test_adds_nullable_generation_columns_to_state_and_sessions(self, engine):
        _upgrade(engine, GENERATIONS_REVISION)
        for table in ("auth_state", "auth_sessions"):
            column = _columns(engine, table)["credential_generation_id"]
            assert column["nullable"] is True
            assert "ix_" + table + "_credential_generation_id" in _indexes(engine, table)

    def test_existing_rows_are_kept_and_unbound(self, engine):
        _upgrade(engine, PREVIOUS_REVISION)
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO users (username, display_name) VALUES ('alice', 'Alice')"))
            conn.execute(text("INSERT INTO auth_state (state, provider_id, expires_at) VALUES ('st', 'corp', '2030-01-01 00:00:00')"))
            conn.execute(
                text(
                    "INSERT INTO auth_sessions (session_id, user_id, expires_at) "
                    "SELECT 'ss', users.id, '2030-01-01 00:00:00' FROM users WHERE username = 'alice'"
                )
            )

        _upgrade(engine, GENERATIONS_REVISION)

        with engine.connect() as conn:
            assert conn.execute(text("SELECT credential_generation_id FROM auth_state")).scalars().all() == [None]
            assert conn.execute(text("SELECT credential_generation_id FROM auth_sessions")).scalars().all() == [None]

    def test_active_per_provider_is_enforced_but_two_providers_may_each_have_one(self, engine):
        import pytest
        from sqlalchemy.exc import IntegrityError

        _upgrade(engine, GENERATIONS_REVISION)
        with engine.begin() as conn:
            conn.execute(
                text(
                    f"INSERT INTO {TABLE} "
                    "(provider_id, generation_id, client_id, discovery_url, client_settings_json, fingerprint, status, effective_at) "
                    "VALUES ('a', 'g1', 'cid', 'https://a/.well-known/openid-configuration', '{}', 'f1', 'active', '2030-01-01 00:00:00')"
                )
            )
            conn.execute(
                text(
                    f"INSERT INTO {TABLE} "
                    "(provider_id, generation_id, client_id, discovery_url, client_settings_json, fingerprint, status, effective_at) "
                    "VALUES ('b', 'g2', 'cid', 'https://b/.well-known/openid-configuration', '{}', 'f2', 'active', '2030-01-01 00:00:00')"
                )
            )
        with engine.begin() as conn:
            with pytest.raises(IntegrityError):
                conn.execute(
                    text(
                        f"INSERT INTO {TABLE} "
                        "(provider_id, generation_id, client_id, discovery_url, client_settings_json, fingerprint, status, effective_at) "
                        "VALUES ('a', 'g3', 'cid', 'https://a/.well-known/openid-configuration', '{}', 'f3', 'active', '2030-01-02 00:00:00')"
                    )
                )


class TestRoundTrip:
    def test_downgrade_removes_table_and_columns(self, engine):
        _upgrade(engine, GENERATIONS_REVISION)
        _downgrade(engine, PREVIOUS_REVISION)

        tables = inspect(engine).get_table_names()
        assert TABLE not in tables
        assert "credential_generation_id" not in _columns(engine, "auth_state")
        assert "credential_generation_id" not in _columns(engine, "auth_sessions")

    def test_downgrade_keeps_unrelated_rows(self, engine):
        _upgrade(engine, GENERATIONS_REVISION)
        with engine.begin() as conn:
            conn.execute(text("INSERT INTO auth_state (state, provider_id, expires_at) VALUES ('st', 'corp', '2030-01-01 00:00:00')"))

        _downgrade(engine, PREVIOUS_REVISION)

        with engine.connect() as conn:
            assert conn.execute(text("SELECT state FROM auth_state")).scalars().all() == ["st"]
