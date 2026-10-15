"""Service account source transition migration: a new table, round-trippable.

Runs on SQLite, and on PostgreSQL when ``MLFLOW_OIDC_TEST_POSTGRES_URI`` is set (skipped otherwise).
"""

import pytest
from sqlalchemy import inspect, text

from mlflow_oidc_auth.tests.db.test_phase0_migration import (  # noqa: F401  (fixtures)
    _downgrade,
    _upgrade,
    db_uri,
    engine,
)

PREVIOUS_REVISION = "e1f2a3b4c5d6"
REVISION = "f7b8c9d0e1f3"
TABLE = "service_account_source_transitions"


def _columns(engine):
    return {c["name"]: c for c in inspect(engine).get_columns(TABLE)}


def test_upgrade_creates_the_transition_table(engine):
    _upgrade(engine, REVISION)

    columns = _columns(engine)
    assert set(columns) == {
        "id",
        "user_id",
        "generation",
        "target_source",
        "target_subject",
        "phase",
        "revoked_tokens",
        "revoked_sessions",
        "actor",
        "created_at",
        "updated_at",
        "completed_at",
    }
    assert columns["target_subject"]["nullable"] is True
    assert columns["revoked_tokens"]["default"] is not None


def test_two_generations_of_one_user_and_a_unique_constraint(engine):
    _upgrade(engine, REVISION)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, display_name, is_admin, is_service_account, active, managed_by, "
                "service_account_source) VALUES ('ci-bot', 'CI', :f, :t, :t, 'manual', 'internal')"
            ),
            {"f": False, "t": True},
        )
        user_id = conn.execute(text("SELECT id FROM users WHERE username = 'ci-bot'")).scalar_one()
        conn.execute(
            text(f"INSERT INTO {TABLE} (user_id, generation, target_source, phase) " "VALUES (:uid, 1, 'partner', 'pinned')"),
            {"uid": user_id},
        )
        conn.execute(
            text(f"INSERT INTO {TABLE} (user_id, generation, target_source, phase) " "VALUES (:uid, 2, 'internal', 'completed')"),
            {"uid": user_id},
        )
        # The same generation can never be pinned twice for one account.
        duplicate = text(f"INSERT INTO {TABLE} (user_id, generation, target_source, phase) VALUES (:uid, 2, 'partner', 'pinned')")
        with pytest.raises(Exception):
            conn.execute(duplicate, {"uid": user_id})


def test_round_trip(engine):
    _upgrade(engine, REVISION)
    _downgrade(engine, PREVIOUS_REVISION)

    assert TABLE not in inspect(engine).get_table_names()

    _upgrade(engine, REVISION)
    assert TABLE in inspect(engine).get_table_names()
