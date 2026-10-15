"""Credential-generation persistence: bootstrap, rotation, pruning and snapshot safety."""

import threading
from datetime import datetime, timedelta

import pytest

from mlflow_oidc_auth.db.models import SqlAuthSession, SqlAuthState, SqlOidcCredentialGeneration, SqlUser
from mlflow_oidc_auth.repository.credential_generation import (
    STATUS_ACTIVE,
    STATUS_RETIRED,
    ActiveGenerationConflict,
    parse_settings,
    serialize_settings,
)

SECRET_CIPHERTEXT = "gAAAAABm-fake-credential-ciphertext-not-a-real-token"
SETTINGS = {"scope": "openid email", "code_challenge_method": "S256", "verify": True, "public_client": False, "redirect_uri": None}


@pytest.fixture
def store(tmp_path):
    from mlflow_oidc_auth.sqlalchemy_store import SqlAlchemyStore

    s = SqlAlchemyStore()
    s.init_db(f"sqlite:///{tmp_path / 'auth.db'}")
    yield s
    s.engine.dispose()


@pytest.fixture
def repo(store):
    return store.credential_generation_repo


def _material(**overrides):
    values = dict(
        client_id="client-1",
        encrypted_secret=SECRET_CIPHERTEXT,
        discovery_url="https://idp.example/.well-known/openid-configuration",
        client_settings=dict(SETTINGS),
        fingerprint="a" * 64,
    )
    values.update(overrides)
    return values


class TestBootstrap:
    def test_bootstrap_creates_an_active_generation(self, repo):
        gen = repo.bootstrap("corp", **_material())
        assert gen.status == STATUS_ACTIVE
        assert gen.provider_id == "corp"
        assert gen.client_id == "client-1"
        assert gen.encrypted_secret == SECRET_CIPHERTEXT
        assert gen.retired_at is None and gen.retain_until is None
        assert repo.get_active("corp").generation_id == gen.generation_id

    def test_bootstrap_is_idempotent_under_duplicate_active(self, repo):
        first = repo.bootstrap("corp", **_material())
        # A second bootstrap attempt loses at the partial unique index and adopts the winner
        # instead of creating a second generation.
        second = repo.bootstrap("corp", **_material(fingerprint="b" * 64))
        assert second.generation_id == first.generation_id
        assert second.fingerprint == first.fingerprint
        assert len(repo.list_for_provider("corp")) == 1

    def test_two_providers_bootstrap_independently(self, repo):
        a = repo.bootstrap("corp-a", **_material())
        b = repo.bootstrap("corp-b", **_material(discovery_url="https://b/oidc"))
        assert a.generation_id != b.generation_id
        assert repo.get_active("corp-a").generation_id == a.generation_id
        assert repo.get_active("corp-b").generation_id == b.generation_id


class TestRotation:
    def test_rotation_retires_the_old_generation_with_a_retention_deadline(self, repo):
        old = repo.bootstrap("corp", **_material())
        outcome = repo.rotate(
            "corp",
            **_material(encrypted_secret="gAAAAABm-new-ciphertext", fingerprint="c" * 64),
            retention_seconds=3600,
            in_flight_ttl_seconds=900,
        )
        assert outcome.active.generation_id != old.generation_id
        assert outcome.active.status == STATUS_ACTIVE
        assert outcome.retired.generation_id == old.generation_id
        assert outcome.retired.status == STATUS_RETIRED
        assert outcome.retired.retired_at is not None
        assert outcome.retired.retain_until == outcome.retired.retired_at + timedelta(seconds=3600)
        assert outcome.pruned_generation_ids == ()

        active = repo.get_active("corp")
        assert active.generation_id == outcome.active.generation_id
        previous = repo.get("corp", old.generation_id)
        assert previous.usable_at() is True
        all_generations = repo.list_for_provider("corp")
        assert [g.status for g in all_generations] == [STATUS_ACTIVE, STATUS_RETIRED]

    def test_retired_generation_past_retention_is_not_usable(self, repo):
        old = repo.bootstrap("corp", **_material())
        repo.rotate("corp", **_material(fingerprint="c" * 64), retention_seconds=10, in_flight_ttl_seconds=5)
        retired = repo.get("corp", old.generation_id)
        later = retired.retain_until + timedelta(seconds=1)
        assert retired.usable_at(later) is False

    def test_rotation_with_zero_retention_prunes_the_previous_generation_immediately(self, repo):
        old = repo.bootstrap("corp", **_material())
        outcome = repo.rotate("corp", **_material(fingerprint="c" * 64), retention_seconds=0, in_flight_ttl_seconds=900)
        assert outcome.pruned_generation_ids == (old.generation_id,)
        assert repo.get("corp", old.generation_id) is None
        # The old ciphertext is gone with the row.
        with repo._Session() as session:  # noqa: SLF001 - white-box check in a repository test
            assert session.query(SqlOidcCredentialGeneration).count() == 1

    def test_rotation_rolls_back_when_committing_the_active_switch_fails(self, repo, monkeypatch):
        old = repo.bootstrap("corp", **_material())

        # Simulate the old secret/row cleanup failing inside the transaction: the whole switch
        # must roll back so a refresh result can never report completion with the active row
        # already replaced.
        def boom(*args, **kwargs):
            raise RuntimeError("cleanup failed")

        monkeypatch.setattr(repo, "_prune", boom)
        # The managed session maker wraps and rolls back any failure raised inside it.
        with pytest.raises(Exception):
            repo.rotate("corp", **_material(fingerprint="c" * 64), retention_seconds=3600, in_flight_ttl_seconds=900)
        assert repo.get_active("corp").generation_id == old.generation_id
        assert len(repo.list_for_provider("corp")) == 1


class TestPruning:
    def _reference_rows(self, store, generation_id):
        with store.ManagedSessionMaker(read_only=False) as session:
            user = SqlUser(username="alice", display_name="Alice")
            session.add(user)
            session.flush()
            session.add(SqlAuthState(state="the-state", provider_id="corp", credential_generation_id=generation_id, expires_at=datetime(2030, 1, 1)))
            session.add(
                SqlAuthSession(
                    session_id="the-session",
                    user_id=user.id,
                    provider_id="corp",
                    credential_generation_id=generation_id,
                    expires_at=datetime(2030, 1, 1),
                )
            )

    def test_referenced_generation_is_not_pruned_early(self, repo, store):
        old = repo.bootstrap("corp", **_material())
        outcome = repo.rotate("corp", **_material(fingerprint="c" * 64), retention_seconds=100000, in_flight_ttl_seconds=900)
        self._reference_rows(store, old.generation_id)

        # Long past the in-flight TTL, but a state and a live session still name the generation.
        later = outcome.retired.retired_at + timedelta(seconds=1000)
        deleted = repo.prune_retired("corp", in_flight_ttl_seconds=900, moment=later)
        assert deleted == ()
        assert repo.get("corp", old.generation_id) is not None

    def test_unreferenced_generation_is_pruned_after_the_in_flight_ttl(self, repo):
        old = repo.bootstrap("corp", **_material())
        outcome = repo.rotate("corp", **_material(fingerprint="c" * 64), retention_seconds=100000, in_flight_ttl_seconds=900)
        later = outcome.retired.retired_at + timedelta(seconds=901)
        deleted = repo.prune_retired("corp", in_flight_ttl_seconds=900, moment=later)
        assert deleted == (old.generation_id,)
        assert repo.get("corp", old.generation_id) is None

    def test_not_pruned_before_the_in_flight_ttl_even_without_references(self, repo):
        old = repo.bootstrap("corp", **_material())
        outcome = repo.rotate("corp", **_material(fingerprint="c" * 64), retention_seconds=100000, in_flight_ttl_seconds=900)
        deleted = repo.prune_retired("corp", in_flight_ttl_seconds=900, moment=outcome.retired.retired_at + timedelta(seconds=10))
        assert deleted == ()
        assert repo.get("corp", old.generation_id) is not None

    def test_pruning_is_scoped_to_the_named_provider(self, repo):
        old_a = repo.bootstrap("corp-a", **_material(discovery_url="https://a/oidc"))
        old_b = repo.bootstrap("corp-b", **_material(discovery_url="https://b/oidc"))
        repo.rotate("corp-a", **_material(discovery_url="https://a/oidc", fingerprint="c" * 64), retention_seconds=3600, in_flight_ttl_seconds=900)
        outcome_b = repo.rotate("corp-b", **_material(discovery_url="https://b/oidc", fingerprint="d" * 64), retention_seconds=3600, in_flight_ttl_seconds=900)

        later = outcome_b.retired.retired_at + timedelta(seconds=4000)
        deleted_a = repo.prune_retired("corp-a", in_flight_ttl_seconds=900, moment=later)
        assert deleted_a == (old_a.generation_id,)
        assert repo.get("corp-b", old_b.generation_id) is not None

    def test_global_prune_touches_every_provider(self, repo):
        old_a = repo.bootstrap("corp-a", **_material(discovery_url="https://a/oidc"))
        old_b = repo.bootstrap("corp-b", **_material(discovery_url="https://b/oidc"))
        repo.rotate("corp-a", **_material(discovery_url="https://a/oidc", fingerprint="c" * 64), retention_seconds=3600, in_flight_ttl_seconds=900)
        outcome_b = repo.rotate("corp-b", **_material(discovery_url="https://b/oidc", fingerprint="d" * 64), retention_seconds=3600, in_flight_ttl_seconds=900)
        later = outcome_b.retired.retired_at + timedelta(seconds=4000)
        assert set(repo.prune_retired(None, in_flight_ttl_seconds=900, moment=later)) == {old_a.generation_id, old_b.generation_id}


class TestSnapshot:
    def test_settings_round_trip_known_keys(self):
        blob = serialize_settings(SETTINGS)
        assert parse_settings(blob) == SETTINGS

    def test_unknown_snapshot_keys_are_dropped(self):
        import json

        blob = json.dumps({**SETTINGS, "added_in_a_future_release": "value"})
        assert parse_settings(blob) == SETTINGS

    def test_repr_never_carries_the_ciphertext(self, repo):
        gen = repo.bootstrap("corp", **_material())
        assert SECRET_CIPHERTEXT not in repr(gen)
        assert "encrypted_secret" not in repr(gen)
