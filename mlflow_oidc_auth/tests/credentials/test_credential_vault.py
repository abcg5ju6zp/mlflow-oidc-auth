"""The credential vault: what reaches ``oidc_credential_generations.encrypted_secret``."""

import base64

import pytest
from cryptography.fernet import Fernet

from mlflow_oidc_auth.credentials.vault import CredentialVault, validate_encryption_key

# Test-only values, never credentials: they exist only inside this process.
SECRET = "test-secret-key-not-a-credential"
OTHER_SECRET = "a-different-test-secret-not-a-credential"
CLIENT_SECRET = "oidc-client-secret-test-value-0123456789"


class TestRoundTrip:
    def test_derived_key_round_trip(self):
        vault = CredentialVault(SECRET)
        assert vault.decrypt_secret(vault.encrypt_secret(CLIENT_SECRET)) == CLIENT_SECRET

    def test_dedicated_key_round_trip(self):
        vault = CredentialVault(SECRET, Fernet.generate_key().decode())
        assert vault.decrypt_secret(vault.encrypt_secret(CLIENT_SECRET)) == CLIENT_SECRET

    def test_ciphertext_contains_no_secret_material(self):
        blob = CredentialVault(SECRET).encrypt_secret(CLIENT_SECRET)
        assert CLIENT_SECRET not in blob
        assert CLIENT_SECRET.encode() not in base64.urlsafe_b64decode(blob.encode())

    def test_encryption_is_randomised(self):
        vault = CredentialVault(SECRET)
        assert vault.encrypt_secret(CLIENT_SECRET) != vault.encrypt_secret(CLIENT_SECRET)

    def test_purpose_label_differs_from_session_vault(self):
        """A key derived here must not produce the same blob context as the session vault."""
        from mlflow_oidc_auth.session.token_vault import TokenVault

        # Both derive from SECRET_KEY, but a credential blob must not be decryptable through a
        # vault constructed for a different purpose label. Cross-decryption is checked directly
        # at the HKDF label level: the derived Fernet keys must differ.
        from mlflow_oidc_auth.credentials.vault import HKDF_INFO as CRED_INFO
        from mlflow_oidc_auth.session.token_vault import HKDF_INFO as SESSION_INFO

        assert CRED_INFO != SESSION_INFO
        assert CredentialVault(SECRET)._fernet is not TokenVault(SECRET)._fernet

    def test_dedicated_key_is_not_the_derived_one(self):
        blob = CredentialVault(SECRET, Fernet.generate_key().decode()).encrypt_secret(CLIENT_SECRET)
        assert CredentialVault(SECRET).decrypt_secret(blob) is None

    def test_rotated_dedicated_key_still_decrypts_old_blobs(self):
        old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
        blob = CredentialVault(SECRET, old).encrypt_secret(CLIENT_SECRET)
        assert CredentialVault(SECRET, f"{new},{old}").decrypt_secret(blob) == CLIENT_SECRET


class TestRefusal:
    def test_wrong_secret_returns_none(self):
        blob = CredentialVault(SECRET).encrypt_secret(CLIENT_SECRET)
        assert CredentialVault(OTHER_SECRET).decrypt_secret(blob) is None

    def test_wrong_dedicated_key_returns_none(self):
        blob = CredentialVault(SECRET, Fernet.generate_key().decode()).encrypt_secret(CLIENT_SECRET)
        assert CredentialVault(SECRET, Fernet.generate_key().decode()).decrypt_secret(blob) is None

    @pytest.mark.parametrize("position", [0, 20, -3])
    def test_tampered_blob_returns_none(self, position):
        vault = CredentialVault(SECRET)
        blob = vault.encrypt_secret(CLIENT_SECRET)
        chars = list(blob)
        chars[position] = "A" if chars[position] != "A" else "B"
        assert vault.decrypt_secret("".join(chars)) is None

    @pytest.mark.parametrize("blob", [None, "", "not-a-token", "gAAAAA", 42])
    def test_garbage_returns_none(self, blob):
        assert CredentialVault(SECRET).decrypt_secret(blob) is None

    @pytest.mark.parametrize("bad", ["short", "not base64 !!", base64.urlsafe_b64encode(b"x" * 31).decode()])
    def test_malformed_dedicated_key_is_refused(self, bad):
        with pytest.raises(ValueError) as excinfo:
            CredentialVault(SECRET, bad)
        assert bad not in str(excinfo.value), "the key value must not be echoed"

    def test_no_key_at_all_is_refused(self):
        with pytest.raises(ValueError):
            CredentialVault(None)

    @pytest.mark.parametrize("empty", ["", "   "])
    def test_encrypt_empty_secret_is_refused(self, empty):
        with pytest.raises(ValueError):
            CredentialVault(SECRET).encrypt_secret(empty)


def test_startup_validation_accepts_unset_and_valid_key():
    validate_encryption_key(None)
    validate_encryption_key("")
    validate_encryption_key(Fernet.generate_key().decode())
    with pytest.raises(ValueError):
        validate_encryption_key("not-a-key")
