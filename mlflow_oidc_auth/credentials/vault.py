"""Encryption for OIDC client secrets held by credential-generation rows.

Generation rows persist in the same database the rest of the plugin uses. A client secret is
already held by the external secret manager (Kubernetes Secret, Vault, a cloud secret service),
but writing it into a shared database in clear text would widen the exposure to every backup,
replica log and database credential: the secret therefore lands in the table encrypted, next to
the generation it belongs to so that an old generation stays usable for the in-flight logins and
the sessions it opened for the whole retention window.

This is deliberately a **separate vault** from ``session.token_vault``:

* the purpose label differs (HKDF ``info``), so a key derived for one kind of blob never
  decrypts the other, and rotating one never silently changes the other;
* the payload is one opaque string rather than a session-token record.

**Key.** ``OIDC_CREDENTIAL_ENCRYPTION_KEY`` when set: one or more comma-separated
urlsafe-base64 32-byte Fernet keys, the first used to encrypt and all accepted to decrypt, so the
encryption key itself can be rotated without every stored generation becoming unreadable.
Otherwise a key is derived from ``SECRET_KEY`` with HKDF-SHA256 under the purpose-specific
``info``; the cookie-signing key is never used directly.

**Logging.** Nothing here ever logs a secret, a blob, or key material — not even on failure.
"""

from __future__ import annotations

import base64
import functools
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from mlflow_oidc_auth.logger import get_logger

logger = get_logger()

# Purpose-bound derivation label, distinct from the session-token vault's. Changing it
# invalidates every stored generation secret, so it is versioned rather than edited.
HKDF_INFO = b"mlflow-oidc-auth/provider-credentials/v1"


def _derive_key(secret_key: str) -> bytes:
    """HKDF-SHA256 a Fernet key from ``SECRET_KEY``, bound to this purpose."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=HKDF_INFO)
    return base64.urlsafe_b64encode(hkdf.derive(secret_key.encode("utf-8")))


def _parse_dedicated_keys(value: str) -> list[bytes]:
    """Parse ``OIDC_CREDENTIAL_ENCRYPTION_KEY``: comma-separated Fernet keys, first current.

    Raises:
        ValueError: If any entry is not a urlsafe-base64 encoding of 32 bytes. The message does
            not include the value.
    """
    keys = [part.strip() for part in value.split(",") if part.strip()]
    if not keys:
        raise ValueError("OIDC_CREDENTIAL_ENCRYPTION_KEY is set but empty")
    parsed = []
    for index, key in enumerate(keys):
        try:
            raw = base64.urlsafe_b64decode(key.encode("ascii"))
        except Exception:
            raw = b""
        if len(raw) != 32:
            raise ValueError(f"OIDC_CREDENTIAL_ENCRYPTION_KEY entry {index} is not a urlsafe-base64 32-byte Fernet key")
        parsed.append(key.encode("ascii"))
    return parsed


def validate_encryption_key(value: Optional[str]) -> None:
    """Check ``OIDC_CREDENTIAL_ENCRYPTION_KEY`` at startup, so a bad key fails fast.

    Unset (None or empty) is valid: the key is then derived from ``SECRET_KEY``.

    Parameters:
        value: The configured value.

    Raises:
        ValueError: If it is set but not one or more urlsafe-base64 32-byte Fernet keys. The
            message names the setting and the offending entry's position, never the value.
    """
    if value:
        _parse_dedicated_keys(value)


class CredentialVault:
    """Encrypts and decrypts the client secret stored on a credential-generation row.

    Parameters:
        secret_key: ``SECRET_KEY``, used to derive a key when no dedicated key is configured.
        dedicated_key: ``OIDC_CREDENTIAL_ENCRYPTION_KEY``, when set.

    Raises:
        ValueError: If ``dedicated_key`` is set but malformed, or neither key is available.
    """

    def __init__(self, secret_key: Optional[str], dedicated_key: Optional[str] = None) -> None:
        if dedicated_key:
            keys = _parse_dedicated_keys(dedicated_key)
        elif secret_key:
            keys = [_derive_key(secret_key)]
        else:
            raise ValueError("No key available to encrypt provider credentials")
        self._fernet = MultiFernet([Fernet(key) for key in keys])

    def encrypt_secret(self, secret: str) -> str:
        """Encrypt one client secret into an opaque, authenticated string.

        Parameters:
            secret: The plain-text client secret.

        Returns:
            The Fernet token, as text.

        Raises:
            ValueError: If ``secret`` is not a non-empty string. A missing secret belongs in a
                public-client generation as a null column, not as an encrypted empty value.
        """
        if not isinstance(secret, str) or not secret.strip():
            raise ValueError("Cannot encrypt an empty client secret")
        return self._fernet.encrypt(secret.encode("utf-8")).decode("ascii")

    def decrypt_secret(self, blob: Optional[str]) -> Optional[str]:
        """Decrypt a stored secret, or None when there is none or it cannot be trusted.

        A blob that fails authentication — written under a key since rotated away, or tampered
        with — is treated exactly like an absent one. The caller then cannot register the
        generation's confidential client, which fails closed: nothing is ever sent to the IdP
        with a partially trusted secret.

        Parameters:
            blob: The column value.

        Returns:
            The client secret, or None.
        """
        if not blob or not isinstance(blob, (str, bytes)):
            return None
        try:
            plaintext = self._fernet.decrypt(blob.encode("ascii") if isinstance(blob, str) else blob)
            value = plaintext.decode("utf-8")
        except (InvalidToken, ValueError, TypeError, UnicodeError) as exc:
            # The blob is deliberately not logged: it is ciphertext of a live credential.
            logger.debug("A stored provider credential could not be decrypted (%s); treating as absent", type(exc).__name__)
            return None
        return value or None


@functools.lru_cache(maxsize=4)
def _vault_for(secret_key: Optional[str], dedicated_key: Optional[str]) -> CredentialVault:
    return CredentialVault(secret_key, dedicated_key)


def get_credential_vault() -> CredentialVault:
    """The credential vault for the current configuration.

    Cached per key material, so key derivation runs once per process rather than per rotation,
    while a configuration change (tests, a reload) still takes effect.

    Returns:
        The vault.

    Raises:
        ValueError: If ``OIDC_CREDENTIAL_ENCRYPTION_KEY`` is malformed.
    """
    from mlflow_oidc_auth.config import config

    secret_key = getattr(config, "SECRET_KEY", None)
    dedicated_key = getattr(config, "OIDC_CREDENTIAL_ENCRYPTION_KEY", None)
    return _vault_for(
        secret_key if isinstance(secret_key, str) else None,
        dedicated_key if isinstance(dedicated_key, str) and dedicated_key else None,
    )
