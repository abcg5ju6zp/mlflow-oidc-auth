"""Configuration settings that govern credential generations."""

import os
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet

from mlflow_oidc_auth.config import AppConfig


class TestCredentialGenerationSettings:
    def test_defaults_align_retention_with_session_lifetime(self):
        config = AppConfig()
        # 14-day session lifetime plus the 15-minute in-flight state lifetime.
        assert config.OIDC_CREDENTIAL_GENERATION_RETENTION_SECONDS == 14 * 24 * 60 * 60 + 15 * 60
        assert config.OIDC_CREDENTIAL_VALIDATION_TIMEOUT_SECONDS == 10
        assert config.OIDC_CREDENTIAL_ENCRYPTION_KEY is None

    def test_retention_follows_a_custom_session_max_age(self):
        with patch.dict(os.environ, {"SESSION_COOKIE_MAX_AGE_SECONDS": "3600"}):
            config = AppConfig()
        assert config.OIDC_CREDENTIAL_GENERATION_RETENTION_SECONDS == 3600 + 15 * 60

    def test_explicit_retention_override(self):
        with patch.dict(os.environ, {"OIDC_CREDENTIAL_GENERATION_RETENTION_SECONDS": "42"}):
            config = AppConfig()
        assert config.OIDC_CREDENTIAL_GENERATION_RETENTION_SECONDS == 42

    def test_validation_timeout_override(self):
        with patch.dict(os.environ, {"OIDC_CREDENTIAL_VALIDATION_TIMEOUT_SECONDS": "3"}):
            config = AppConfig()
        assert config.OIDC_CREDENTIAL_VALIDATION_TIMEOUT_SECONDS == 3

    def test_dedicated_encryption_key_is_accepted(self):
        key = Fernet.generate_key().decode()
        with patch.dict(os.environ, {"OIDC_CREDENTIAL_ENCRYPTION_KEY": key}):
            config = AppConfig()
        assert config.OIDC_CREDENTIAL_ENCRYPTION_KEY == key

    def test_malformed_dedicated_encryption_key_fails_fast(self):
        with patch.dict(os.environ, {"OIDC_CREDENTIAL_ENCRYPTION_KEY": "not-a-fernet-key"}):
            with pytest.raises(ValueError) as excinfo:
                AppConfig()
        assert "not-a-fernet-key" not in str(excinfo.value), "the key value must not be echoed"
