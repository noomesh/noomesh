# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for secrets management."""
import os
import pytest
from unittest.mock import patch

from noomesh.secrets import SecretsManager


class TestMaskSecret:
    """Test secret masking for logging."""

    def test_mask_normal_string(self):
        sm = SecretsManager()
        result = sm.mask_secret("ghp_abc123xyz456")
        assert result.startswith("ghp_")
        assert result.endswith("z456")
        assert "*" in result

    def test_mask_short_string(self):
        sm = SecretsManager()
        result = sm.mask_secret("abc")
        assert result == "***"

    def test_mask_empty_string(self):
        sm = SecretsManager()
        result = sm.mask_secret("")
        assert result == ""

    def test_mask_custom_visible_chars(self):
        sm = SecretsManager()
        result = sm.mask_secret("abcdefghij", visible_chars=2)
        assert result.startswith("ab")
        assert result.endswith("ij")
        assert len(result) == 10


class TestGetSecret:
    """Test secret retrieval from environment."""

    def test_get_secret_from_env(self):
        sm = SecretsManager()
        with patch.dict(os.environ, {"MY_KEY": "my_value"}):
            assert sm.get_secret("MY_KEY") == "my_value"

    def test_get_secret_with_noo_prefix(self):
        sm = SecretsManager()
        with patch.dict(os.environ, {"NOO_SECRET_MY_KEY": "prefixed_value"}):
            assert sm.get_secret("MY_KEY") == "prefixed_value"

    def test_get_secret_prefix_takes_precedence(self):
        sm = SecretsManager()
        with patch.dict(os.environ, {
            "NOO_SECRET_MY_KEY": "prefixed",
            "MY_KEY": "plain",
        }):
            assert sm.get_secret("MY_KEY") == "prefixed"

    def test_get_secret_default(self):
        sm = SecretsManager()
        assert sm.get_secret("NONEXISTENT_KEY_XYZ", default="fallback") == "fallback"

    def test_get_secret_missing_returns_none(self):
        sm = SecretsManager()
        assert sm.get_secret("NONEXISTENT_KEY_XYZ") is None


class TestGetAllSecrets:
    """Test listing all NOO_SECRET_ variables."""

    def test_get_all_secrets(self):
        sm = SecretsManager()
        with patch.dict(os.environ, {
            "NOO_SECRET_FOO": "bar",
            "NOO_SECRET_BAZ": "qux",
            "UNRELATED_VAR": "ignored",
        }, clear=False):
            secrets = sm.get_all_secrets()
            assert "FOO" in secrets
            assert secrets["FOO"] == "bar"
            assert "BAZ" in secrets
            assert "UNRELATED_VAR" not in secrets


class TestGetApiKey:
    """Test API key retrieval."""

    def test_get_api_key_found(self):
        sm = SecretsManager()
        with patch.dict(os.environ, {"GITHUB_API_KEY": "ghp_abc123"}):
            assert sm.get_api_key("GITHUB") == "ghp_abc123"

    def test_get_api_key_token_fallback(self):
        sm = SecretsManager()
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_token123"}):
            assert sm.get_api_key("GITHUB") == "ghp_token123"

    def test_get_api_key_missing(self):
        sm = SecretsManager()
        assert sm.get_api_key("NONEXISTENT_SERVICE_XYZ") is None


class TestLoadEnvFile:
    """Test .env file loading."""

    def test_load_env_file(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text('TEST_LOAD_VAR="hello_world"\n# comment\nTEST_LOAD_VAR2=bare_value\n')
        sm = SecretsManager()
        # Clear to ensure they're not set
        os.environ.pop("TEST_LOAD_VAR", None)
        os.environ.pop("TEST_LOAD_VAR2", None)
        try:
            sm.load_env_file(env_file)
            assert os.environ.get("TEST_LOAD_VAR") == "hello_world"
            assert os.environ.get("TEST_LOAD_VAR2") == "bare_value"
        finally:
            os.environ.pop("TEST_LOAD_VAR", None)
            os.environ.pop("TEST_LOAD_VAR2", None)

    def test_load_env_file_does_not_overwrite(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("EXISTING_VAR=new_value\n")
        sm = SecretsManager()
        os.environ["EXISTING_VAR"] = "original"
        try:
            sm.load_env_file(env_file)
            assert os.environ["EXISTING_VAR"] == "original"
        finally:
            os.environ.pop("EXISTING_VAR", None)

    def test_load_env_file_missing(self, tmp_path):
        sm = SecretsManager()
        # Should not raise
        sm.load_env_file(tmp_path / "nonexistent.env")


class TestEncryption:
    """Test encrypt/decrypt roundtrip."""

    def test_encrypt_decrypt_roundtrip(self):
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            pytest.skip("cryptography not installed")

        key = Fernet.generate_key().decode()
        sm = SecretsManager(encryption_key=key)
        plaintext = "super-secret-value"
        encrypted = sm.encrypt(plaintext)
        assert encrypted != plaintext
        decrypted = sm.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypt_without_key_raises(self):
        sm = SecretsManager()
        with pytest.raises(ValueError, match="Encryption key not configured"):
            sm.encrypt("value")

    def test_decrypt_without_key_raises(self):
        sm = SecretsManager()
        with pytest.raises(ValueError, match="Encryption key not configured"):
            sm.decrypt("value")
