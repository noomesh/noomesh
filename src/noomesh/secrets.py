# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Secrets management for Mesh"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Optional

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class SecretsManager:
    """
    Manage encrypted secrets and sensitive configuration

    Features:
    - Environment variable loading
    - Encryption/decryption with Fernet
    - .env file support
    - Secure defaults
    """

    def __init__(self, encryption_key: Optional[str] = None):
        """
        Initialize secrets manager

        Args:
            encryption_key: Base64-encoded Fernet key (or None to load from env)
        """
        self.encryption_key = encryption_key or os.getenv("NOO_ENCRYPTION_KEY")

        if CRYPTO_AVAILABLE and self.encryption_key:
            try:
                self.cipher = Fernet(self.encryption_key.encode())
            except Exception:
                self.cipher = None
        else:
            self.cipher = None

    @staticmethod
    def generate_encryption_key() -> str:
        """
        Generate a new encryption key

        Returns:
            Base64-encoded Fernet key
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError(
                "cryptography not installed. Install with: pip install cryptography"
            )

        return Fernet.generate_key().decode()

    def encrypt(self, value: str) -> str:
        """
        Encrypt a value

        Args:
            value: Plain text value

        Returns:
            Encrypted value (base64)
        """
        if not self.cipher:
            raise ValueError("Encryption key not configured")

        return self.cipher.encrypt(value.encode()).decode()

    def decrypt(self, encrypted_value: str) -> str:
        """
        Decrypt a value

        Args:
            encrypted_value: Encrypted value (base64)

        Returns:
            Plain text value
        """
        if not self.cipher:
            raise ValueError("Encryption key not configured")

        return self.cipher.decrypt(encrypted_value.encode()).decode()

    def get_secret(
        self,
        key: str,
        default: Optional[str] = None,
        encrypted: bool = False
    ) -> Optional[str]:
        """
        Get secret from environment

        Args:
            key: Secret key name
            default: Default value if not found
            encrypted: Whether the value is encrypted

        Returns:
            Secret value or default
        """
        # KEY_FILE, then NOO_SECRET_KEY, then KEY — the order lives in ONE
        # place, `secret_env`, shared with every direct reader and mirrored
        # by the Rust gateway. An empty value counts as unset.
        from .secret_env import secret as _secret

        value = _secret(key)

        # Fall back to default
        if value is None:
            return default

        # Decrypt if needed
        if encrypted and self.cipher:
            try:
                return self.decrypt(value)
            except Exception:
                return default

        return value

    def load_env_file(self, env_file: Path = Path(".env")) -> None:
        """
        Load secrets from .env file

        Args:
            env_file: Path to .env file
        """
        if not env_file.exists():
            return

        # Warn if .env is world-readable (POSIX only)
        try:
            mode = env_file.stat().st_mode
            if mode & 0o044:
                import structlog
                structlog.get_logger(__name__).warning(
                    "env_file_world_readable",
                    path=str(env_file),
                    mode=oct(mode),
                    fix="chmod 600 .env",
                )
        except (OSError, AttributeError):
            pass

        with open(env_file, "r") as f:
            for line in f:
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue

                # Parse KEY=VALUE
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip()

                    # Remove quotes
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    elif value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]

                    # Set in environment if not already set
                    if key not in os.environ:
                        os.environ[key] = value

    def get_database_url(self) -> Optional[str]:
        """Get database URL from environment"""
        return self.get_secret("DATABASE_URL")

    def get_redis_url(self) -> str:
        """Get Redis URL from environment (the server is TLS-only: rediss://)"""
        return self.get_secret("REDIS_URL", default="rediss://localhost:6379")

    def get_api_key(self, service: str) -> Optional[str]:
        """
        Get API key for a service

        Args:
            service: Service name (e.g., "GITHUB", "OPENAI")

        Returns:
            API key or None
        """
        return self.get_secret(f"{service}_API_KEY") or self.get_secret(f"{service}_TOKEN")

    def get_all_secrets(self) -> Dict[str, str]:
        """
        Get all secrets from environment (NOO_SECRET_* variables)

        Returns:
            Dictionary of secret names to values
        """
        secrets = {}

        for key, value in os.environ.items():
            if key.startswith("NOO_SECRET_"):
                secret_name = key.replace("NOO_SECRET_", "")
                secrets[secret_name] = value

        return secrets

    def mask_secret(self, value: str, visible_chars: int = 4) -> str:
        """
        Mask a secret for logging

        Args:
            value: Secret value
            visible_chars: Number of characters to show

        Returns:
            Masked value (e.g., "ghp_****abc123")
        """
        if not value or len(value) <= visible_chars:
            return "*" * len(value)

        prefix = value[:visible_chars]
        suffix = value[-visible_chars:]
        masked_middle = "*" * (len(value) - visible_chars * 2)

        return f"{prefix}{masked_middle}{suffix}"


# Global instance
_secrets_manager: Optional[SecretsManager] = None


def get_secrets_manager() -> SecretsManager:
    """
    Get global secrets manager instance

    Returns:
        SecretsManager instance
    """
    global _secrets_manager

    if _secrets_manager is None:
        _secrets_manager = SecretsManager()

    return _secrets_manager


# Convenience functions

def get_secret(key: str, default: Optional[str] = None) -> Optional[str]:
    """Get secret from environment"""
    return get_secrets_manager().get_secret(key, default)


def get_api_key(service: str) -> Optional[str]:
    """Get API key for service"""
    return get_secrets_manager().get_api_key(service)


def load_env_file(env_file: Path = Path(".env")) -> None:
    """Load .env file"""
    get_secrets_manager().load_env_file(env_file)


# Docker secrets support — maps secret filenames to expected env vars
_SECRET_FILE_TO_ENV = {
    "jwt_secret": "NOO_JWT_SECRET",
    "cluster_secret": "NOO_CLUSTER_SECRET",
    "controller_secret": "NOO_CONTROLLER_SECRET",
    "postgres_password": "POSTGRES_PASSWORD",
    "redis_password": "REDIS_PASSWORD",
    "node_agent_token": "NOO_NODE_AGENT_TOKEN",
    # (nats_user / nats_password → NATS_USER / NATS_PASSWORD were mapped here
    # retired the shared bus user.)
    # Per-principal bus credentials. Minted by `noo onboard`
    # on a fresh install; existing installs get them from
    # `noo cluster nats-users render`. Kept in parity with the wizard's
    # SECRETS table (noo-cli/src/onboard/mod.rs) — see
    # tests/test_onboard_secret_parity.py.
    "nats_gateway_password": "NATS_GATEWAY_PASSWORD",
    "nats_worker_password": "NATS_WORKER_PASSWORD",
    "admin_password": "NOO_ADMIN_PASSWORD",
}


def load_docker_secrets(secrets_dir: Path = Path("/run/secrets")) -> None:
    """
    Load secrets from Docker secrets directory.

    Docker secrets are mounted as files in /run/secrets/.
    Known secret filenames are mapped to their expected env vars
    (e.g. ``jwt_secret`` -> ``NOO_JWT_SECRET``).  Unknown files
    are loaded with a ``NOO_SECRET_`` prefix (backward compat).

    Args:
        secrets_dir: Directory containing secret files
    """
    if not secrets_dir.exists():
        return

    for secret_file in secrets_dir.iterdir():
        if not secret_file.is_file():
            continue

        secret_value = secret_file.read_text().strip()
        base_name = secret_file.name.lower().replace("-", "_")

        # Known mapping takes priority
        env_key = _SECRET_FILE_TO_ENV.get(base_name)
        if env_key:
            if env_key not in os.environ:
                os.environ[env_key] = secret_value
        else:
            # Fallback: NOO_SECRET_ prefix
            fallback_key = f"NOO_SECRET_{base_name.upper()}"
            if fallback_key not in os.environ:
                os.environ[fallback_key] = secret_value
