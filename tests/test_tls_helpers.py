# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for TLS/SSL helper functions used across CLI and gateway code."""

from __future__ import annotations




# ── ssl_verify() from gateway deps ──────────────────────────────────


class TestSslVerify:
    """Tests for gateway.deps.ssl_verify()."""

    def test_returns_ssl_context_when_env_set(self, tmp_path, monkeypatch):
        import ssl
        from unittest.mock import patch

        monkeypatch.setenv("NOO_TLS_CA", str(tmp_path / "ca.crt"))
        (tmp_path / "ca.crt").write_text("placeholder")

        from noomesh.gateway.deps import ssl_verify

        # Mock create_default_context to avoid needing a real CA cert
        mock_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with patch("ssl.create_default_context", return_value=mock_ctx):
            result = ssl_verify()
        assert isinstance(result, ssl.SSLContext)
        # Hostname verification is ON the earlier change — it was
        # False here, which meant any leaf the cluster CA ever issued
        # could impersonate any cluster host to these Python clients.
        assert result.check_hostname is True
        assert result.verify_mode == ssl.CERT_REQUIRED

    def test_returns_true_when_no_ca(self, monkeypatch):
        monkeypatch.delenv("NOO_TLS_CA", raising=False)

        from noomesh.gateway.deps import ssl_verify

        assert ssl_verify() is True

    def test_returns_true_when_ca_env_set_but_file_missing(self, monkeypatch):
        monkeypatch.setenv("NOO_TLS_CA", "/nonexistent/ca.crt")

        from noomesh.gateway.deps import ssl_verify

        assert ssl_verify() is True

    def test_returns_true_when_ca_env_empty(self, monkeypatch):
        monkeypatch.setenv("NOO_TLS_CA", "")

        from noomesh.gateway.deps import ssl_verify

        assert ssl_verify() is True


# ── client_cert() from gateway deps ─────────────────────────────────


class TestClientCert:
    """Tests for gateway.deps.client_cert()."""

    def test_returns_tuple_when_both_files_exist(self, tmp_path, monkeypatch):
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        cert.write_text("--- CERT ---")
        key.write_text("--- KEY ---")
        monkeypatch.setenv("NOO_TLS_CERT", str(cert))
        monkeypatch.setenv("NOO_TLS_KEY", str(key))

        from noomesh.gateway.deps import client_cert

        result = client_cert()
        assert result == (str(cert), str(key))

    def test_returns_none_when_not_configured(self, monkeypatch):
        monkeypatch.delenv("NOO_TLS_CERT", raising=False)
        monkeypatch.delenv("NOO_TLS_KEY", raising=False)

        from noomesh.gateway.deps import client_cert

        assert client_cert() is None

    def test_returns_none_when_cert_missing(self, tmp_path, monkeypatch):
        key = tmp_path / "key.pem"
        key.write_text("--- KEY ---")
        monkeypatch.setenv("NOO_TLS_CERT", "/nonexistent/cert.pem")
        monkeypatch.setenv("NOO_TLS_KEY", str(key))

        from noomesh.gateway.deps import client_cert

        assert client_cert() is None

    def test_returns_none_when_key_missing(self, tmp_path, monkeypatch):
        cert = tmp_path / "cert.pem"
        cert.write_text("--- CERT ---")
        monkeypatch.setenv("NOO_TLS_CERT", str(cert))
        monkeypatch.setenv("NOO_TLS_KEY", "/nonexistent/key.pem")

        from noomesh.gateway.deps import client_cert

        assert client_cert() is None

    def test_returns_none_when_env_empty(self, monkeypatch):
        monkeypatch.setenv("NOO_TLS_CERT", "")
        monkeypatch.setenv("NOO_TLS_KEY", "")

        from noomesh.gateway.deps import client_cert

        assert client_cert() is None
