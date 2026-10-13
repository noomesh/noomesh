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


# ── cli_http_verify() from cli_utils ────────────────────────────────


class TestCliHttpVerify:
    """Tests for cli_utils.cli_http_verify()."""

    def test_returns_ca_path_when_available(self, tmp_path, monkeypatch):
        ca = tmp_path / "ca.crt"
        ca.write_text("--- CA ---")
        monkeypatch.setenv("NOO_TLS_CA", str(ca))

        from noomesh.cli_utils import cli_http_verify

        assert cli_http_verify() == str(ca)

    def test_returns_false_for_https_without_ca(self, monkeypatch):
        monkeypatch.delenv("NOO_TLS_CA", raising=False)
        monkeypatch.setenv("CONTROLLER_URL", "https://localhost:8080")

        from noomesh.cli_utils import cli_http_verify

        assert cli_http_verify() is False

    def test_returns_true_for_http(self, monkeypatch):
        monkeypatch.delenv("NOO_TLS_CA", raising=False)
        monkeypatch.setenv("CONTROLLER_URL", "http://localhost:8080")

        from noomesh.cli_utils import cli_http_verify

        assert cli_http_verify() is True

    def test_ca_takes_priority_over_url_scheme(self, tmp_path, monkeypatch):
        """Even for HTTP URLs, if CA is set, return the CA path."""
        ca = tmp_path / "ca.crt"
        ca.write_text("--- CA ---")
        monkeypatch.setenv("NOO_TLS_CA", str(ca))
        monkeypatch.setenv("CONTROLLER_URL", "http://localhost:8080")

        from noomesh.cli_utils import cli_http_verify

        assert cli_http_verify() == str(ca)


# ── cli_client_cert() from cli_utils ────────────────────────────────


class TestCliClientCert:
    """Tests for cli_utils.cli_client_cert()."""

    def test_returns_tuple_when_configured(self, tmp_path, monkeypatch):
        cert = tmp_path / "client.crt"
        key = tmp_path / "client.key"
        cert.write_text("--- CERT ---")
        key.write_text("--- KEY ---")
        monkeypatch.setenv("NOO_TLS_CERT", str(cert))
        monkeypatch.setenv("NOO_TLS_KEY", str(key))

        from noomesh.cli_utils import cli_client_cert

        assert cli_client_cert() == (str(cert), str(key))

    def test_returns_none_when_not_set(self, monkeypatch):
        monkeypatch.delenv("NOO_TLS_CERT", raising=False)
        monkeypatch.delenv("NOO_TLS_KEY", raising=False)

        from noomesh.cli_utils import cli_client_cert

        assert cli_client_cert() is None

    def test_returns_none_when_files_missing(self, monkeypatch):
        monkeypatch.setenv("NOO_TLS_CERT", "/no/cert.pem")
        monkeypatch.setenv("NOO_TLS_KEY", "/no/key.pem")

        from noomesh.cli_utils import cli_client_cert

        assert cli_client_cert() is None
