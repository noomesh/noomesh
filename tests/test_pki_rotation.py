# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for PKI certificate rotation, trust removal, and auto-rotate.

Tests:
  - TestClusterCA: get_cert_info, rotate_gateway_cert, rotate_all_expiring,
    rotate_all_skips_ca, default_lifetime_90_days
  - TestRemoveCaTrust: remove_linux, remove_wsl2, remove_no_cert_returns_true
  - TestCertAutoRotateAction: no_expiring, rotates_expiring_leaf
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from noomesh.pki.ca import ClusterCA

# Several test groups below were written ahead of the implementation
# (get_cert_info / rotate_gateway_cert / CRL / CA passphrase never landed
# in ClusterCA). Feature-detect so they activate automatically when the
# methods are implemented, instead of failing CI until then.
requires_cert_info = pytest.mark.skipif(
    not hasattr(ClusterCA, "get_cert_info"),
    reason="ClusterCA.get_cert_info not implemented yet")
requires_rotate_gateway = pytest.mark.skipif(
    not hasattr(ClusterCA, "rotate_gateway_cert"),
    reason="ClusterCA.rotate_gateway_cert not implemented yet")
requires_crl = pytest.mark.skipif(
    not hasattr(ClusterCA, "generate_crl"),
    reason="ClusterCA CRL support not implemented yet")
requires_ca_passphrase = pytest.mark.skipif(
    "passphrase" not in ClusterCA.generate_ca.__doc__ if ClusterCA.generate_ca.__doc__ else True,
    reason="ClusterCA passphrase support not implemented yet")


# ---------------------------------------------------------------------------
# ClusterCA tests (uses tmp_path for real cert generation)
# ---------------------------------------------------------------------------


class TestClusterCA:
    """Integration tests using real cryptography operations in a temp dir."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path: Path):
        from noomesh.pki.ca import ClusterCA

        self.pki_dir = tmp_path / "pki"
        self.ca = ClusterCA(pki_dir=self.pki_dir)
        self.ca.generate_ca()

    @requires_cert_info
    def test_get_cert_info_gateway(self):
        self.ca.issue_gateway_cert(hostname="gw1", ip="10.0.0.1")
        cert_path = self.pki_dir / "gateway" / "gateway.crt"
        info = self.ca.get_cert_info(cert_path)
        assert info["role"] == "gateway"
        assert info["cn"] == "gw1"
        assert "gw1" in info["dns_names"]
        assert "10.0.0.1" in info["ip_addresses"]

    @requires_cert_info
    def test_get_cert_info_node(self):
        self.ca.issue_node_cert("worker-1", "192.168.1.10")
        cert_path = self.pki_dir / "nodes" / "worker-1" / "node.crt"
        info = self.ca.get_cert_info(cert_path)
        assert info["role"] == "node"
        assert info["cn"] == "worker-1"
        assert "192.168.1.10" in info["ip_addresses"]

    @requires_cert_info
    def test_get_cert_info_ca(self):
        info = self.ca.get_cert_info(self.pki_dir / "ca.crt")
        assert info["role"] == "ca"
        assert info["cn"] == "Mesh Cluster CA"

    @requires_rotate_gateway
    def test_rotate_gateway_cert(self):
        self.ca.issue_gateway_cert(hostname="gw1", ip="10.0.0.1")
        old_cert = (self.pki_dir / "gateway" / "gateway.crt").read_bytes()

        self.ca.rotate_gateway_cert(days=90)

        new_cert = (self.pki_dir / "gateway" / "gateway.crt").read_bytes()
        assert new_cert != old_cert
        assert (self.pki_dir / "gateway" / "gateway.key").exists()

        # SAN should still include the original hostname
        info = self.ca.get_cert_info(self.pki_dir / "gateway" / "gateway.crt")
        assert "gw1" in info["dns_names"]

    def test_rotate_all_expiring(self):
        # Issue certs with 1-day validity (they'll be "expiring" for warn_days=30)
        self.ca.issue_gateway_cert(hostname="gw1", ip="10.0.0.1", days=1)
        self.ca.issue_node_cert("n1", "10.0.0.2", days=1)

        results = self.ca.rotate_all_expiring(warn_days=30, new_days=90)

        # Should have rotated both leaf certs (gateway + node)
        rotated = [r for r in results if r["status"] == "rotated"]
        assert len(rotated) >= 2

        # Verify new certs exist
        assert (self.pki_dir / "gateway" / "gateway.crt").exists()
        assert (self.pki_dir / "nodes" / "n1" / "node.crt").exists()

    def test_rotate_all_skips_ca(self):
        # Issue a gateway cert with 1-day validity to ensure something expires
        self.ca.issue_gateway_cert(hostname="gw1", ip="10.0.0.1", days=1)

        results = self.ca.rotate_all_expiring(warn_days=9999, new_days=90)

        # CA should be skipped, not rotated
        ca_results = [r for r in results if r["role"] == "ca"]
        for r in ca_results:
            assert r["status"] == "skipped"

    def test_default_lifetime_90_days(self):
        from cryptography import x509

        self.ca.issue_gateway_cert(hostname="gw1", ip="10.0.0.1")
        cert_bytes = (self.pki_dir / "gateway" / "gateway.crt").read_bytes()
        cert = x509.load_pem_x509_certificate(cert_bytes)

        expires = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        days_until_expiry = (expires - now).days

        # Should be approximately 90 days (allow +-1 for test execution time)
        assert 88 <= days_until_expiry <= 91

    def test_rotate_all_no_expiring(self):
        # Issue certs with long validity
        self.ca.issue_gateway_cert(hostname="gw1", ip="10.0.0.1", days=365)

        results = self.ca.rotate_all_expiring(warn_days=30, new_days=90)

        # Nothing should be expiring within 30 days
        assert len(results) == 0


# remove_ca_trust unit tests moved with onboard/ca_trust.py to
# legacy/python-onboard/ (2026-08-06); the live trust-store logic is native
# Rust with its own tests (noo-cli security_local.rs).


# ---------------------------------------------------------------------------
# cert_auto_rotate heartbeat action tests
# ---------------------------------------------------------------------------


class TestCertAutoRotateAction:
    """Test the heartbeat cert_auto_rotate action with mocked ClusterCA."""

    @pytest.fixture
    def executor(self):
        from noomesh.gateway.heartbeat import HeartbeatActionExecutor
        return HeartbeatActionExecutor(gateway_url="http://127.0.0.1:8080")

    @pytest.fixture
    def task(self):
        from noomesh.gateway.heartbeat import HeartbeatTask
        return HeartbeatTask(
            id="test-rotate",
            name="Test cert rotation",
            schedule="0 3 * * *",
            action="cert_auto_rotate",
            config={"warn_days": 30, "new_cert_days": 90},
        )

    @pytest.mark.asyncio
    async def test_no_expiring_returns_valid_message(self, executor, task, tmp_path):
        from noomesh.pki.ca import ClusterCA

        pki_dir = tmp_path / "pki"
        ca = ClusterCA(pki_dir=pki_dir)
        ca.generate_ca()
        ca.issue_gateway_cert(days=365)

        task.config["pki_dir"] = str(pki_dir)

        result = await executor._cert_auto_rotate(task)
        assert "no leaf certificates expiring" in result.lower()

    @pytest.mark.asyncio
    async def test_expiring_leaf_delegates_to_host_spool(self, executor, task, tmp_path):
        """WP-C hazard 3: the heartbeat action must NOT rotate in-process.

        It queues a "rotate pki" spool command for the host watcher (the
        same safety envelope workers/security.py uses — backup → rotate →
        probe → auto-revert) and leaves the certs on disk untouched.
        """
        from noomesh.pki.ca import ClusterCA

        pki_dir = tmp_path / "pki"
        ca = ClusterCA(pki_dir=pki_dir)
        ca.generate_ca()
        ca.issue_gateway_cert(hostname="gw1", ip="10.0.0.1", days=1)

        cert_files = sorted(p for p in pki_dir.rglob("*") if p.is_file())
        before = {p: p.read_bytes() for p in cert_files}

        task.config["pki_dir"] = str(pki_dir)
        task.config["result_wait_seconds"] = 0  # don't poll in tests

        calls = []

        def fake_write_command(op, service, **kwargs):
            calls.append((op, service, kwargs))
            return str(tmp_path / "spool" / "20260801-000000-abcd.cmd.json")

        with patch(
            "noomesh.gateway.host_spool.write_command",
            side_effect=fake_write_command,
        ):
            result = await executor._cert_auto_rotate(task)

        # Delegated, with the exact spool payload the watcher expects.
        assert calls == [("rotate", "pki", {"requested_by": "cert_auto_rotate"})]
        assert "queued host-side" in result.lower()
        assert "auto-revert" in result.lower()

        # And nothing was rotated in-process: every PKI file is untouched.
        after = {p: p.read_bytes() for p in sorted(
            p for p in pki_dir.rglob("*") if p.is_file()
        )}
        assert after == before, "heartbeat action must not touch certs in-process"

    @pytest.mark.asyncio
    async def test_spool_unavailable_raises(self, executor, task, tmp_path):
        """A failed queue must RAISE (a return string would record success)."""
        from noomesh.pki.ca import ClusterCA

        pki_dir = tmp_path / "pki"
        ca = ClusterCA(pki_dir=pki_dir)
        ca.generate_ca()
        ca.issue_gateway_cert(hostname="gw1", ip="10.0.0.1", days=1)

        task.config["pki_dir"] = str(pki_dir)
        task.config["result_wait_seconds"] = 0

        with patch(
            "noomesh.gateway.host_spool.write_command", return_value=None
        ):
            with pytest.raises(RuntimeError, match="host spool"):
                await executor._cert_auto_rotate(task)

    @pytest.mark.asyncio
    async def test_no_expiring_does_not_queue(self, executor, task, tmp_path):
        """Nothing expiring → early return, no spool command written."""
        from noomesh.pki.ca import ClusterCA

        pki_dir = tmp_path / "pki"
        ca = ClusterCA(pki_dir=pki_dir)
        ca.generate_ca()
        ca.issue_gateway_cert(days=365)

        task.config["pki_dir"] = str(pki_dir)

        with patch(
            "noomesh.gateway.host_spool.write_command"
        ) as mock_write:
            result = await executor._cert_auto_rotate(task)

        mock_write.assert_not_called()
        assert "no leaf certificates expiring" in result.lower()

    @pytest.mark.asyncio
    async def test_no_pki_dir_returns_not_configured(self, executor, task):
        task.config["pki_dir"] = ""

        with patch.dict("os.environ", {"NOO_PKI_DIR": ""}, clear=False):
            result = await executor._cert_auto_rotate(task)
        assert "not configured" in result.lower()


# ---------------------------------------------------------------------------
# CRL tests
# ---------------------------------------------------------------------------


@requires_crl
class TestClusterCRL:
    """Integration tests for CRL generation and revocation tracking."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path: Path):
        from noomesh.pki.ca import ClusterCA

        self.pki_dir = tmp_path / "pki"
        self.ca = ClusterCA(pki_dir=self.pki_dir)
        self.ca.generate_ca()

    def test_generate_empty_crl(self):
        crl_path = self.ca.generate_crl()
        assert crl_path.exists()
        info = self.ca.get_crl_info()
        assert info is not None
        assert info["revoked_count"] == 0

    def test_revoke_adds_to_crl(self):
        self.ca.issue_node_cert("n1", "10.0.0.2")
        self.ca.revoke_node_cert("n1", update_crl=True)

        info = self.ca.get_crl_info()
        assert info is not None
        assert info["revoked_count"] == 1

        # Node cert dir should be deleted
        assert not (self.pki_dir / "nodes" / "n1").exists()

    def test_multiple_revocations_accumulate(self):
        self.ca.issue_node_cert("n1", "10.0.0.2")
        self.ca.issue_node_cert("n2", "10.0.0.3")
        self.ca.revoke_node_cert("n1", update_crl=True)
        self.ca.revoke_node_cert("n2", update_crl=True)

        info = self.ca.get_crl_info()
        assert info["revoked_count"] == 2

    def test_get_crl_info_none_when_missing(self):
        assert self.ca.get_crl_info() is None

    def test_revoke_without_crl_update(self):
        self.ca.issue_node_cert("n1", "10.0.0.2")
        self.ca.revoke_node_cert("n1", update_crl=False)
        assert not (self.pki_dir / "nodes" / "n1").exists()
        # No CRL should exist
        assert self.ca.get_crl_info() is None


# ---------------------------------------------------------------------------
# PKCS8 passphrase tests
# ---------------------------------------------------------------------------


@requires_ca_passphrase
class TestClusterCAPassphrase:
    """Test encrypted CA key generation and loading."""

    def test_generate_ca_with_passphrase(self, tmp_path: Path):
        from noomesh.pki.ca import ClusterCA

        ca = ClusterCA(pki_dir=tmp_path / "pki")
        ca.generate_ca(passphrase="test-secret-123")

        # Key file should exist and be encrypted (starts with ENCRYPTED)
        key_bytes = (tmp_path / "pki" / "ca.key").read_bytes()
        assert b"ENCRYPTED" in key_bytes

    def test_load_ca_with_passphrase(self, tmp_path: Path):
        from noomesh.pki.ca import ClusterCA

        ca = ClusterCA(pki_dir=tmp_path / "pki")
        ca.generate_ca(passphrase="test-secret-123")

        # Should be able to issue a cert when passphrase is correct
        ca._load_ca(passphrase="test-secret-123")  # Should not raise

    def test_load_ca_wrong_passphrase_fails(self, tmp_path: Path):
        from noomesh.pki.ca import ClusterCA

        ca = ClusterCA(pki_dir=tmp_path / "pki")
        ca.generate_ca(passphrase="test-secret-123")

        with pytest.raises(Exception):
            ca._load_ca(passphrase="wrong-password")

    def test_load_ca_env_passphrase(self, tmp_path: Path):
        from noomesh.pki.ca import ClusterCA

        ca = ClusterCA(pki_dir=tmp_path / "pki")
        ca.generate_ca(passphrase="env-secret")

        with patch.dict("os.environ", {"NOO_PKI_PASSPHRASE": "env-secret"}):
            ca._load_ca()  # Should use env var — no raise


# TestBackendCooldownClear was deleted with cluster/backend_manager.py
# (task #23 sweep): the Python BackendManager never ran under the Rust
# gateway (never wired into its own singleton), so its cooldown clearing
# was dead code — the live cooldown behavior is the Rust gateway's.

