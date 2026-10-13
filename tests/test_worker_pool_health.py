# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Supervisor-agnostic worker pool entry (WP-T23 phase 1).

The worker pool must run correctly whether the Rust gateway spawns it
(NOO_WORKER_SUPERVISOR=inprocess, today's default) or a separate
noo-trellion container does (external). These tests cover the pieces the
standalone entry adds: the /health listener, the RSS self-watchdog's
/proc reader, and the loud-but-non-fatal critical-env inventory check.
"""
from __future__ import annotations

import asyncio
import json
import sys
import urllib.request

import pytest

from noomesh.gateway.worker_pool import (
    _missing_critical_env,
    _read_rss_mb,
    _start_health_server,
)


class _FakeMessaging:
    def __init__(self, connected: bool):
        self.is_connected = connected


async def _get(url: str):
    """GET in a thread (urllib is blocking); returns (status, json body)."""
    def _fetch():
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:  # 4xx/5xx still carry the body
            return e.code, json.loads(e.read())
    return await asyncio.to_thread(_fetch)


def test_every_worker_healthcheck_dials_loopback() -> None:
    """The listener binds 127.0.0.1 only, so every healthcheck that probes it
    must dial 127.0.0.1 — `localhost` can resolve to ::1 first."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    files = ["docker-compose.cluster.yml", "docker-compose.trellion.yml",
             "docker/Dockerfile.worker", "docker/Dockerfile.trellion"]
    probes = []
    for rel in files:
        text = (root / rel).read_text()
        probes += [(rel, line.strip()) for line in text.splitlines() if ":8090/health" in line]
    assert len(probes) >= 4, f"parse found too few probes: {probes}"
    for rel, line in probes:
        assert "http://127.0.0.1:8090/health" in line, f"{rel}: {line}"


class TestHealthListener:
    async def test_the_listener_binds_loopback_only(self):
        """Its only consumer is the container's own healthcheck; a 0.0.0.0
        bind put a plain-HTTP listener on every compose network."""
        import inspect

        assert "host" not in inspect.signature(_start_health_server).parameters, (
            "the bind address must not be a caller's choice"
        )
        server = await _start_health_server(_FakeMessaging(True), port=0)
        try:
            addrs = {sock.getsockname()[0] for sock in server.sockets}
            assert addrs == {"127.0.0.1"}, f"health listener bound {addrs}"
        finally:
            server.close()
            await server.wait_closed()

    async def test_health_ok_when_nats_connected(self):
        server = await _start_health_server(
            _FakeMessaging(True), port=0)
        port = server.sockets[0].getsockname()[1]
        try:
            status, body = await _get(f"http://127.0.0.1:{port}/health")
            # Importing noomesh.workers registers real handlers, so the
            # count is the genuine registry size — must be > 0.
            assert status == 200
            assert body["nats_connected"] is True
            assert body["handlers_registered"] > 0
            assert body["status"] == "ok"
            # No DB in unit tests — informational, never gates the 200.
            assert body["db_ok"] is False
        finally:
            server.close()
            await server.wait_closed()

    async def test_health_503_when_nats_disconnected(self):
        server = await _start_health_server(
            _FakeMessaging(False), port=0)
        port = server.sockets[0].getsockname()[1]
        try:
            status, body = await _get(f"http://127.0.0.1:{port}/health")
            assert status == 503
            assert body["nats_connected"] is False
            assert body["status"] == "degraded"
        finally:
            server.close()
            await server.wait_closed()

    async def test_default_bind_is_loopback(self):
        """an earlier change: the listener's only consumer is the container's
        own healthcheck, so the DEFAULT bind (the one the pool uses) is
        loopback — never every interface of a container on noo-cluster."""
        server = await _start_health_server(_FakeMessaging(True), port=0)
        try:
            hosts = {sock.getsockname()[0] for sock in server.sockets}
            assert hosts == {"127.0.0.1"}, f"the /health listener binds {hosts}"
        finally:
            server.close()
            await server.wait_closed()

    async def test_unknown_path_is_404(self):
        server = await _start_health_server(
            _FakeMessaging(True), port=0)
        port = server.sockets[0].getsockname()[1]
        try:
            status, _ = await _get(f"http://127.0.0.1:{port}/nope")
            assert status == 404
        finally:
            server.close()
            await server.wait_closed()


class TestRssReader:
    @pytest.mark.skipif(sys.platform != "linux", reason="/proc is Linux-only")
    def test_reads_own_rss(self):
        rss = _read_rss_mb()
        assert rss is not None
        # A running pytest with this import graph is comfortably >10MB and
        # (sanity ceiling) below a terabyte.
        assert 10 < rss < 1024 * 1024


class TestCriticalEnvInventory:
    def test_alias_satisfies_group(self, monkeypatch):
        # DATABASE_URL alone must satisfy the (PAGEINDEX_DSN, DATABASE_URL)
        # group — the worker plane resolves either.
        monkeypatch.delenv("PAGEINDEX_DSN", raising=False)
        monkeypatch.setenv("DATABASE_URL", "postgresql://x")
        assert "PAGEINDEX_DSN" not in _missing_critical_env()

    def test_missing_group_is_reported_by_first_alias(self, monkeypatch):
        monkeypatch.delenv("PAGEINDEX_DSN", raising=False)
        monkeypatch.delenv("DATABASE_URL", raising=False)
        assert "PAGEINDEX_DSN" in _missing_critical_env()

    def test_blank_value_counts_as_missing(self, monkeypatch):
        # An allowlisted-but-empty ${VAR:-} passthrough is exactly the
        # silent-default trap the check exists for.
        monkeypatch.delenv("NOO_BUS_KEY_FILE", raising=False)
        monkeypatch.setenv("NOO_BUS_KEY", "   ")
        assert "NOO_BUS_KEY" in _missing_critical_env()

    def test_set_value_not_reported(self, monkeypatch):
        monkeypatch.setenv("NOO_BUS_KEY", "s3cret")
        assert "NOO_BUS_KEY" not in _missing_critical_env()

    def test_a_correctly_keyed_worker_logs_no_critical_env_unset(self, monkeypatch):
        """an earlier change: a worker carrying exactly what compose delivers —
        its own keys as `_FILE` pointers, and NO fleet or controller secret —
        is complete. Before, the list named NOO_CLUSTER_SECRET, so a worker
        keyed the 702 way warned `critical_env_unset` on every start."""
        from noomesh.gateway import worker_pool as wp

        for k in ("NOO_CLUSTER_SECRET", "NOO_CLUSTER_SECRET_FILE", "NOO_CONTROLLER_SECRET", "NOO_CONTROLLER_SECRET_FILE",
                  "NOO_BUS_KEY", "NOO_GATEWAY_KEY", "REDIS_PASSWORD", "NOO_AUDIT_HMAC_KEY"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("NOO_WORKER_SURFACES", "core")
        for k, v in {
            "PAGEINDEX_DSN": "postgresql://x", "NATS_URL": "tls://nats:4222", "REDIS_URL": "rediss://redis:6379",
            "REDIS_PASSWORD_FILE": "/run/secrets/redis_password", "NOO_AUDIT_HMAC_KEY_FILE": "/run/secrets/noo_audit_hmac_key",
            "NOO_BUS_KEY_FILE": "/run/secrets/noo_bus_key", "NOO_GATEWAY_KEY_FILE": "/run/secrets/noo_gateway_key",
            "NOO_SANDBOX_URL": "https://sandbox:8000",
        }.items():
            monkeypatch.setenv(k, v)
        assert _missing_critical_env() == []
        warned: list = []
        monkeypatch.setattr(wp.log, "warning", lambda event, **kw: warned.append(event))
        wp._warn_missing_critical_env()
        assert "worker_pool.critical_env_unset" not in warned, warned
        # And the list names no shared secret at all.
        names = {n for names, _ in wp._CRITICAL_ENV for n in names}
        assert not names & {"NOO_CLUSTER_SECRET", "NOO_CONTROLLER_SECRET"}, names
