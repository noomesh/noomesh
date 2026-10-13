# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Integration tests for the node-agent (Go or Python).

Exercises every HTTP endpoint on the running node-agent container.
Automatically skipped when NOO_NODE_AGENT_URL is not set.

Run:
    NOO_NODE_AGENT_URL=https://localhost:8081 \
    NOO_NODE_AGENT_TOKEN=<token> \
    pytest tests/integration/test_node_agent.py -v
"""
from __future__ import annotations

import os
import time

import httpx
import pytest

NODE_AGENT_URL = os.getenv("NOO_NODE_AGENT_URL", "").rstrip("/")
NODE_AGENT_TOKEN = os.getenv("NOO_NODE_AGENT_TOKEN", "")

pytestmark = pytest.mark.skipif(
    not NODE_AGENT_URL,
    reason="NOO_NODE_AGENT_URL not set — skipping node-agent integration tests",
)


@pytest.fixture
def client():
    """HTTP client with auth header and TLS skip."""
    headers = {}
    if NODE_AGENT_TOKEN:
        headers["Authorization"] = f"Bearer {NODE_AGENT_TOKEN}"
    return httpx.Client(
        base_url=NODE_AGENT_URL,
        headers=headers,
        verify=False,
        timeout=10.0,
    )


# ── Health (no auth required) ──


class TestHealth:
    def test_health_returns_200(self, client):
        # Health is public — send without auth too
        resp = httpx.get(f"{NODE_AGENT_URL}/health", verify=False, timeout=5)
        assert resp.status_code == 200

    def test_health_body(self, client):
        resp = httpx.get(f"{NODE_AGENT_URL}/health", verify=False, timeout=5)
        body = resp.json()
        assert body["status"] == "healthy"
        assert "node_id" in body
        assert body["node_id"] is not None


# ── Auth enforcement ──


class TestAuth:
    def test_unauthenticated_rejected(self):
        """All authenticated endpoints reject requests without a token."""
        endpoints = [
            ("POST", "/start"),
            ("POST", "/stop"),
            ("GET", "/gpu"),
            ("GET", "/metrics"),
            ("GET", "/logs/containers"),
            ("GET", "/stats/containers"),
            ("POST", "/api/device/location"),
        ]
        for method, path in endpoints:
            resp = httpx.request(
                method, f"{NODE_AGENT_URL}{path}",
                verify=False, timeout=5,
            )
            assert resp.status_code in (401, 403), (
                f"{method} {path}: expected 401/403, got {resp.status_code}"
            )


# ── GPU metrics ──


class TestGPU:
    def test_gpu_endpoint(self, client):
        resp = client.get("/gpu")
        assert resp.status_code == 200
        body = resp.json()
        assert "available" in body

    def test_gpu_has_node_id_when_available(self, client):
        resp = client.get("/gpu")
        body = resp.json()
        if body.get("available"):
            assert "node_id" in body
            assert "gpu_utilization_percent" in body


# ── Prometheus metrics ──


class TestPrometheus:
    def test_metrics_returns_text(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers.get("content-type", "")

    def test_metrics_has_required_families(self, client):
        resp = client.get("/metrics")
        text = resp.text
        assert "noo_node_info" in text
        assert "noo_node_load" in text
        assert "# HELP" in text
        assert "# TYPE" in text

    def test_metrics_node_id_label(self, client):
        resp = client.get("/metrics")
        assert "node_id=" in resp.text


# ── Container logs ──


class TestLogs:
    def test_list_containers(self, client):
        resp = client.get("/logs/containers")
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, list)
        if body:
            assert "name" in body[0]
            assert "status" in body[0]

    def test_get_container_logs(self, client):
        """Get logs from a real container (if any are running)."""
        containers = client.get("/logs/containers").json()
        if not containers:
            pytest.skip("No containers running")

        name = containers[0]["name"]
        resp = client.get(f"/logs/{name}", params={"tail": 10})
        assert resp.status_code == 200
        body = resp.json()
        assert "logs" in body

    def test_get_logs_nonexistent(self, client):
        resp = client.get("/logs/nonexistent-container-12345")
        assert resp.status_code in (404, 500)


# ── Container stats ──


class TestStats:
    def test_container_stats(self, client):
        resp = client.get("/stats/containers")
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body, list)
        if body:
            stat = body[0]
            assert "name" in stat
            assert "cpu_percent" in stat
            assert "mem_usage_mb" in stat


# ── Device sensors (mock endpoints) ──


class TestDeviceSensors:
    def test_camera_describe(self, client):
        resp = client.post("/api/device/camera_capture", json={"describe": True})
        assert resp.status_code == 200
        assert "description" in resp.json()

    def test_camera_image(self, client):
        resp = client.post("/api/device/camera_capture", json={"describe": False})
        assert resp.status_code == 200
        body = resp.json()
        assert "image" in body
        assert body["format"] == "png"

    def test_location(self, client):
        resp = client.post("/api/device/location")
        assert resp.status_code == 200
        body = resp.json()
        assert "lat" in body
        assert "lon" in body
        assert "accuracy_m" in body

    def test_clipboard(self, client):
        resp = client.post("/api/device/clipboard")
        assert resp.status_code == 200
        assert "content" in resp.json()

    def test_screenshot_describe(self, client):
        resp = client.post("/api/device/screenshot", json={"describe": True})
        assert resp.status_code == 200
        assert "description" in resp.json()

    def test_audio(self, client):
        resp = client.post("/api/device/ambient_audio", json={"duration_seconds": 3})
        assert resp.status_code == 200
        body = resp.json()
        assert "transcript" in body
        assert body["duration_seconds"] == 3

    def test_battery(self, client):
        resp = client.post("/api/device/battery_status")
        assert resp.status_code == 200
        body = resp.json()
        assert "battery_pct" in body
        assert "is_charging" in body


# ── Backend start/stop (Docker required) ──


class TestBackendLifecycle:
    """Tests that actually start/stop containers. Run with caution."""

    @pytest.mark.skipif(
        not os.getenv("NOO_TEST_BACKEND_LIFECYCLE"),
        reason="Set NOO_TEST_BACKEND_LIFECYCLE=1 to enable destructive backend tests",
    )
    def test_start_and_stop_ollama(self, client):
        # Start
        resp = client.post("/start", json={
            "backend": "ollama",
            "model": "qwen3:8b",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "started"
        assert body["backend"] == "ollama"

        # Give it a moment to come up
        time.sleep(5)

        # Stop
        resp = client.post("/stop", json={"backend": "ollama"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "stopped"
