# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The worker dials no node agent's controller routes.

noo-worker presents its own leaf, ``services/worker`` (``O=Mesh Cluster
Service``). Every node-agent route it ever named in the disk scan —
``POST /cleanup/images`` and ``POST /cleanup/logs`` — is ControllerOnly
(node-agent-go ``internal/api/server.go``), so a service leaf is refused
there with a 403 and a WARN on the node (``TestTheWorkerLeafIsRefused…`` in
``internal/api/worker_leaf_routes_test.go``).

The scan is the gateway's: ``disk_cleanup`` is RUST_NATIVE, the Rust
heartbeat owns cron, and the gateway presents the controller leaf. The
Python copies in ``heartbeat.py`` could never succeed (they sent no bearer,
so every node answered 401, and swallowed it into "0 dangling"). They now
refuse loudly without dialling. These tests pin all three facts.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import httpx
import pytest

from tests._compose_projection import env_of, full_projection

ROOT = Path(__file__).resolve().parents[1]
HEARTBEAT_ACTIONS = ROOT / "gateway-rust" / "src" / "heartbeat_actions.rs"


def _executor(requests: list):
    from noomesh.gateway.heartbeat import HeartbeatActionExecutor

    ex = HeartbeatActionExecutor(gateway_url="https://gateway.invalid:8080")

    def record(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(200, json={"nodes": [{"id": "n1", "agent_url": "https://n1:8081"}], "removed": 7, "truncated": 7})

    # Any dial at all is recorded: the refusal must happen BEFORE the network.
    ex._http_client = httpx.AsyncClient(transport=httpx.MockTransport(record))
    return ex


@pytest.mark.parametrize("method,target", [
    ("_detect_docker_images", "docker_dangling_images"),
    ("_detect_container_logs", "container_logs"),
])
def test_each_worker_node_scan_refuses_loudly_without_dialling(method, target):
    requests: list = []
    ex = _executor(requests)
    with pytest.raises(RuntimeError) as err:
        asyncio.run(getattr(ex, method)())
    msg = str(err.value)
    assert target in msg and "heartbeat_actions.rs" in msg, msg
    assert requests == [], f"the worker dialled {requests} — it holds no controller leaf"


def test_disk_cleanup_with_a_node_target_fails_the_run_not_reports_zero():
    """`actions must RAISE`: a refusal is a failed run, never a clean scan."""
    from noomesh.gateway.heartbeat import HeartbeatTask

    requests: list = []
    ex = _executor(requests)
    task = HeartbeatTask(id="t", name="t", schedule="0 3 * * *", action="disk_cleanup",
                         config={"targets": ["tmp_noo_files", "container_logs"]})
    with pytest.raises(RuntimeError, match="container_logs"):
        asyncio.run(ex._disk_cleanup(task))
    assert requests == []


def test_the_gateway_owns_disk_cleanup():
    """The route that still works: the Rust gateway runs the scan with its
    own controller leaf, for cron and for "Run now" alike."""
    src = HEARTBEAT_ACTIONS.read_text()
    native = src.split("const RUST_NATIVE_ACTIONS", 1)[1].split("];", 1)[0]
    assert re.search(r'^\s*"disk_cleanup",', native, re.M), "disk_cleanup left RUST_NATIVE — it would reach the worker, which refuses"
    body = src.split("async fn detect_container_logs", 1)[1].split("#[cfg(test)]", 1)[0]
    assert '"/cleanup/logs"' in body and '"/cleanup/images"' in src
    # The credential is chosen per agent: none for an agent
    # that admits the controller leaf alone, the legacy bearer otherwise.
    assert "build_node_agent_client()" in body and "node_agent_auth::header_for(" in body
    # A refused node is named, never folded into the count as zero.
    assert "NOT scanned" in body


def test_the_python_cron_loop_does_not_fire_in_the_worker():
    """Two things keep the Python `_dispatch` off the disk scan: the action
    is Rust-native, and the worker has no firing loop at all — an earlier change
    deleted it along with its `GATEWAY_ENGINE=python` gate, so the worker is
    not even handed the variable."""
    services = full_projection()["services"]
    for name in ("worker", "worker-extra"):
        assert "GATEWAY_ENGINE" not in env_of(services[name]), name
    hb = (ROOT / "src/noomesh/gateway/heartbeat.py").read_text()
    wp = (ROOT / "src/noomesh/gateway/worker_pool.py").read_text()
    assert "def start(" not in hb and "def _tick(" not in hb, "the Python firing loop is back"
    assert "hs.start(" not in wp, "the worker starts a heartbeat loop again"
