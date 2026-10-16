# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The gateway and the worker carry the first two lines of the sandbox's
container hardening, and the node-agent compose lane is not privileged by
default.

The audit (sandbox/exec lane): the sandbox runs under cap_drop ALL, a
read-only rootfs and no-new-privileges, while the gateway (which holds the JWT
secret, every bus key and the audit key) and the worker (which runs tool
code) ran with Docker's default capability set. Pinned here from the composed
projection:

  1. gateway, worker and worker-extra: `cap_drop: [ALL]`, no `cap_add`,
     `no-new-privileges:true`;
  2. the worker's `noomesh.yaml` mount is `:ro` (nothing in the worker writes
     it); the gateway's stays read-write, because its settings route writes
     that file;
  3. neither service is `privileged`;
  4. `read_only` is NOT claimed for either (their write sets are not a fixed
     list of paths; the comment on the service says why). If it is added
     later, the tmpfs for every path must come with it, so this test asserts
     the pair: read_only without a /tmp tmpfs fails;
  5. the `node-agent` service's `privileged:` default is `false` and
     `.env.example` ships `NOO_NODE_AGENT_PRIVILEGED=false`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests._compose_projection import full_projection

ROOT = Path(__file__).resolve().parents[1]
HARDENED = ("gateway", "worker", "worker-extra")


@pytest.fixture(scope="module")
def svcs() -> dict:
    return full_projection()["services"]


@pytest.mark.parametrize("name", HARDENED)
def test_capabilities_are_dropped(svcs, name):
    s = svcs[name]
    assert s.get("cap_drop") == ["ALL"], f"{name}: cap_drop is {s.get('cap_drop')!r}"
    assert not s.get("cap_add"), f"{name}: adds capabilities back: {s.get('cap_add')}"
    assert not s.get("privileged"), f"{name} is privileged"


@pytest.mark.parametrize("name", HARDENED)
def test_no_new_privileges(svcs, name):
    opts = svcs[name].get("security_opt") or []
    assert "no-new-privileges:true" in opts, f"{name}: security_opt is {opts!r}"


@pytest.mark.parametrize("name", HARDENED)
def test_read_only_comes_with_its_tmpfs(svcs, name):
    s = svcs[name]
    if s.get("read_only"):
        tmpfs = s.get("tmpfs") or []
        tmpfs = list(tmpfs) if not isinstance(tmpfs, str) else [tmpfs]
        assert any(str(t).split(":")[0] == "/tmp" for t in tmpfs), (
            f"{name}: read_only without a /tmp tmpfs; list every path the service writes"
        )


def _mount_of(svc: dict, target: str) -> dict:
    for v in svc.get("volumes") or []:
        if isinstance(v, dict) and v.get("target") == target:
            return v
        if isinstance(v, str) and v.split(":")[1:2] == [target]:
            parts = v.split(":")
            return {"source": parts[0], "target": parts[1], "read_only": len(parts) > 2 and "ro" in parts[2].split(",")}
    return {}


@pytest.mark.parametrize("name", ("worker", "worker-extra"))
def test_worker_config_mount_is_read_only(svcs, name):
    m = _mount_of(svcs[name], "/app/noomesh.yaml")
    assert m, f"{name} no longer mounts /app/noomesh.yaml (this guard would be vacuous)"
    assert m.get("read_only") is True, f"{name}: /app/noomesh.yaml is writable: {m}"


def test_gateway_keeps_its_config_writable(svcs):
    m = _mount_of(svcs["gateway"], "/app/noomesh.yaml")
    assert m, "the gateway must mount noomesh.yaml"
    assert not m.get("read_only"), (
        "the gateway's settings route writes noomesh.yaml; a :ro mount turns every settings save into an EROFS"
    )


def test_node_agent_lane_is_unprivileged_by_default():
    text = (ROOT / "docker-compose.cluster.yml").read_text()
    m = re.search(r"privileged:\s*\$\{NOO_NODE_AGENT_PRIVILEGED:-(\w+)\}", text)
    assert m, "the node-agent service lost its env-gated `privileged:` line"
    assert m.group(1) == "false", f"node-agent-compose defaults to privileged: {m.group(1)}"
    env = (ROOT / ".env.example").read_text()
    line = re.search(r"^NOO_NODE_AGENT_PRIVILEGED=(\S*)", env, re.M)
    assert line and line.group(1) == "false", ".env.example must ship NOO_NODE_AGENT_PRIVILEGED=false"
