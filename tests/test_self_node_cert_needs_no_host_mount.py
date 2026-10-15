# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The stack start never depends on the controller's node identity (i67, F1).

0.6.3-rc.1 bind-mounted the host directory `/etc/noo/self-node` into the
gateway so it could read the controller's own node's birth cert. That
directory is created by the node-identity step, which runs AFTER the stack
starts on a fresh install (onboard's services tail) and had never run on an
upgraded controller, so the launcher's bind-source preflight refused every
start: "gateway: /etc/noo/self-node <- /etc/noo/self-node: missing (Docker
would create it root-owned)".

The cert now reaches the gateway through the PKI's certificate-only view it
already mounts read-only (`public/nodes` -> `/app/pki/nodes`), which the CLI
fills without sudo. This pins both halves: no gateway bind source under the
host's `/etc/noo`, and the view the cert rides is still mounted.
"""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.cluster.yml"


def _gateway_volumes() -> list[str]:
    doc = __import__("tests._compose_projection", fromlist=["untag"]).untag(
        __import__("tests._compose_projection", fromlist=["load_raw"]).load_raw(COMPOSE)
    )
    vols = doc["services"]["gateway"].get("volumes") or []
    out = []
    for v in vols:
        out.append(v if isinstance(v, str) else f"{v.get('source', '')}:{v.get('target', '')}")
    assert len(out) >= 5, f"the parser found only {out}"
    return out


def test_the_gateway_binds_nothing_from_the_hosts_etc_noo() -> None:
    bad = [v for v in _gateway_volumes() if v.split(":")[0].startswith("/etc/noo")]
    assert not bad, (
        "the gateway bind-mounts a host /etc/noo path; it does not exist before the node "
        f"identity does, and the launcher refuses the start: {bad}"
    )


def test_the_view_that_carries_the_self_nodes_cert_is_mounted() -> None:
    assert any(v.endswith("/public/nodes:/app/pki/nodes:ro") for v in _gateway_volumes()), _gateway_volumes()
    src = (ROOT / "gateway-rust/src/routes/bootstrap.rs").read_text()
    assert 'const SELF_NODES_VIEW: &str = "/app/pki/nodes";' in src
