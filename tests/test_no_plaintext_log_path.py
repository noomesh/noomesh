# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The log shipper has exactly one push path, and it is never plaintext.

Fleet logging plan §1.2: nodes push to the CONTROLLER (node leaf + cluster
token, `POST /api/cluster/nodes/{self}/logs`), never to a Loki port. Two
things pin that in source, because the Go tests can only prove what the
code under test does, not that no OTHER path was added beside it:

  - the shipper builds its URL from the controller URL and refuses a
    scheme other than https:// (a Go test exercises the refusal; this
    checks the guard is still there and that the test still runs);
  - nothing under internal/logship names a Loki endpoint or a plain
    `http://` URL — the only way to a log store is through the gateway.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOGSHIP = ROOT / "node-agent-go/internal/logship"


def _sources() -> dict[str, str]:
    files = {p.name: p.read_text() for p in LOGSHIP.glob("*.go") if not p.name.endswith("_test.go")}
    assert files, "internal/logship has no sources — the package moved and this test checks nothing"
    return files


def _code_only(src: str) -> str:
    return "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("//"))


def test_the_push_url_is_the_controller_ingest_route_and_https_only() -> None:
    push = _sources()["push.go"]
    assert '"/api/cluster/nodes/" + nodeID + "/logs"' in push, "the push URL is no longer the gateway ingest route"
    assert re.search(r'HasPrefix\(strings\.ToLower\(u\), "https://"\)', push), (
        "the https:// guard on the controller URL is gone — the cluster token would cross the wire in the clear"
    )
    test = (LOGSHIP / "shipper_test.go").read_text()
    assert "func TestAnHTTPControllerIsRefused" in test, "the Go test for the plaintext refusal was removed"


def test_no_loki_endpoint_and_no_plaintext_url_in_the_shipper() -> None:
    for name, src in _sources().items():
        code = _code_only(src)
        assert "loki/api" not in code and "/loki/" not in code, f"{name} names a Loki endpoint; nodes push through the gateway only"
        assert ":3100" not in code and ":3101" not in code, f"{name} names a Loki port"
        assert '"http://' not in code, f"{name} builds a plaintext URL"


def test_the_gateway_forwards_to_loki_over_https_only() -> None:
    """The second hop (phase 6). The gateway's `NOO_LOKI_URL` default in compose
    is https, and the ingest route builds its push URL from that value with no
    scheme of its own — so there is no `http://` anywhere on the path a log
    line takes. The test module of logs_ingest.rs dials a local listener over
    http and is cut off before the scan."""
    compose = (ROOT / "docker-compose.cluster.yml").read_text()
    defaults = re.findall(r"NOO_LOKI_URL=\$\{NOO_LOKI_URL:-([^}]+)\}", compose)
    assert defaults, "compose no longer sets NOO_LOKI_URL with a default — the parse found nothing"
    for d in defaults:
        assert d.startswith("https://"), f"NOO_LOKI_URL defaults to a plaintext Loki: {d}"

    ingest = (ROOT / "gateway-rust/src/routes/logs_ingest.rs").read_text()
    code = _code_only(ingest.split("#[cfg(test)]", 1)[0])
    assert '"/loki/api/v1/push"' in code or "/loki/api/v1/push" in code, "the forward URL is no longer Loki's push route"
    assert '"http://' not in code, "logs_ingest.rs builds a plaintext URL"
    assert "cluster_client()" in code, "the forward no longer uses the gateway's mTLS client"


def test_the_compose_loki_service_publishes_no_port() -> None:
    """Read, not edited: `docker compose config` with every profile, so an
    overlay cannot add a `ports:` block the raw file does not show."""
    from tests._compose_projection import full_projection

    loki = full_projection()["services"].get("loki")
    assert loki, "the compose projection has no loki service"
    assert "ports" not in loki, f"loki publishes a host port: {loki['ports']} — a node pushes through the gateway, never to Loki"


def test_the_agent_hands_the_shipper_the_heartbeats_transport_and_bearer() -> None:
    """Same leaf, same token, same door: the shipper must not grow its own client."""
    agent = _code_only((ROOT / "node-agent-go/internal/agent/agent.go").read_text())
    block = agent.split("func (a *Agent) startLogShip", 1)[1].split("\n}\n", 1)[0]
    assert "Client:        a.http," in block or "Client: a.http," in block, "the shipper is not using the agent's mTLS client"
    assert "auth.SetClusterAuth(req, a.cfg.NodeID, a.cfg.ClusterSecret)" in block, "the shipper is not sending the heartbeat's cluster token"
