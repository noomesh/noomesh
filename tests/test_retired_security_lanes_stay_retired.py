# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Legacy/fallback security lanes that nothing used, retired together.

Each lane below had its code path deleted; these guards are the cheap half —
the places the lane was DELIVERED or ADVERTISED from, where it would most
likely come back by copy-paste. The behavioural halves live beside the code:

- 32-hex cluster signatures — `auth.rs` `cluster_token_accepts_only_the_full_64_hex_width`,
  `tests/test_cluster_auth.py`
- retired posture bridges — `posture.rs` `an_open_retired_bridge_refuses_boot`,
  `tests/test_posture_key_parity.py`, `tests/test_bus_principal_parity.py`
- Python gateway remnants — `tests/test_no_retired_python_gateway_imports.py`,
  `tests/test_heartbeat.py`
- noo_gateway insecure toggles — `packages/noo-gateway-client/tests`
- worker /health on loopback — `tests/test_worker_pool_health.py`
- node-agent org overrides — `internal/auth/principal_test.go`
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

COMPOSE = sorted(ROOT.glob("docker-compose*.yml"))

# Env keys whose only reader was a retired lane. Delivering one again hands a
# container a switch that does nothing (or, for the bus principal, a switch
# that would read as a working rollout bridge).
NOT_DELIVERED = {
    "TELEGRAM_ALLOWED_USERS": "retired allow-list: admits nobody (links are the allow-list)",
    "NOO_BUS_PRINCIPAL": "retired bridge: workers always require a verified Noo-Principal",
    "NOO_CLUSTER_LEGACY_FULL_ACCESS": "retired bridge: a fleet token is only ever a node",
    "NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH": "retired bridge: the pull lane is always signed",
    "NOO_CONTROLLER_CERT_ORG": "retired node-agent override: the agent refuses to start on it",
    "NOO_SERVICE_CERT_ORG": "retired node-agent override: the agent refuses to start on it",
    "NOO_NODE_CERT_ORG": "retired node-agent override: the agent refuses to start on it",
    "NOO_GATEWAY_TLS_VERIFY": "retired noo_gateway toggle: from_env refuses it",
    "NOO_GATEWAY_TLS_CHECK_HOSTNAME": "retired noo_gateway toggle: from_env refuses it",
    "NOO_GATEWAY_SHARED_SECRET_FALLBACK": "retired noo_gateway rung: from_env refuses it",
}


def _code_lines(text: str) -> list[tuple[int, str]]:
    return [(i, l) for i, l in enumerate(text.splitlines(), 1) if not l.lstrip().startswith("#")]


def test_no_compose_file_delivers_a_retired_key() -> None:
    assert len(COMPOSE) >= 3, f"found too few compose files: {COMPOSE}"
    hits = []
    for f in COMPOSE:
        for i, line in _code_lines(f.read_text()):
            for key, why in NOT_DELIVERED.items():
                if re.search(rf"(?<![A-Za-z0-9_]){key}(?![A-Za-z0-9_])", line):
                    hits.append(f"{f.name}:{i}: {key} — {why}")
    assert not hits, "retired keys delivered by compose:\n" + "\n".join(hits)


def test_the_worker_no_longer_gets_the_heartbeat_engine_gate() -> None:
    """GATEWAY_ENGINE gated the deleted Python heartbeat loop on the worker
    side. The gateway service's own GATEWAY_ENGINE (the launcher's engine
    selector) is a different reader and stays."""
    from tests._compose_projection import env_of, full_projection

    services = full_projection()
    for name in ("worker", "trellion"):
        if name in services:
            assert "GATEWAY_ENGINE" not in env_of(services[name]), (
                f"{name} is handed GATEWAY_ENGINE; its only reader was the deleted "
                "Python heartbeat firing loop"
            )


def test_no_insecure_tailscale_serve_advice() -> None:
    """`https+insecure://` tells tailscaled to skip verifying the backend —
    the one hop a serve mapping exists to make trustworthy."""
    trees = [ROOT / "noo-cli" / "src", ROOT / "gateway-rust" / "src", ROOT / "scripts", ROOT / "docs"]
    hits = []
    scanned = 0
    for tree in trees:
        for f in tree.rglob("*"):
            if not f.is_file() or f.suffix not in {".rs", ".sh", ".py", ".md"}:
                continue
            scanned += 1
            for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
                if "https+insecure://" in line:
                    hits.append(f"{f.relative_to(ROOT)}:{i}")
    assert scanned > 100, "scanned suspiciously few files"
    assert not hits, "insecure serve advice:\n" + "\n".join(hits)


def test_the_launcher_warns_about_the_retired_allowlist() -> None:
    lib = (ROOT / "scripts" / "lib-addons.sh").read_text()
    keys = (ROOT / "scripts" / "retired-env-keys").read_text()
    assert "warn_retired_env_keys()" in lib and "TELEGRAM_ALLOWED_USERS|" in keys
    assert "noo security user link" in keys, "the warning must name the replacement"
    assert "noo onboard --only env" in lib, "the warning must name the command that removes the line"
    for script in ("noomesh-start.sh", "noomesh-rebuild.sh"):
        text = (ROOT / "scripts" / script).read_text()
        assert re.search(r"^warn_retired_env_keys$", text, re.M), f"{script} never calls it"
