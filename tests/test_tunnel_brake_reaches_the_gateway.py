# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The tunnel brake the docs name actually reaches the gateway.

`docs/reference/env.md` says `NOO_NODE_TUNNEL=0` makes the gateway answer
`404` on `GET /api/node/tunnel` and send every streaming and bulk node call
over HTTPS again. The gateway reads it from its process environment
(`gateway-rust/src/tunnel.rs`), and the gateway container only sees what the
compose `environment:` list names — so until the first rebase of the phase 2
branch onto dev the brake was documented, read, and unreachable: an operator
following the page would have set a dial wired to nothing (the search-provider
knobs had the same gap, `test_search_provider_knobs_reach_the_gateway`).

This reads the raw compose file (not a projection) because the question is
"is the variable on the gateway's environment list", nothing more.
"""
from __future__ import annotations

import re
from pathlib import Path

from tests._compose_projection import load_raw, untag

REPO = Path(__file__).resolve().parents[1]
COMPOSE = REPO / "docker-compose.cluster.yml"
TUNNEL_RS = REPO / "gateway-rust" / "src" / "tunnel.rs"
BRAKE = "NOO_NODE_TUNNEL"


def _gateway_env() -> dict[str, str]:
    services = untag(load_raw(COMPOSE))["services"]
    env = services["gateway"].get("environment") or []
    if isinstance(env, dict):
        return {k: str(v) for k, v in env.items()}
    out: dict[str, str] = {}
    for e in env:
        if isinstance(e, str):
            k, _, v = e.partition("=")
            out[k] = v
    return out


def test_the_brake_reaches_the_gateway_and_is_open_when_unset() -> None:
    env = _gateway_env()
    assert BRAKE in env, f"the gateway never sees {BRAKE}; env.md says it is the operator's brake"
    # Unset on the host must stay unset in the container: the gateway treats
    # an empty value as "tunnels on", and a compose default of `1` would hide
    # a typo in the operator's .env behind a value that looks deliberate.
    assert env[BRAKE] == "${NOO_NODE_TUNNEL:-}", env[BRAKE]


def test_the_gateway_reads_exactly_that_name() -> None:
    """The compose line and the reader name the same variable; a rename of
    either side without the other is the original gap again."""
    src = TUNNEL_RS.read_text()
    assert re.search(rf'env::var\("{BRAKE}"\)', src), f"tunnel.rs no longer reads {BRAKE}"
    rows = (REPO / "docs" / "reference" / "env.md").read_text()
    assert re.search(rf"^\| `{BRAKE}` \|", rows, re.M), f"env.md has no row for {BRAKE}"
