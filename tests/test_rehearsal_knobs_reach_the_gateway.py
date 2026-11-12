# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The three gateway rehearsal knobs (i564) reach the gateway container.

The release rehearsal's test stack shortens three gateway timers by env:
`NOO_MESH_NODES_TTL_S`, `NOO_GATEWAY_HEARTBEAT_INTERVAL_S` and
`NOO_GATEWAY_IDLE_S`. The gateway has no env_file; a variable the compose
`environment:` list does not name never reaches it, however carefully it is
set in `/root/.noo/.env` (the same trap as `test_tunnel_brake_reaches_the_gateway`).

Each must pass through EMPTY when unset, so a shipped install keeps the
gateway's own default, and each must be read by the gateway under exactly
that name and documented.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests._compose_projection import load_raw, untag

REPO = Path(__file__).resolve().parents[1]
COMPOSE = REPO / "docker-compose.cluster.yml"
SRC = REPO / "gateway-rust" / "src"

# knob -> the gateway source file that names it
KNOBS = {
    "NOO_MESH_NODES_TTL_S": SRC / "state.rs",
    "NOO_GATEWAY_HEARTBEAT_INTERVAL_S": SRC / "coordinator" / "classes.rs",
    "NOO_GATEWAY_IDLE_S": SRC / "conn_timeouts.rs",
}


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


@pytest.mark.parametrize("knob", sorted(KNOBS))
def test_the_knob_reaches_the_gateway_and_is_empty_when_unset(knob: str) -> None:
    env = _gateway_env()
    assert knob in env, f"the gateway never sees {knob}; the rehearsal sets it in vain"
    assert env[knob] == f"${{{knob}:-}}", env[knob]


@pytest.mark.parametrize("knob", sorted(KNOBS))
def test_the_gateway_reads_exactly_that_name_and_the_docs_list_it(knob: str) -> None:
    src = KNOBS[knob].read_text()
    assert f'"{knob}"' in src, f"{KNOBS[knob].name} no longer names {knob}"
    rows = (REPO / "docs" / "reference" / "env.md").read_text()
    assert re.search(rf"^\| `{knob}` \|", rows, re.M), f"env.md has no row for {knob}"
