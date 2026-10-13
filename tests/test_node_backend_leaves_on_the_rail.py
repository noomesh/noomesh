# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A node's backend door leaves travel the rail.

Four places name the same set of door services and must agree:

  noo-cli/src/commands/node_leaves.rs  NODE_DOOR_LEAVES — what the controller
                                       issues and packs (svc-<x>.crt/.key)
  scripts/noo-apply.sh                 the `for _svc in ...` install loop — what
                                       a Linux node installs
  node-agent-go internal/docker        backendDoors — which leaf each backend's
                                       door serves with, and the host the agent
                                       dials it by (arrives with the door PR)
  the allow-lists                      tests/test_bundle_kind_allowlists.py

A service in the Rust table that the applier loop does not name is a pair
that is signed, delivered, verified -- and silently never installed: the
node applies the bundle with exit 0 and keeps refusing the backend. That is
the silent-success shape, so it is pinned here rather than trusted.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
LEAVES_RS = REPO / "noo-cli/src/commands/node_leaves.rs"
APPLY = REPO / "scripts/noo-apply.sh"
GO_DOORS = REPO / "node-agent-go/internal/docker/client.go"


def _rust_rows() -> list[dict]:
    text = LEAVES_RS.read_text()
    table = re.search(r"pub const NODE_DOOR_LEAVES: &\[NodeDoorLeaf\] = &\[(.*?)\n\];", text, re.S)
    assert table, "node_leaves.rs: no NODE_DOOR_LEAVES table"
    rows = []
    for block in re.findall(r"NodeDoorLeaf \{(.*?)\}", table.group(1), re.S):
        row = {}
        for field in ("service", "crt_kind", "key_kind"):
            m = re.search(rf'{field}: "([^"]+)"', block)
            assert m, f"row without {field}: {block}"
            row[field] = m.group(1)
        for field in ("backends", "doors"):
            m = re.search(rf"{field}: &\[(.*?)\]", block, re.S)
            assert m, f"row without {field}: {block}"
            row[field] = re.findall(r'"([^"]+)"', m.group(1))
        rows.append(row)
    assert len(rows) >= 5, f"parsed {len(rows)} rows -- the parser, not the table, is broken"
    return rows


def _apply_loop() -> list[str]:
    m = re.search(r"^for _svc in ([a-z ]+); do$", APPLY.read_text(), re.M)
    assert m, "noo-apply.sh: no `for _svc in ...; do` leaf install loop"
    return m.group(1).split()


def test_the_applier_installs_every_service_the_controller_packs() -> None:
    assert _apply_loop() == [r["service"] for r in _rust_rows()]


def test_the_applier_loop_reads_the_kinds_the_controller_writes() -> None:
    text = APPLY.read_text()
    assert '_c="$WORK/files/svc-$_svc.crt"; _k="$WORK/files/svc-$_svc.key"' in text
    for r in _rust_rows():
        assert r["crt_kind"] == f"svc-{r['service']}.crt"
        assert r["key_kind"] == f"svc-{r['service']}.key"


def test_every_door_name_is_what_the_agent_dials() -> None:
    """vLLM's own listener is dialled as noo-<backend>; every other door is
    a sidecar, dialled as noo-stunnel-<service>."""
    for r in _rust_rows():
        if r["service"] == "vllm":
            assert r["doors"] == [f"noo-{b}" for b in r["backends"]], r
        else:
            assert r["doors"] == [f"noo-stunnel-{r['service']}"], r


def test_the_agent_door_table_agrees_when_it_is_present() -> None:
    """The Go door table lands with the door PR (#544). Before it, there is
    nothing to compare against, and this says so instead of passing."""
    text = GO_DOORS.read_text()
    table = re.search(r"var backendDoors = map\[string\]backendDoor\{(.*?)\n\}", text, re.S)
    if not table:
        pytest.skip("node-agent-go has no backendDoors table on this base (door PR #544 not merged)")
    go: dict[str, str] = {}
    for backend, body in re.findall(r'"([a-z-]+)":\s*\{([^}]*)\}', table.group(1)):
        m = re.search(r'Sidecar:\s*"([^"]+)"', body)
        go[backend] = m.group(1) if m else "vllm"
    assert go, "parsed no rows from backendDoors"
    rust = {b: r["service"] for r in _rust_rows() for b in r["backends"]}
    assert go == rust, f"agent doors {go} vs controller leaves {rust}"


GO_LEAF_REPORT = REPO / "node-agent-go/internal/backendleaves/backendleaves.go"


def test_the_agent_reports_every_leaf_the_controller_packs() -> None:
    """The heartbeat's `backend_leaves` covers exactly the
    services the controller issues. One the agent does not look for would
    read, in `noo cluster verify`, as a node holding no leaf it actually
    holds -- the row fails a healthy node."""
    m = re.search(r"var Services = \[\]string\{([^}]*)\}", GO_LEAF_REPORT.read_text())
    assert m, "backendleaves.go: no `var Services = []string{...}`"
    go = re.findall(r'"([^"]+)"', m.group(1))
    assert go, "parsed no services from backendleaves.Services"
    assert go == [r["service"] for r in _rust_rows()]
