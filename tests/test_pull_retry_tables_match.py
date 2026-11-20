# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The ollama pull-failure classifier exists twice: noo-cli (Rust, the
onboard First Model step and `noo models pull`) and the node agent (Go, a
node's first placement). They must say the same thing about the same
failure, so the marker tables, the status rules and the retry bounds are
held equal here. A marker added to one side only would retry on a
laptop and fail at once on a node (or the reverse)."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RUST = (REPO / "noo-cli/src/commands/pull_retry.rs").read_text()
GO = (REPO / "node-agent-go/internal/reconcile/pull_retry.go").read_text()


def rust_strs(name: str) -> list[str]:
    m = re.search(rf"const {name}: \[&str; (\d+)\] = \[(.*?)\];", RUST, re.S)
    assert m, name
    items = re.findall(r'"([^"]*)"', m.group(2))
    assert len(items) == int(m.group(1)), name
    return items


def go_strs(name: str) -> list[str]:
    m = re.search(rf"var {name} = \[\]string\{{(.*?)\n\}}", GO, re.S)
    assert m, name
    return re.findall(r'"([^"]*)"', m.group(1))


def test_permanent_markers_match_in_order():
    assert go_strs("pullPermanentMarkers") == rust_strs("PERMANENT")


def test_network_markers_match_in_order():
    assert go_strs("pullNetworkMarkers") == rust_strs("NETWORK")


def test_permanent_statuses_match():
    r = re.search(r"Some\(([\d |]+)\) => return None", RUST)
    g = re.search(r"var pullPermanentStatuses = \[\]int\{([^}]*)\}", GO)
    assert r and g
    assert [int(x) for x in g.group(1).split(",")] == [int(x) for x in r.group(1).split("|")]


def test_5xx_range_matches():
    assert "500..=599" in RUST
    assert "status >= 500 && status <= 599" in GO


def test_retry_bounds_match():
    tries = int(re.search(r"pub const TRIES: usize = (\d+);", RUST).group(1))
    delays = re.search(r"pub const DELAYS_SECS: \[u64; \d+\] = \[([\d, ]+)\];", RUST).group(1)
    cap = int(re.search(r"pub const MAX_TOTAL_WAIT_SECS: u64 = (\d+);", RUST).group(1))
    assert tries == int(re.search(r"const pullTries = (\d+)", GO).group(1))
    assert [int(x) for x in delays.split(",")] == [
        int(x) for x in re.search(r"var pullDelaysSecs = \[\]int\{([^}]*)\}", GO).group(1).split(",")
    ]
    assert cap == int(re.search(r"const pullMaxTotalWaitSecs = (\d+)", GO).group(1))
