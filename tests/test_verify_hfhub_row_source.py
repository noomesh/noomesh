# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The `hf-cache hub owner` verify row judges the self-node AGENT's HF cache.

0.6.26 on ctrl: the row stat'ed the CLI's own HF_CACHE_DIR (the controller
compose's cache, an operator-owned NFS dir there), not the directory the
self-node agent stages into, and promised an applier repair the applier
never makes. Pinned here without a Rust build: `live` takes the agent's
cache from the fleet (the self node's heartbeat) or the agent's env file,
the call site hands it the fleet, the compose cache gets its own row, and
the applier claim is only under hf_hub_reown's own condition (hub uid 0,
hf-cache owned by noo-agent).
"""
from __future__ import annotations

from pathlib import Path

from tests import _rust_src as rs

ROOT = Path(__file__).resolve().parent.parent
HF_HUB = ROOT / "noo-cli/src/commands/cluster_verify/hf_hub.rs"
VERIFY = ROOT / "noo-cli/src/commands/cluster_verify.rs"


def test_live_judges_the_agents_cache_and_never_the_cli_env_as_it() -> None:
    code = rs.own_code(HF_HUB.read_text())
    live = rs.fn_body(code, "pub(crate) fn live(")
    assert "agent_cache(fleet" in live, live
    assert 'var("HF_CACHE_DIR")' not in live, live
    assert "controller_row(&ctl" in live, live
    src = rs.fn_body(code, "pub(crate) fn agent_cache(")
    assert '"/etc/noo-node-agent.env"' in code and "AGENT_ENV" in src
    assert 'self_node"].as_bool() == Some(true)' in src, src
    assert 'hf_cache_dir"' in src, src


def test_the_applier_claim_needs_a_root_hub_under_the_agents_cache() -> None:
    judge = rs.fn_body(rs.own_code(HF_HUB.read_text()), "fn judge(")
    claim = "re-owns it at its next apply"
    assert judge.count(claim) == 1, judge
    before = judge[: judge.index(claim)]
    arm = before[before.rindex("Hub::Dir(h) if") :]
    assert "h.0 == 0" in arm and "Some((Some(au), true)) if au == c.0" in arm, arm
    ctl = rs.fn_body(rs.own_code(HF_HUB.read_text()), "pub(crate) fn controller_row(")
    assert ", None)" in ctl, ctl


def test_the_call_site_hands_the_fleet_to_the_row() -> None:
    body = rs.fn_body(rs.own_code(VERIFY.read_text()), "pub fn cluster_verify(")
    assert "hf_hub::live(Some(&Value::Array(fleet.clone())))" in body, "the row is given the fleet"
    assert "hf_hub::live()" not in body
