# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The CLI's mirror of the gateway's heartbeat dispatch lists must match.

`noo heartbeat import` warns about tasks whose actions need the trellion-intel
add-on. It decides that with a copy of the gateway's RUST_NATIVE_ACTIONS and
RUST_LLM_ACTIONS (heartbeat_actions.rs `action_path`); a drift here would
warn about the wrong tasks — or none.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _list(text: str, name: str) -> set[str]:
    m = re.search(name + r"[^=]*=\s*&\[(.*?)\];", text, re.S)
    assert m, f"{name} not found"
    return set(re.findall(r'"([a-z_]+)"', m.group(1)))


def test_cli_mirror_matches_gateway_lists():
    gw = (ROOT / "gateway-rust" / "src" / "heartbeat_actions.rs").read_text()
    cli = (ROOT / "noo-cli" / "src" / "commands" / "heartbeat.rs").read_text()
    for name in ("RUST_NATIVE_ACTIONS", "RUST_LLM_ACTIONS"):
        assert _list(cli, name) == _list(gw, name), f"{name} drifted between noo-cli and the gateway"
