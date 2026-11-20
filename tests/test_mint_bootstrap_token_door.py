# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The MCP door's bootstrap-token answer carries the gateway's `run_on` and
`needs_human`: an agent on the door reads the same strings the CLI prints,
and an older gateway's body (neither field) reads as it always did.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from noomesh.mcp.tool_models import get_all_tools  # noqa: E402

BODY = {
    "node_name": "node_a",
    "expires_at": "2026-12-01T00:00:00Z",
    "install_command": "INSTALL",
    "enroll_command": "noo enroll noo1.BLOB",
    "provision_command": "noo cluster provision node_a --wait",
}
NEEDS = "the enroll command runs sudo; a person types the password unless that machine has passwordless sudo"


def _fmt(data: dict) -> str:
    return get_all_tools()["noo_mint_bootstrap_token"].model_construct().format_response(data)


def test_the_door_says_needs_human_and_run_on() -> None:
    out = _fmt({**BODY, "run_on": "the new machine, as its own user", "needs_human": NEEDS})
    assert "to run on the new machine, as its own user:" in out
    assert out.endswith(f"Needs a person: {NEEDS}")
    assert "1. INSTALL" in out and "2. noo enroll noo1.BLOB" in out


def test_an_older_gateway_body_reads_as_before() -> None:
    out = _fmt(BODY)
    assert "to run on that machine as their user:" in out
    assert "Needs a person" not in out
