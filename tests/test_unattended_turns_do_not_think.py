# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Unattended turns run with the model's reasoning block off.

Found 2026-09-27: weekly_research came back as reasoning-plus-answer — on
gemma-4 the reasoning arrives as plain text with a bare `thought` prefix,
and only the STREAMING path turns that into a virtual <think>. The quality
gate then rejected the report as a stub, and the operator received nothing.
The MCP door's agentic tool (POST /api/inference, non-streaming) leaked the
same `thought` text inline.

`coordinator::run` hard-wires enable_thinking=true. The unattended callers —
every heartbeat LLM action and the non-streaming inference route — must go
through `run_with_thinking(…, false)`. This reads the source, because the
regression is one identifier: `run(` where `run_with_thinking(` belongs.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
UNATTENDED = [
    REPO / "gateway-rust" / "src" / "heartbeat_actions.rs",
    REPO / "gateway-rust" / "src" / "routes" / "inference.rs",
]


def _non_test_source(path: Path) -> str:
    text = path.read_text()
    cut = text.find("#[cfg(test)]")
    return text if cut < 0 else text[:cut]


def test_unattended_callers_never_use_bare_coordinator_run() -> None:
    bare = re.compile(r"coordinator::run\(")
    for path in UNATTENDED:
        src = _non_test_source(path)
        hits = [m.start() for m in bare.finditer(src)]
        assert not hits, (
            f"{path.relative_to(REPO)} calls bare coordinator::run( at offsets {hits}; "
            "unattended turns must use run_with_thinking(…, false) — see the module docstring"
        )


def test_the_guard_found_the_callers_it_governs() -> None:
    """A guard over a file that stopped containing the call would pass by
    absence. Both files must still call run_with_thinking with `false`."""
    for path in UNATTENDED:
        src = _non_test_source(path)
        assert "run_with_thinking(" in src, f"{path.name}: the unattended call moved — update the guard"
        assert re.search(r"run_with_thinking\([^;]*?\bfalse,?\s*\)", src, re.S), (
            f"{path.name}: run_with_thinking is called, but not with enable_thinking = false"
        )
