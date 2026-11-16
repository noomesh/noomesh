# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The MCP log tools read the gateway's "off by choice" answers as such.

On an install with `cluster.monitoring: lean` and no Loki, POST /api/logs/search
answers 200 `{"lines": [], "backend": "off", "message": ...}` and the scans carry
`loki_off: true`. The model must read the gateway's line (naming
`noo stack monitoring on`), never "no matching lines" or "Loki not reachable".
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from noomesh.mcp.tool_models import get_all_tools  # noqa: E402

LINE = "Log search is off on this install. Turn it on: noo stack monitoring on"


def _fmt(tool: str, data: dict) -> str:
    cls = get_all_tools()[tool]
    return cls.model_construct().format_response(data)


def test_search_off_is_the_gateways_line() -> None:
    out = _fmt("noo_logs_search", {"lines": [], "backend": "off", "message": LINE})
    assert out == LINE
    assert "no matching lines" not in _fmt("noo_logs_search", {"backend": "off"})


def test_a_scan_because_loki_is_off_names_the_command() -> None:
    off = {"matches": [], "window_minutes": 15, "backend": "agent-scan",
           "loki_error": "log search is off by choice: noo stack monitoring on", "loki_off": True}
    out = _fmt("noo_logs_errors", off)
    assert "log search is off by choice: noo stack monitoring on" in out
    down = dict(off, loki_off=False, loki_error="Loki unreachable: refused")
    assert "Loki unreachable: refused" in _fmt("noo_logs_errors", down)
