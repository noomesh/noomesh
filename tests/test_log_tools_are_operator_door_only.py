# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""No log tool reaches the user MCP door.

`/mcp/user` exposes only tools tagged `external` (`get_external_tools`). The
log tools (`noo_logs_tail`, `noo_logs_errors`, anything on `/api/logs/*`)
read the whole installation's output and must stay on the operator door —
the gateway refuses `/api/logs/*` to a User-tier token (`LOGS_READ_PREFIX`),
so an `external` tag here would only produce a tool that always 403s. Nothing
pinned this before 2026-09-28.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from noomesh.mcp.tool_models import get_all_tools, get_external_tools  # noqa: E402


def test_the_log_tools_exist_and_are_not_external() -> None:
    tools = get_all_tools()
    for name in ("noo_logs_tail", "noo_logs_errors", "noo_logs_search"):
        assert name in tools, f"{name} is gone — the parse found nothing"
    external = get_external_tools()
    leaked = sorted(n for n, cls in external.items() if cls.path.startswith("/api/logs/"))
    assert not leaked, f"log tools on the user door: {leaked}"
    assert "noo_logs_tail" not in external and "noo_logs_errors" not in external
    assert "noo_logs_search" not in external


def wire_keys(cls) -> set:
    # The key the gateway reads: `name` is declared `name_field` (alias) because
    # a field called `name` would shadow the tool's ClassVar.
    return {cls._api_key(n, f) for n, f in cls.model_fields.items()}


def test_the_search_tool_is_read_only_and_builds_no_logql_field() -> None:
    # Phase 5: the model fills typed fields; the gateway writes the LogQL.
    # A `query` field here would be the raw-LogQL door under a friendlier
    # name.
    tools = get_all_tools()
    search = tools["noo_logs_search"]
    assert search.path == "/api/logs/search"
    assert search.method.value == "POST"
    assert search.risk_level.value == "low"
    fields = wire_keys(search)
    assert {"text", "node", "name", "source", "level", "since", "until", "limit", "direction"} <= fields
    assert "query" not in fields
    for name in ("noo_logs_tail", "noo_logs_errors"):
        assert {"node", "name", "source", "since"} <= wire_keys(tools[name]), name
    # Every answer through these three says who answered.
    for name in ("noo_logs_tail", "noo_logs_errors", "noo_logs_search"):
        rendered = tools[name]().format_response({"backend": "agent-scan", "loki_error": "down"})
        assert "agent-scan" in rendered and "PARTIAL" in rendered, (name, rendered)
        rendered = tools[name]().format_response({"backend": "loki"})
        assert "loki" in rendered and "PARTIAL" not in rendered, (name, rendered)


def test_the_user_door_still_has_tools() -> None:
    # A door with nothing on it would pass the test above for the wrong reason.
    assert len(get_external_tools()) >= 10
