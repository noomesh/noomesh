# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The range/discover/alerts tools reach the operator door and nothing else.

`noo_metrics_query`, `noo_metrics_range`, `noo_metrics_discover` and `noo_alerts_list` read the
whole installation's metrics and alert state. Like the log tools they are
absent from `/mcp/user` (not `external`-tagged, not in `mcp-tools.json`),
present in the operator manifest, read-only, and their gateway paths are in
`auth::METRICS_READ_PATHS`, which `scope_allows_for` refuses to anyone below
Operator (pinned by `metric_reads_are_operator_and_admin_only` in auth.rs).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from noomesh.mcp.tool_models import get_all_tools, get_external_tools  # noqa: E402

NEW = {
    "noo_metrics_query": "/api/metrics/query",
    "noo_metrics_range": "/api/metrics/range",
    "noo_metrics_discover": "/api/metrics/discover",
    "noo_alerts_list": "/api/alerts/list",
    # Request traces (i359): every account's routes, so operator door only
    # (auth::TRACES_READ_PREFIX refuses /api/traces/* below Operator).
    "noo_traces_summary": "/api/traces/summary",
    "noo_traces_requests": "/api/traces/requests",
}


def _manifest(name: str) -> dict:
    data = json.loads((ROOT / "gateway-rust" / name).read_text(encoding="utf-8"))
    tools = data["tools"] if isinstance(data, dict) else data
    return {t["name"]: t for t in tools}


def test_the_tools_exist_are_read_only_and_not_external() -> None:
    tools = get_all_tools()
    external = get_external_tools()
    for name, path in NEW.items():
        assert name in tools, f"{name} is gone — the parse found nothing"
        cls = tools[name]
        assert cls.path == path
        assert cls.method.value == "GET"
        assert cls.risk_level.value == "low"
        assert "external" not in cls.tags and "observability" in cls.tags
        assert name not in external, f"{name} is on the user door"


def test_the_manifests_agree_with_the_defs() -> None:
    user, operator = _manifest("mcp-tools.json"), _manifest("mcp-tools-local.json")
    for name, path in NEW.items():
        assert name not in user, f"{name} in the user-door manifest"
        assert name in operator, f"{name} missing from the operator manifest — run scripts/build-mcp-manifest.py"
        assert operator[name]["path"] == path
        assert operator[name]["method"].upper() == "GET"


def test_no_user_door_tool_proxies_these_paths() -> None:
    external = get_external_tools()
    leaked = sorted(n for n, c in external.items() if c.path in NEW.values())
    assert not leaked, leaked


def test_the_gateway_refuses_these_paths_below_operator() -> None:
    src = (ROOT / "gateway-rust" / "src" / "auth.rs").read_text(encoding="utf-8")
    m = re.search(r"pub const METRICS_READ_PATHS: &\[&str\] = &\[(.*?)\];", src, re.S)
    assert m, "METRICS_READ_PATHS not found — the parse found nothing"
    listed = set(re.findall(r'"([^"]+)"', m.group(1)))
    t = re.search(r'pub const TRACES_READ_PREFIX: &str = "([^"]+)";', src)
    assert t, "TRACES_READ_PREFIX not found — the parse found nothing"
    gated = {p for p in NEW.values() if p in listed or p.startswith(t.group(1))}
    assert set(NEW.values()) == gated, set(NEW.values()) - gated
    assert "path.starts_with(TRACES_READ_PREFIX)" in src, "the traces prefix is declared but not enforced"
    # And each is a real, GET-only route, in the file that serves it.
    routes = ROOT / "gateway-rust" / "src" / "routes"
    for path in NEW.values():
        text = (routes / ("traces.rs" if path.startswith(t.group(1)) else "admin.rs")).read_text(encoding="utf-8")
        assert re.search(rf'\.route\("{re.escape(path)}",\s*get\(', text), path
        assert not re.search(rf'\.route\("{re.escape(path)}",[^)]*post\(', text), path


def test_no_tool_field_is_a_raw_write() -> None:
    # Read-only means no silence/ack verbs sneak in as fields.
    for name in NEW:
        cls = get_all_tools()[name]
        fields = {cls._api_key(n, f) for n, f in cls.model_fields.items()}
        assert not fields & {"silence", "ack", "comment", "createdBy", "matchers"}, (name, fields)
