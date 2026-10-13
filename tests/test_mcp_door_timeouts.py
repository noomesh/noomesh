# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A door tool must not give up before the route it calls does.

`gateway-rust/src/mcp_external.rs` self-calls the route with a reqwest timeout
of the manifest's `timeout_secs`. When that is shorter than the route's own
wait, the caller is told "gateway unreachable" about work that is still
running or already finished (graph recluster, 2026-10-04).

The long routes are now OPERATION-BACKED (`gateway-rust/src/ops.rs`,
`routes/ops.rs`): such a route starts an op and holds the request for at most
MAX_WAIT_SECS (25) before answering 202 with a handle. So for those the door
only has to outlast THAT bound, not the 900 s a recluster takes. A route that
is NOT op-backed still has to be outlasted in full.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROVIDER = ROOT / "gateway-rust/src/memory/provider.rs"
OPS = ROOT / "gateway-rust/src/ops.rs"
OPS_ROUTES = ROOT / "gateway-rust/src/routes/ops.rs"
MANIFESTS = ("gateway-rust/mcp-tools.json", "gateway-rust/mcp-tools-local.json")

#: Routes that wait on a worker for a long time. Each must be either
#: operation-backed (door >= MAX_WAIT_SECS + margin) or outlasted in full.
LONG_ROUTES = {
    "/api/v1/graph/recluster": 900,
    "/api/v1/graph/entity-cleanup": 600,
    "/api/v1/graph/navigate": 120,
    "/api/v1/graph/traverse": 120,
    "/api/v1/graph/extract-relations": 120,
    "/api/snapshots/consolidate": 120,
    "/api/v1/docs/ingest": 120,
    "/api/v1/rag/ingest": 120,
}
MARGIN = 10


def _max_wait() -> int:
    m = re.search(r"pub const MAX_WAIT_SECS: u64 = (\d+);", OPS.read_text())
    assert m, "MAX_WAIT_SECS not found in gateway-rust/src/ops.rs"
    return int(m.group(1))


def _recluster_timeout() -> int:
    m = re.search(r"const RECLUSTER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs\((\d+)\)",
                  PROVIDER.read_text())
    assert m, "RECLUSTER_TIMEOUT not found in memory/provider.rs"
    return int(m.group(1))


def _op_backed_routes() -> set:
    """Routes the registry in routes/ops.rs declares as the body of an op type."""
    return set(re.findall(r'route:\s*"([^"]+)"', OPS_ROUTES.read_text()))


def _tools():
    for rel in MANIFESTS:
        for t in json.loads((ROOT / rel).read_text())["tools"]:
            yield rel, t


def test_the_recluster_wait_in_this_test_is_the_providers():
    assert LONG_ROUTES["/api/v1/graph/recluster"] == _recluster_timeout()


def test_every_long_route_is_either_op_backed_or_outlasted_in_full():
    backed = _op_backed_routes()
    seen = set()
    for rel, t in _tools():
        wait = LONG_ROUTES.get(t["path"])
        if wait is None:
            continue
        seen.add(t["path"])
        if t["path"] in backed:
            need = _max_wait() + MARGIN
            why = f"op-backed: the route holds a request at most {_max_wait()}s"
        else:
            need = wait
            why = f"not op-backed: the route waits {wait}s"
        assert t["timeout_secs"] >= need, f"{rel}: {t['name']} door timeout {t['timeout_secs']}s < {need}s ({why})"
    # The manifests must actually contain the long tools, or this test guards nothing.
    assert {"/api/v1/graph/recluster", "/api/v1/graph/navigate", "/api/v1/graph/extract-relations",
            "/api/snapshots/consolidate", "/api/v1/graph/entity-cleanup"} <= seen


def test_the_long_routes_the_operator_named_are_op_backed():
    backed = _op_backed_routes()
    for route in ("/api/v1/graph/recluster", "/api/v1/graph/entity-cleanup", "/api/v1/graph/extract-relations", "/api/snapshots/consolidate",
                  "/api/v1/rag/ingest", "/api/v1/docs/ingest", "/api/v1/graph/navigate", "/api/v1/graph/traverse"):
        assert route in backed, f"{route} must be an operation-backed route (routes/ops.rs TYPES)"


def test_an_op_backed_door_does_not_wait_for_the_whole_run():
    """The door timeout is the bounded wait, not the run: a recluster tool that still carried 930 s would
    hold an MCP request open for fifteen minutes, which is the failure this design removes."""
    for rel, t in _tools():
        if t["path"] == "/api/v1/graph/recluster":
            assert t["timeout_secs"] < _recluster_timeout(), f"{rel}: {t['name']} still waits for the whole run"


def test_op_tools_are_in_both_doors_and_carry_the_poll_timeout():
    for rel in MANIFESTS:
        tools = {t["name"]: t for t in json.loads((ROOT / rel).read_text())["tools"]}
        for name in ("noo_op_start", "noo_op_status", "noo_op_cancel", "noo_op_list"):
            assert name in tools, f"{rel} lacks {name}"
        status = tools["noo_op_status"]
        assert status["path"] == "/api/v1/ops/{op_id}" and status["method"] == "GET"
        assert status["timeout_secs"] >= _max_wait() + MARGIN, "noo_op_status long-polls up to MAX_WAIT_SECS"
        assert tools["noo_op_start"]["path"] == "/api/v1/ops" and tools["noo_op_start"]["method"] == "POST"
        assert tools["noo_op_cancel"]["method"] == "DELETE"


def test_the_entity_cleanup_tool_is_on_the_operator_door_only():
    """A destructive, admin-only run: the user door serves the `external` subset (mcp-tools.json) and
    must never carry it; the operator door (mcp-tools-local.json) does, as a dry run by default."""
    user = {t["name"] for t in json.loads((ROOT / MANIFESTS[0]).read_text())["tools"]}
    operator = {t["name"]: t for t in json.loads((ROOT / MANIFESTS[1]).read_text())["tools"]}
    assert "noo_graph_entity_cleanup" not in user
    tool = operator["noo_graph_entity_cleanup"]
    assert tool["path"] == "/api/v1/graph/entity-cleanup" and tool["method"] == "POST"
    assert "external" not in tool["tags"] and "admin" in tool["tags"]
    assert tool["risk_level"] == "high"
    assert tool["input_schema"]["properties"]["apply"]["default"] is False, "dry run must be the default"
    assert "apply" not in tool["input_schema"].get("required", [])
    # and no user-door tool reaches the route: noo_op_start can name the type but the gateway refuses non-admins
    assert all(t["path"] != "/api/v1/graph/entity-cleanup"
               for t in json.loads((ROOT / MANIFESTS[0]).read_text())["tools"])


def test_the_entity_cleanup_tool_says_it_only_previews_and_makes_no_false_claim():
    tool = {t["name"]: t for t in json.loads((ROOT / MANIFESTS[1]).read_text())["tools"]}["noo_graph_entity_cleanup"]
    d = " ".join(tool["description"].split())
    assert "ONLY PREVIEWS" in d and "noo graph entity-cleanup --apply" in d and "refused" in d
    assert "operator key is refused" not in d
    assert "refused over MCP" in tool["input_schema"]["properties"]["apply"]["description"]
