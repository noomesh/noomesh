# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Callers of an operation-backed route must handle BOTH answers it can give.

A long route (recluster, extract-relations, consolidate, ingest, navigate,
traverse) starts an op and waits up to its `default_wait`: 200 with today's
result if the run finished in time, 202 with a handle `{op_id, poll, ...}` if
not. Gateway side: gateway-rust/src/routes/ops.rs. These are the Python
callers: the tool dispatcher (`mcp/tool_models.dispatch`, which serves the
coordinator's tools and the MCP server) and `noomesh.ops_client.settle`
(heartbeat ingest, the rag CLI).
"""
from __future__ import annotations

import httpx
import pytest

from noomesh import ops_client
from noomesh.mcp import tool_models
from noomesh.mcp.tool_defs import graph as g
from noomesh.mcp.tool_defs import ops as ops_defs

OP = "0f9c1d2e-0000-4000-8000-000000000001"
BASE = "https://gw.test"


def _handle(status="running"):
    return {"op_id": OP, "type": "graph.navigate", "status": status, "poll": f"/api/v1/ops/{OP}",
            "poll_interval_ms": 1000}


class Gateway:
    """A fake gateway: the route answers `route_reply`; polls answer `polls` in order."""

    def __init__(self, route_reply, polls=()):
        self.route_reply = route_reply
        self.polls = list(polls)
        self.calls = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, request.url.path, dict(request.url.params)))
        if request.url.path.startswith("/api/v1/ops/"):
            return httpx.Response(200, json=self.polls.pop(0))
        status, body = self.route_reply
        return httpx.Response(status, json=body)

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self), base_url=BASE)


# ── ops_client.settle ────────────────────────────────────────────────────────


async def test_a_200_result_passes_through_untouched():
    gw = Gateway((200, {"doc_id": "d1"}))
    async with gw.client() as c:
        r = await c.post("/api/v1/rag/ingest", json={})
        assert await ops_client.settle(c, r, BASE) is r
    assert len(gw.calls) == 1, "a finished route is not polled"


async def test_a_202_handle_is_followed_to_the_result_with_the_routes_status():
    gw = Gateway((202, _handle()), polls=[
        {"status": "running"},
        {"status": "succeeded", "result": {"doc_id": "d9"}, "result_status": 200},
    ])
    async with gw.client() as c:
        r = await c.post("/api/v1/rag/ingest", json={})
        s = await ops_client.settle(c, r, BASE, timeout=30)
    assert s.status_code == 200 and s.json() == {"doc_id": "d9"}
    polls = [p for p in gw.calls if p[1].startswith("/api/v1/ops/")]
    assert len(polls) == 2 and all(int(p[2]["wait"]) <= ops_client.POLL_WAIT_SECS for p in polls), polls


async def test_a_failed_op_keeps_the_status_the_synchronous_route_would_have_given():
    gw = Gateway((202, _handle()), polls=[
        {"status": "failed", "error": "question required", "result": {"error": "question required"}, "result_status": 400},
    ])
    async with gw.client() as c:
        r = await c.post("/x", json={})
        s = await ops_client.settle(c, r, BASE, timeout=30)
    assert s.status_code == 400 and s.json() == {"error": "question required"}


async def test_running_out_of_time_returns_the_unfinished_202_never_a_success():
    gw = Gateway((202, _handle()))
    async with gw.client() as c:
        r = await c.post("/x", json={})
        s = await ops_client.settle(c, r, BASE, timeout=0)
    assert s is r and s.status_code == 202, "'submitted' must never read as 'done'"
    assert not [p for p in gw.calls if p[1].startswith("/api/v1/ops/")], "no time, no polls"


async def test_cancelled_and_expired_are_not_success():
    for status, code in (("cancelled", 409), ("expired", 410)):
        gw = Gateway((202, _handle()), polls=[{"status": status}])
        async with gw.client() as c:
            r = await c.post("/x", json={})
            s = await ops_client.settle(c, r, BASE, timeout=30)
        assert s.status_code == code


def test_is_handle_needs_a_202_and_an_op_id():
    assert ops_client.is_handle(httpx.Response(202, json=_handle()))
    assert not ops_client.is_handle(httpx.Response(200, json=_handle()))
    assert not ops_client.is_handle(httpx.Response(202, json={"note": "accepted"}))
    assert not ops_client.is_handle(httpx.Response(202, text="not json"))


# ── the tool dispatcher ──────────────────────────────────────────────────────


@pytest.fixture
def dispatch_against(monkeypatch):
    def _install(gw: Gateway):
        client = gw.client()
        monkeypatch.setattr(tool_models, "_get_http_client", lambda: client)
        monkeypatch.setattr(tool_models, "GATEWAY_URL", BASE)
        monkeypatch.setattr(tool_models, "_auth_headers", lambda auth: {})
        return client
    return _install


async def test_dispatch_returns_a_finished_run_as_before(dispatch_against):
    gw = Gateway((200, {"seed_entities": [], "hypotheses": [], "candidate_page_ids": []}))
    dispatch_against(gw)
    out = await tool_models.dispatch(g.PaiGraphNavigate(query="q"))
    assert isinstance(out, str)
    assert len(gw.calls) == 1


async def test_dispatch_follows_a_202_handle_to_the_result_the_formatter_expects(dispatch_against):
    # The extract tool's formatter reads `edges_created`: without following the handle it would
    # have rendered the HANDLE as "Extracted 0 semantic edge(s)".
    gw = Gateway((202, _handle()), polls=[
        {"status": "running"},
        {"status": "succeeded", "result": {"edges_created": 4}, "result_status": 200},
    ])
    dispatch_against(gw)
    out = await tool_models.dispatch(g.PaiGraphExtractRelations(page_id="p"))
    assert "4 semantic edge" in out, out


async def test_dispatch_raises_the_exception_the_synchronous_status_implied(dispatch_against):
    gw = Gateway((202, _handle()), polls=[
        {"status": "failed", "error": "page_id required", "result": {"error": "page_id required"}, "result_status": 400},
    ])
    dispatch_against(gw)
    with pytest.raises(ValueError, match="page_id required"):
        await tool_models.dispatch(g.PaiGraphExtractRelations(page_id="p"))
    gw = Gateway((202, _handle()), polls=[{"status": "failed", "error": "boom", "result_status": 500}])
    dispatch_against(gw)
    with pytest.raises(RuntimeError, match="boom"):
        await tool_models.dispatch(g.PaiGraphExtractRelations(page_id="p"))


async def test_dispatch_out_of_time_names_the_op_so_it_can_be_picked_up(dispatch_against, monkeypatch):
    gw = Gateway((202, _handle()))
    dispatch_against(gw)
    monkeypatch.setattr(tool_models, "_TIMEOUT", 0.0)
    with pytest.raises(TimeoutError, match=OP):
        await tool_models.dispatch(g.PaiGraphExtractRelations(page_id="p"))


# ── the tool definitions ─────────────────────────────────────────────────────


def test_every_operation_backed_tool_tells_the_model_what_a_handle_is():
    from noomesh.mcp.tool_defs import rag, snapshots
    for cls in (g.PaiGraphNavigate, g.PaiGraphTraverseWithIntent, g.PaiGraphExtractRelations,
                g.PaiGraphRunClustering, snapshots.PaiConsolidateNow, rag.PaiRagIngest):
        assert "noo_op_status" in cls.description, f"{cls.name} must say what to do with a handle"
        assert "op_id" in cls.description


def test_op_tools_are_declared_for_the_user_door_and_route_to_the_ops_api():
    by = {c.name: c for c in (ops_defs.PaiOpStart, ops_defs.PaiOpStatus, ops_defs.PaiOpCancel, ops_defs.PaiOpList)}
    assert by["noo_op_start"].path == "/api/v1/ops"
    assert by["noo_op_status"].path == "/api/v1/ops/{op_id}"
    assert all("external" in c.tags for c in by.values()), "the user door serves only `external`-tagged tools"
    # `wait` is bounded at the schema, so a model cannot ask for an hour.
    schema = ops_defs.PaiOpStatus.model_json_schema()["properties"]["wait"]
    assert schema["anyOf"][0]["maximum"] == 25 if "anyOf" in schema else schema["maximum"] == 25
