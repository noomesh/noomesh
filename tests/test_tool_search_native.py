# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`noo_tool_search` is answered in process, and a failed call says where.

No gateway route serves `GET /api/tools/search`: the operator door answers
the tool from its own catalog (gateway-rust/src/mcp_local.rs), and the
standalone MCP server from this registry (`PaiToolSearch.run_local`), so
`dispatch` must never proxy it. A 404 with an empty body is a missing route,
and says so with the method and path only (never the query string or a
header value). The transport is mocked, not `dispatch`.
"""

from __future__ import annotations

import httpx
import pytest

from noomesh.mcp import tool_models
from noomesh.mcp.tool_defs.discovery import PaiToolSearch


def _transport(handler):
    sent = []

    def record(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return handler(request)

    return httpx.MockTransport(record), sent


@pytest.fixture
def client(monkeypatch):
    def install(handler):
        transport, sent = _transport(handler)
        monkeypatch.setattr(tool_models, "_http_client", httpx.AsyncClient(transport=transport))
        return sent

    return install


async def test_the_native_search_answers_from_the_registry_and_sends_nothing(client):
    sent = client(lambda r: httpx.Response(500))
    out = await tool_models.dispatch(PaiToolSearch(query="tool search", max_results=3))
    assert out.startswith("Matching tools ("), out
    assert out.splitlines()[2].strip() == "noo_tool_search", out  # header, blank, first hit
    assert not sent, f"a native tool was proxied: {[str(r.url) for r in sent]}"
    out = await tool_models.dispatch(PaiToolSearch(query="zzzqqq"))
    assert out == "No tools matched the query."


class _Probe(tool_models.ToolDef):
    """A GET tool on a path no gateway serves (test only; not registered)."""

    name = "rh_probe"
    description = "probe"
    method = tool_models.HttpMethod.GET
    path = "/api/rh/no-such-route"
    q: str = "secret-value"

    def get_params(self):
        return {"q": self.q}


async def test_an_empty_404_names_method_and_path_never_the_query(client):
    client(lambda r: httpx.Response(404, text=""))
    with pytest.raises(LookupError) as e:
        await tool_models.dispatch(_Probe())
    msg = str(e.value)
    assert msg == ("no route GET /api/rh/no-such-route on this gateway: the tool names a path "
                   "the gateway does not serve (a wiring defect)"), msg
    assert "secret-value" not in msg and "?" not in msg


async def test_a_404_with_a_body_is_the_routes_answer(client):
    client(lambda r: httpx.Response(404, json={"error": "no such message"}))
    with pytest.raises(LookupError) as e:
        await tool_models.dispatch(_Probe())
    msg = str(e.value)
    assert msg.startswith("Not found: GET /api/rh/no-such-route: ") and "no such message" in msg, msg
    assert "secret-value" not in msg
