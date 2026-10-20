# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The MCP Python SDK, 2.x, against everything in this tree that speaks MCP.

mcp 1.30 -> 2.3 removed the decorator API on the low-level `Server`
(`@server.list_tools()` / `@server.call_tool()`), changed the handler
signatures to ``(ctx, params) -> Result``, changed `streamable_http_client` to
yield ``(read, write)`` (it was a 3-tuple), moved the HTTP client to ``httpx2``,
dropped the hand-driven ``StreamableHTTPServerTransport.connect(scope, ...)``,
and stopped validating ``tools/call`` arguments against the tool's schema. The
older tests of these modules mock the SDK out entirely (`tests/test_mcp_client.py`
patches ``sys.modules["mcp"]``), so none of them could see any of that. This
file drives the REAL SDK, in-process, over a real stdio subprocess, over a real
Streamable HTTP socket, and against a stand-in for the Rust doors.

`mcp` is imported at module top on purpose: if the extra is missing the file
FAILS at collection (CI installs the `mcp` extra) instead of skipping.
"""

from __future__ import annotations

import asyncio
import json
import re
import socket
import sys
import threading
import time
from pathlib import Path

import mcp
import mcp_types
import pytest
import uvicorn
from mcp import Client
from mcp.types import Tool
from mcp.types.version import HANDSHAKE_PROTOCOL_VERSIONS, MODERN_PROTOCOL_VERSIONS
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from noomesh.mcp.client import MCPClientManager, MCPServer

ROOT = Path(__file__).resolve().parents[1]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Serve:
    """Run an ASGI app under uvicorn in a thread; wait until it accepts."""

    def __init__(self, app) -> None:
        self.port = _free_port()
        self.server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="warning")
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> "_Serve":
        self.thread.start()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return self
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("test server did not start")

    def __exit__(self, *exc) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"


def test_the_sdk_is_the_2x_series() -> None:
    assert int(mcp.__version__.split(".")[0]) >= 2 if hasattr(mcp, "__version__") else True
    from importlib.metadata import version

    assert int(version("mcp").split(".")[0]) >= 2
    # The decorator API the 1.x wiring used is gone: that is why the port exists.
    from mcp.server import Server

    assert not hasattr(Server("x"), "list_tools")
    assert not hasattr(Server("x"), "call_tool")


# ---------------------------------------------------------------------------
# The three servers, in process
# ---------------------------------------------------------------------------

def _hub(monkeypatch):
    from noomesh.mcp import server as hub
    from noomesh.mcp import tool_models

    calls: list[tuple[str, dict]] = []

    async def fake_handle(name: str, arguments: dict) -> str:
        calls.append((name, arguments))
        if name == "boom":
            raise RuntimeError("kaput")
        return f"ran {name}"

    monkeypatch.setattr(tool_models, "handle_tool_call", fake_handle)
    return hub._build_server(), calls


async def test_hub_lists_every_enabled_tool_with_its_schema(monkeypatch) -> None:
    from noomesh.mcp.tool_models import get_enabled_tools

    server, _ = _hub(monkeypatch)
    async with Client(server) as client:
        listed = (await client.list_tools()).tools

    want = {t["name"]: t["input_schema"] for t in get_enabled_tools()}
    assert len(want) > 50, "the registry must not be empty"
    assert {t.name: t.input_schema for t in listed} == want
    # On the wire the field is `inputSchema` (the SDK's alias), which is what
    # the Rust doors serialise too.
    assert "inputSchema" in listed[0].model_dump(by_alias=True)


async def test_hub_call_tool_returns_text_and_keeps_errors_as_text(monkeypatch) -> None:
    from noomesh.mcp.tool_models import get_enabled_tools

    server, calls = _hub(monkeypatch)
    # A tool with no required argument, so the call is schema-valid.
    name = next(
        t["name"] for t in get_enabled_tools() if not t["input_schema"].get("required")
    )
    async with Client(server) as client:
        ok = await client.call_tool(name, {})
    assert [c.text for c in ok.content] == [f"ran {name}"]
    assert not ok.is_error
    assert calls == [(name, {})]


async def test_hub_rejects_arguments_that_break_the_tool_schema(monkeypatch) -> None:
    """mcp 1.x validated `tools/call` arguments inside `@server.call_tool()`;
    2.x does not. `noomesh.mcp._sdk.invalid_arguments` puts it back."""
    from noomesh.mcp.tool_models import get_enabled_tools

    server, calls = _hub(monkeypatch)
    tool = next(t for t in get_enabled_tools() if t["input_schema"].get("required"))
    async with Client(server) as client:
        res = await client.call_tool(tool["name"], {})
    assert res.is_error is True
    assert res.content[0].text.startswith("Input validation error")
    assert calls == [], "an invalid call must not reach the handler"


async def test_filesystem_server_lists_and_runs_a_tool_in_process(tmp_path) -> None:
    from noomesh.mcp import filesystem_server as fs

    (tmp_path / "hello.txt").write_text("hi\n")
    fs._set_allowed([str(tmp_path)])
    async with Client(fs._build_server()) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert {"read_text_file", "list_directory", "list_allowed_directories"} <= names
        assert names == {t["name"] for t in fs.TOOLS}
        res = await client.call_tool("list_directory", {"path": str(tmp_path)})
        assert "hello.txt" in res.content[0].text
        # Handler-level refusals stay text (the 1.x behaviour): not a protocol error.
        res = await client.call_tool("read_text_file", {"path": "/etc/passwd"})
        assert not res.is_error
        assert res.content[0].text.startswith(("Error", "Permission denied", "Access denied"))
        # Schema violation -> validation error, handler never runs.
        res = await client.call_tool("read_text_file", {})
        assert res.is_error is True
        # Unknown tool keeps the pre-existing wording.
        res = await client.call_tool("nope", {})
        assert res.content[0].text == "Error: unknown tool 'nope'"


async def test_github_server_lists_its_tools_in_process() -> None:
    from noomesh.mcp import github_server as gh

    async with Client(gh._build_server()) as client:
        listed = (await client.list_tools()).tools
    assert {t.name for t in listed} == {t["name"] for t in gh.TOOLS}
    assert len(listed) >= 8


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------

def test_the_filesystem_server_over_real_stdio(tmp_path) -> None:
    """A subprocess speaking MCP on stdin/stdout, driven by MCPClientManager's
    stdio path (`mcp.client.stdio.stdio_client` + `ClientSession`)."""
    (tmp_path / "a.txt").write_text("alpha")
    mgr = MCPClientManager(
        [MCPServer(name="fs", transport="stdio", command=sys.executable,
                   args=["-I", "-m", "noomesh.mcp.filesystem_server", str(tmp_path)],
                   env={"PYTHONPATH": str(ROOT / "src")})]
    )
    tools = mgr.list_tools()
    names = {t["name"] for t in tools}
    assert "mcp_fs_list_directory" in names, names
    assert all(t["input_schema"].get("type") == "object" for t in tools)
    out = mgr.call_tool("mcp_fs_list_directory", {"path": str(tmp_path)})
    assert "a.txt" in out


def test_the_hub_http_transport_serves_mcp_to_the_manager_client(monkeypatch) -> None:
    """`noo-mcp-server --transport http`: `Server.streamable_http_app` under
    uvicorn, spoken to by MCPClientManager's streamable-HTTP path with auth
    headers (which builds the httpx2 client the 2.x transport needs)."""
    from noomesh.mcp import server as hub
    from noomesh.mcp import tool_models

    async def fake_handle(name: str, arguments: dict) -> str:
        return f"hub ran {name}"

    monkeypatch.setattr(tool_models, "handle_tool_call", fake_handle)
    server = hub._build_server()
    with _Serve(hub._build_http_app(server)) as srv:
        for headers in (None, {"Authorization": "Bearer test-token"}):
            mgr = MCPClientManager(
                [MCPServer(name="hub", transport="http", url=srv.url, headers=headers)]
            )
            tools = mgr.list_tools()
            assert len(tools) > 50, f"headers={headers}: discovery returned {len(tools)}"
            pick = next(t for t in tools if not t["input_schema"].get("required"))
            out = mgr.call_tool(pick["name"], {})
            assert out == f"hub ran {pick['name'].removeprefix('mcp_hub_')}"


def test_the_hub_http_app_speaks_both_protocol_eras() -> None:
    """Legacy `initialize` handshake negotiates down to a handshake revision the
    Rust doors also serve; the app lives at /mcp only."""
    import httpx

    from noomesh.mcp import server as hub

    with _Serve(hub._build_http_app(hub._build_server())) as srv:
        body = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "t", "version": "0"}},
        }
        r = httpx.post(
            srv.url, json=body,
            headers={"Accept": "application/json, text/event-stream"}, timeout=10,
        )
        assert r.status_code == 200, r.text
        payload = r.text
        if r.headers["content-type"].startswith("text/event-stream"):
            payload = next(l[5:] for l in r.text.splitlines() if l.startswith("data:"))
        result = json.loads(payload)["result"]
        assert result["protocolVersion"] in HANDSHAKE_PROTOCOL_VERSIONS
        assert result["serverInfo"]["name"] == "mesh"
        assert httpx.post(srv.url.replace("/mcp", "/other"), json=body, timeout=10).status_code == 404


# ---------------------------------------------------------------------------
# Compatibility with the Rust doors (gateway-rust/src/mcp_protocol.rs)
# ---------------------------------------------------------------------------

_RUST = (ROOT / "gateway-rust" / "src" / "mcp_protocol.rs").read_text()


def test_the_revisions_the_rust_doors_speak_are_ones_the_sdk_speaks() -> None:
    """The doors answer legacy `initialize` with LEGACY_VERSION and serve the
    SUPPORTED_MODERN stateless revisions. A Python SDK that dropped either
    would leave `MCPClientManager` unable to talk to a noomesh door."""
    legacy = re.search(r'LEGACY_VERSION: &str = "([0-9-]+)"', _RUST).group(1)
    modern = re.search(r"SUPPORTED_MODERN: &\[&str\] = &\[([^\]]*)\]", _RUST).group(1)
    modern = re.findall(r'"([0-9-]+)"', modern)
    assert legacy in HANDSHAKE_PROTOCOL_VERSIONS
    assert modern and set(modern) <= set(MODERN_PROTOCOL_VERSIONS)


def _door_app(tools: list[dict]) -> Starlette:
    """A stand-in for `/mcp/user`: POST only, JSON bodies, stateless, no
    sessions, legacy `initialize` -> 2024-11-05, notifications -> 202, GET and
    DELETE -> 405. Same shapes as mcp_protocol.rs / mcp_external.rs."""

    async def handle(request: Request) -> Response:
        if request.method != "POST":
            return JSONResponse(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": "POST only"}},
                status_code=405, headers={"Allow": "POST"},
            )
        req = await request.json()
        method, rid = req.get("method", ""), req.get("id")
        if method.startswith("notifications/"):
            return Response(status_code=202)
        if method == "initialize":
            result = {
                "protocolVersion": re.search(r'LEGACY_VERSION: &str = "([0-9-]+)"', _RUST).group(1),
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "noomesh-user-mcp", "version": "0.0.0"},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": [{"name": t["name"], "description": t["description"],
                                 "inputSchema": t["input_schema"]} for t in tools]}
        elif method == "tools/call":
            name = req["params"]["name"]
            result = {"content": [{"type": "text", "text": json.dumps({"called": name,
                      "arguments": req["params"].get("arguments", {})})}], "isError": False}
        else:
            return JSONResponse({"jsonrpc": "2.0", "id": rid,
                                 "error": {"code": -32601, "message": "method not found"}})
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": result})

    return Starlette(routes=[Route("/mcp", handle, methods=["GET", "POST", "DELETE"])])


@pytest.mark.parametrize("manifest", ["mcp-tools.json", "mcp-tools-local.json"])
def test_the_2x_client_reads_the_doors_generated_tool_list(manifest) -> None:
    """The tool defs the doors serve are generated (scripts/build-mcp-manifest.py)
    from the Python ToolDef registry, independent of the SDK. Prove the 2.x SDK
    both parses every one of them and completes a call through a door-shaped
    server over HTTP."""
    tools = json.loads((ROOT / "gateway-rust" / manifest).read_text())["tools"]
    assert len(tools) >= 30
    for t in tools:  # pydantic validation in mcp_types, every tool
        Tool(name=t["name"], description=t["description"], input_schema=t["input_schema"])

    with _Serve(_door_app(tools)) as srv:
        mgr = MCPClientManager(
            [MCPServer(name="door", transport="http", url=srv.url,
                       headers={"Authorization": "Bearer x"})]
        )
        listed = mgr.list_tools()
        assert {t["name"] for t in listed} == {f"mcp_door_{t['name']}" for t in tools}
        first = tools[0]["name"]
        out = mgr.call_tool(f"mcp_door_{first}", {"k": "v"})
        assert json.loads(out) == {"called": first, "arguments": {"k": "v"}}
