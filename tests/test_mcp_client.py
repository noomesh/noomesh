# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Unit tests for MCP client manager."""
from __future__ import annotations

import asyncio
from dataclasses import fields
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from noomesh.mcp.client import MCPClientManager, MCPServer


# ---------------------------------------------------------------------------
# MCPServer dataclass
# ---------------------------------------------------------------------------

class TestMCPServerDataclass:
    def test_defaults(self):
        s = MCPServer(name="test")
        assert s.transport == "stdio"
        assert s.args is None
        assert s.url is None
        assert s.env is None

    def test_all_fields(self):
        s = MCPServer(
            name="fs",
            transport="http",
            command="/bin/srv",
            args=["--flag"],
            url="http://localhost:9000",
            env={"KEY": "VAL"},
        )
        assert s.name == "fs"
        assert s.transport == "http"
        assert s.env == {"KEY": "VAL"}

    def test_env_field_exists(self):
        field_names = [f.name for f in fields(MCPServer)]
        assert "env" in field_names


# ---------------------------------------------------------------------------
# Tool name formatting — parametrized spec table
# ---------------------------------------------------------------------------

_FORMAT_SPEC = [
    ("simple", "fs", "read_file", "mcp", "mcp_fs_read_file"),
    ("with_dashes", "my-srv", "do-thing", "mcp", "mcp_my_srv_do_thing"),
    ("dots_in_name", "v1.0", "tool.run", "mcp", "mcp_v1_0_tool_run"),
    ("spaces", "my srv", "my tool", "mcp", "mcp_my_srv_my_tool"),
    ("custom_prefix", "fs", "read", "custom", "custom_fs_read"),
    ("none_tool_name", "fs", None, "mcp", "mcp_fs_tool"),
]


@pytest.mark.parametrize(
    "label, server_name, tool_name, prefix, expected",
    _FORMAT_SPEC,
    ids=[s[0] for s in _FORMAT_SPEC],
)
def test_format_tool_name(label, server_name, tool_name, prefix, expected):
    mgr = MCPClientManager([], tool_prefix=prefix)
    assert mgr._format_tool_name(server_name, tool_name) == expected


# ---------------------------------------------------------------------------
# Result rendering — parametrized spec table
# ---------------------------------------------------------------------------

def _obj(**kw):
    return SimpleNamespace(**kw)


_RENDER_SPEC: List = [
    ("text_content_obj", _obj(content=[_obj(text="hello")], structuredContent=None), "hello"),
    ("data_content_obj", _obj(content=[_obj(data="binary")], structuredContent=None), "binary"),
    ("text_content_dict", {"content": [{"text": "hello"}]}, "hello"),
    ("data_content_dict", {"content": [{"data": "raw"}]}, "raw"),
    ("structured_only", _obj(content=None, structuredContent={"k": "v"}), "{'k': 'v'}"),
    ("multi_content", _obj(content=[_obj(text="a"), _obj(text="b")], structuredContent=None), "a\nb"),
    ("empty_result", _obj(content=None, structuredContent=None), "(no output)"),
    ("empty_content_list", _obj(content=[], structuredContent=None), "(no output)"),
]


@pytest.mark.parametrize(
    "label, result, expected",
    _RENDER_SPEC,
    ids=[s[0] for s in _RENDER_SPEC],
)
def test_render_tool_result(label, result, expected):
    mgr = MCPClientManager([])
    assert mgr._render_tool_result(result) == expected


# ---------------------------------------------------------------------------
# Helper: mock session factory
# ---------------------------------------------------------------------------

def _make_mock_session(tools: List[Dict[str, Any]] | None = None):
    """Return a mock ClientSession with list_tools and call_tool."""
    session = AsyncMock()
    if tools is not None:
        result = MagicMock()
        result.tools = tools
        session.list_tools.return_value = result
    session.initialize = AsyncMock()
    return session


def _patch_stdio(session):
    """Return patches for stdio_client and ClientSession that yield `session`."""

    class _StdioCtx:
        async def __aenter__(self):
            return ("read", "write")
        async def __aexit__(self, *a):
            pass

    class _SessionCtx:
        def __init__(self, *a, **kw):
            pass
        async def __aenter__(self):
            return session
        async def __aexit__(self, *a):
            pass

    return {
        "noomesh.mcp.client.StdioServerParameters": MagicMock(),
        "noomesh.mcp.client.stdio_client": MagicMock(return_value=_StdioCtx()),
        "noomesh.mcp.client.ClientSession": _SessionCtx,
    }


def _apply_session_patches(session):
    """Patch the imports inside _with_session to use our mock session."""

    original_with_session = MCPClientManager._with_session

    async def _patched_with_session(self, server, fn):
        # Bypass the real import + context manager, just call fn(session)
        return await fn(session)

    return patch.object(MCPClientManager, "_with_session", _patched_with_session)


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

class TestToolDiscovery:
    def test_discover_tools_creates_toolspecs(self):
        session = _make_mock_session(tools=[
            {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}},
            {"name": "write_file", "description": "Write a file", "inputSchema": {"type": "object"}},
        ])
        server = MCPServer(name="fs", command="srv")

        with _apply_session_patches(session):
            mgr = MCPClientManager([server])
            tools = asyncio.run(mgr._discover_tools())

        assert len(tools) == 2
        assert tools[0].name == "mcp_fs_read_file"
        assert tools[1].name == "mcp_fs_write_file"
        assert "mcp_fs_read_file" in mgr._tool_map
        assert "mcp_fs_write_file" in mgr._tool_map

    def test_discover_tools_skips_empty_names(self):
        session = _make_mock_session(tools=[
            {"name": "", "description": "bad"},
            {"name": None, "description": "also bad"},
            {"name": "good", "description": "ok"},
        ])
        server = MCPServer(name="s", command="x")

        with _apply_session_patches(session):
            mgr = MCPClientManager([server])
            tools = asyncio.run(mgr._discover_tools())

        assert len(tools) == 1
        assert tools[0].name == "mcp_s_good"

    def test_discover_tools_meta(self):
        session = _make_mock_session(tools=[
            {"name": "tool1", "description": "desc1"},
        ])
        server = MCPServer(name="x", command="cmd")

        with _apply_session_patches(session):
            mgr = MCPClientManager([server])
            metas = asyncio.run(mgr._discover_tools_meta())

        assert metas == [{"name": "mcp_x_tool1", "description": "desc1", "input_schema": {"type": "object", "properties": {}}}]

    def test_list_server_tools_normalizes_objects(self):
        tool_obj = SimpleNamespace(name="obj_tool", description="from obj", inputSchema={"type": "object"})
        session = _make_mock_session()
        result = MagicMock()
        result.tools = [tool_obj]
        session.list_tools.return_value = result

        server = MCPServer(name="o", command="cmd")
        with _apply_session_patches(session):
            mgr = MCPClientManager([server])
            items = asyncio.run(mgr._list_server_tools(server))

        assert len(items) == 1
        assert items[0]["name"] == "obj_tool"
        assert items[0]["input_schema"] == {"type": "object"}

    def test_empty_servers_returns_empty(self):
        mgr = MCPClientManager([])
        # attach_tools with empty servers is a no-op
        registry = MagicMock()
        mgr.attach_tools(registry)
        registry.register.assert_not_called()

        # list_tools returns empty
        assert mgr.list_tools() == []


# ---------------------------------------------------------------------------
# Tool calling
# ---------------------------------------------------------------------------

class TestToolCalling:
    def test_call_tool_routes_correctly(self):
        session = _make_mock_session(tools=[
            {"name": "read", "description": "r"},
        ])
        call_result = _obj(content=[_obj(text="file content")], structuredContent=None)
        session.call_tool.return_value = call_result

        server = MCPServer(name="fs", command="cmd")
        with _apply_session_patches(session):
            mgr = MCPClientManager([server])
            asyncio.run(mgr._discover_tools())
            result = mgr.call_tool("mcp_fs_read", {"path": "/tmp/x"})

        assert result == "file content"
        session.call_tool.assert_called_once_with("read", arguments={"path": "/tmp/x"})

    def test_call_tool_unknown_name(self):
        mgr = MCPClientManager([])
        result = mgr.call_tool("nonexistent", {})
        assert "Error: unknown MCP tool" in result

    def test_call_tool_async_invokes_session(self):
        session = _make_mock_session()
        call_result = _obj(content=[_obj(text="ok")], structuredContent=None)
        session.call_tool.return_value = call_result

        server = MCPServer(name="s", command="c")
        with _apply_session_patches(session):
            mgr = MCPClientManager([server])
            result = asyncio.run(mgr._call_tool_async(server, "my_tool", {"a": 1}))

        assert result == "ok"
        session.call_tool.assert_called_once_with("my_tool", arguments={"a": 1})

    def test_handler_lambda_captures_tool_name(self):
        """Verify the handler lambda in ToolSpec calls call_tool with the right name."""
        session = _make_mock_session(tools=[
            {"name": "t1", "description": "d1"},
            {"name": "t2", "description": "d2"},
        ])
        call_result = _obj(content=[_obj(text="result")], structuredContent=None)
        session.call_tool.return_value = call_result

        server = MCPServer(name="s", command="c")
        with _apply_session_patches(session):
            mgr = MCPClientManager([server])
            tools = asyncio.run(mgr._discover_tools())

            # Call each handler and verify routing
            for tool in tools:
                tool.handler({"arg": "val"})

        # Should have been called twice, once for each tool
        assert session.call_tool.call_count == 2
        calls = [c.args[0] for c in session.call_tool.call_args_list]
        assert "t1" in calls
        assert "t2" in calls


# ---------------------------------------------------------------------------
# attach_tools + list_tools
# ---------------------------------------------------------------------------

class TestAttachAndListTools:
    def test_attach_tools_registers_on_registry(self):
        session = _make_mock_session(tools=[
            {"name": "tool_a", "description": "A"},
            {"name": "tool_b", "description": "B"},
        ])
        server = MCPServer(name="x", command="cmd")
        registry = MagicMock()

        with _apply_session_patches(session):
            mgr = MCPClientManager([server])
            mgr.attach_tools(registry)

        assert registry.register.call_count == 2

    def test_attach_tools_handles_discovery_failure(self):
        """If discovery fails, attach_tools should not crash."""
        server = MCPServer(name="bad", command="nonexistent")
        registry = MagicMock()

        with patch.object(MCPClientManager, "_run_async", side_effect=RuntimeError("boom")):
            mgr = MCPClientManager([server])
            mgr.attach_tools(registry)  # should not raise

        registry.register.assert_not_called()

    def test_list_tools_returns_metadata(self):
        session = _make_mock_session(tools=[
            {"name": "t", "description": "desc"},
        ])
        server = MCPServer(name="s", command="c")

        with _apply_session_patches(session):
            mgr = MCPClientManager([server])
            metas = mgr.list_tools()

        assert len(metas) == 1
        assert metas[0]["name"] == "mcp_s_t"


# ---------------------------------------------------------------------------
# _run_async
# ---------------------------------------------------------------------------

class TestRunAsync:
    def test_run_async_no_loop(self):
        """Runs coroutine via asyncio.run when no event loop exists."""
        async def coro():
            return 42

        result = MCPClientManager._run_async(coro())
        assert result == 42

    def test_run_async_inside_running_loop(self):
        """Runs coroutine in a thread when called from within an event loop."""
        async def inner():
            return 99

        async def outer():
            return MCPClientManager._run_async(inner())

        result = asyncio.run(outer())
        assert result == 99


# ---------------------------------------------------------------------------
# env field wiring
# ---------------------------------------------------------------------------

class TestEnvFieldWiring:
    def test_env_passed_to_stdio_params(self):
        """Verify that server.env is passed through to StdioServerParameters."""
        server = MCPServer(name="fs", command="srv", env={"MY_KEY": "val"})
        mgr = MCPClientManager([server])

        captured_params = {}

        async def fake_fn(session):
            return "ok"

        # We need to patch the imports that happen inside _with_session
        mock_params_cls = MagicMock()
        mock_params_cls.return_value = "params_obj"

        class _FakeStdioCtx:
            async def __aenter__(self):
                return ("r", "w")
            async def __aexit__(self, *a):
                pass

        mock_stdio = MagicMock(return_value=_FakeStdioCtx())

        mock_session = AsyncMock()
        mock_session.initialize = AsyncMock()

        class _FakeSessionCtx:
            def __init__(self, *a, **kw):
                pass
            async def __aenter__(self):
                return mock_session
            async def __aexit__(self, *a):
                pass

        with patch.dict("sys.modules", {
            "mcp": MagicMock(
                ClientSession=_FakeSessionCtx,
                StdioServerParameters=mock_params_cls,
            ),
            "mcp.client": MagicMock(),
            "mcp.client.stdio": MagicMock(stdio_client=mock_stdio),
            "mcp.client.streamable_http": MagicMock(),
        }):
            result = asyncio.run(mgr._with_session(server, fake_fn))

        # Check StdioServerParameters was called with env
        mock_params_cls.assert_called_once()
        call_kwargs = mock_params_cls.call_args
        assert call_kwargs.kwargs.get("env") == {"MY_KEY": "val"} or \
               (call_kwargs[1].get("env") == {"MY_KEY": "val"})

    def test_env_none_passes_empty_dict(self):
        """When env is None, an empty dict is passed to StdioServerParameters."""
        server = MCPServer(name="fs", command="srv")  # env=None
        mgr = MCPClientManager([server])

        mock_params_cls = MagicMock()

        class _FakeStdioCtx:
            async def __aenter__(self):
                return ("r", "w")
            async def __aexit__(self, *a):
                pass

        mock_stdio = MagicMock(return_value=_FakeStdioCtx())
        mock_session = AsyncMock()
        mock_session.initialize = AsyncMock()

        class _FakeSessionCtx:
            def __init__(self, *a, **kw):
                pass
            async def __aenter__(self):
                return mock_session
            async def __aexit__(self, *a):
                pass

        async def fake_fn(session):
            return "ok"

        with patch.dict("sys.modules", {
            "mcp": MagicMock(
                ClientSession=_FakeSessionCtx,
                StdioServerParameters=mock_params_cls,
            ),
            "mcp.client": MagicMock(),
            "mcp.client.stdio": MagicMock(stdio_client=mock_stdio),
            "mcp.client.streamable_http": MagicMock(),
        }):
            asyncio.run(mgr._with_session(server, fake_fn))

        call_kwargs = mock_params_cls.call_args
        env_val = call_kwargs.kwargs.get("env") if call_kwargs.kwargs else call_kwargs[1].get("env")
        assert env_val == {}

    def test_env_vars_expanded_in_args_and_env(self):
        """Shell-style $VAR and ${VAR} in args/env are expanded from os.environ."""
        server = MCPServer(
            name="pg",
            command="uvx",
            args=["pgsql-mcp-server", "--dsn", "$NOO_TEST_DSN"],
            env={"TOKEN": "${NOO_TEST_TOKEN}"},
        )
        mgr = MCPClientManager([server])

        mock_params_cls = MagicMock()

        class _FakeStdioCtx:
            async def __aenter__(self):
                return ("r", "w")
            async def __aexit__(self, *a):
                pass

        mock_stdio = MagicMock(return_value=_FakeStdioCtx())
        mock_session = AsyncMock()
        mock_session.initialize = AsyncMock()

        class _FakeSessionCtx:
            def __init__(self, *a, **kw):
                pass
            async def __aenter__(self):
                return mock_session
            async def __aexit__(self, *a):
                pass

        async def fake_fn(session):
            return "ok"

        with patch.dict("os.environ", {"NOO_TEST_DSN": "postgresql://x", "NOO_TEST_TOKEN": "tok123"}):
            with patch.dict("sys.modules", {
                "mcp": MagicMock(
                    ClientSession=_FakeSessionCtx,
                    StdioServerParameters=mock_params_cls,
                ),
                "mcp.client": MagicMock(),
                "mcp.client.stdio": MagicMock(stdio_client=mock_stdio),
                "mcp.client.streamable_http": MagicMock(),
            }):
                asyncio.run(mgr._with_session(server, fake_fn))

        call_kwargs = mock_params_cls.call_args
        args_val = call_kwargs.kwargs.get("args") or call_kwargs[1].get("args")
        env_val = call_kwargs.kwargs.get("env") or call_kwargs[1].get("env")
        assert args_val == ["pgsql-mcp-server", "--dsn", "postgresql://x"]
        assert env_val == {"TOKEN": "tok123"}


# ---------------------------------------------------------------------------
# _with_session error handling
# ---------------------------------------------------------------------------

class TestWithSession:
    def test_stdio_missing_command_raises(self):
        server = MCPServer(name="bad", transport="stdio", command=None)
        mgr = MCPClientManager([server])

        # Patch imports so we don't need real mcp SDK
        with patch.dict("sys.modules", {
            "mcp": MagicMock(),
            "mcp.client": MagicMock(),
            "mcp.client.stdio": MagicMock(),
            "mcp.client.streamable_http": MagicMock(),
        }):
            with pytest.raises(ValueError, match="missing command"):
                asyncio.run(mgr._with_session(server, AsyncMock()))

    def test_http_missing_url_raises(self):
        server = MCPServer(name="bad", transport="http", url=None)
        mgr = MCPClientManager([server])

        with patch.dict("sys.modules", {
            "mcp": MagicMock(),
            "mcp.client": MagicMock(),
            "mcp.client.stdio": MagicMock(),
            "mcp.client.streamable_http": MagicMock(),
        }):
            with pytest.raises(ValueError, match="missing url"):
                asyncio.run(mgr._with_session(server, AsyncMock()))

    def test_unsupported_transport_raises(self):
        server = MCPServer(name="bad", transport="grpc")
        mgr = MCPClientManager([server])

        with patch.dict("sys.modules", {
            "mcp": MagicMock(),
            "mcp.client": MagicMock(),
            "mcp.client.stdio": MagicMock(),
            "mcp.client.streamable_http": MagicMock(),
        }):
            with pytest.raises(ValueError, match="Unsupported MCP transport"):
                asyncio.run(mgr._with_session(server, AsyncMock()))
