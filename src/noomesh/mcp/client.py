# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import structlog

from ..tools.base import ToolSpec

log = structlog.get_logger(__name__)


def _unwrap(exc: BaseException) -> str:
    """Render an exception, flattening ExceptionGroups.

    The MCP SDK runs its transports inside an anyio task group, so a plain
    `str(exc)` on failure yields only "unhandled errors in a TaskGroup
    (1 sub-exception)" -- the actual cause (ConnectError, timeout, HTTP
    status) sits in `.exceptions` and never reaches the log. Recurse so the
    operator sees why it failed, not just that it did.
    """
    inner = getattr(exc, "exceptions", None)
    if inner:
        return "; ".join(_unwrap(e) for e in inner)
    detail = str(exc).strip()
    return f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__


@dataclass
class MCPServer:
    name: str
    transport: str = "stdio"  # stdio | http
    command: Optional[str] = None
    args: List[str] | None = None
    url: Optional[str] = None
    env: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None  # HTTP headers for auth etc.


class MCPClientManager:
    def __init__(self, servers: List[MCPServer], tool_prefix: str = "mcp") -> None:
        self.servers = servers
        self.tool_prefix = tool_prefix
        self._tool_map: Dict[str, Tuple[MCPServer, str]] = {}

    def attach_tools(self, registry: Any) -> None:
        if not self.servers:
            return
        try:
            tools = self._run_async(self._discover_tools())
        except Exception as exc:
            log.warning("mcp.tool_discovery_failed", error=_unwrap(exc)[:300])
            return
        for tool in tools:
            registry.register(tool)

    def list_tools(self) -> List[Dict[str, Any]]:
        if not self.servers:
            return []
        try:
            return self._run_async(self._discover_tools_meta())
        except Exception as exc:
            log.warning("mcp.tool_listing_failed", error=_unwrap(exc)[:300])
            return []

    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        if tool_name not in self._tool_map:
            return f"Error: unknown MCP tool '{tool_name}'."
        server, inner_name = self._tool_map[tool_name]
        return self._run_async(self._call_tool_async(server, inner_name, arguments))

    async def _discover_tools(self) -> List[ToolSpec]:
        tools: List[ToolSpec] = []
        for server in self.servers:
            items = await self._list_server_tools_safe(server)
            for tool in items:
                if not tool.get("name"):
                    continue
                tool_name = self._format_tool_name(server.name, tool.get("name"))
                self._tool_map[tool_name] = (server, tool.get("name"))
                tools.append(
                    ToolSpec(
                        name=tool_name,
                        description=tool.get("description") or "MCP tool",
                        parameters=tool.get("input_schema") or {"type": "object"},
                        handler=lambda args, name=tool_name: self.call_tool(name, args),
                    )
                )
        return tools

    async def _discover_tools_meta(self) -> List[Dict[str, Any]]:
        metas: List[Dict[str, Any]] = []
        for server in self.servers:
            items = await self._list_server_tools_safe(server)
            for tool in items:
                if not tool.get("name"):
                    continue
                tool_name = self._format_tool_name(server.name, tool.get("name"))
                self._tool_map[tool_name] = (server, tool.get("name"))
                metas.append(
                    {
                        "name": tool_name,
                        "description": tool.get("description") or "MCP tool",
                        "input_schema": tool.get("input_schema") or {"type": "object", "properties": {}},
                    }
                )
        return metas

    async def _list_server_tools_safe(self, server: MCPServer) -> List[Dict[str, Any]]:
        """List one server's tools, isolating its failure from the others.

        Discovery used to let an exception from any single server propagate
        out of the loop, so ONE unreachable server cost every server's tools
        -- an unrelated stdio MCP server would go dark because some HTTP one
        was down. Degrade per-server instead: log which one failed and why,
        and keep whatever the reachable servers offer.
        """
        try:
            return await self._list_server_tools(server)
        except Exception as exc:
            log.warning(
                "mcp.server_discovery_failed",
                server=server.name,
                transport=server.transport,
                target=server.url or server.command,
                error=_unwrap(exc)[:300],
            )
            return []

    async def _list_server_tools(self, server: MCPServer) -> List[Dict[str, Any]]:
        async def _list(session: Any) -> List[Dict[str, Any]]:
            result = await session.list_tools()
            tools = getattr(result, "tools", result)
            normalized = []
            for tool in tools:
                if isinstance(tool, dict):
                    normalized.append(
                        {
                            "name": tool.get("name"),
                            "description": tool.get("description"),
                            "input_schema": tool.get("inputSchema") or tool.get("input_schema"),
                        }
                    )
                else:
                    normalized.append(
                        {
                            "name": getattr(tool, "name", None),
                            "description": getattr(tool, "description", None),
                            "input_schema": getattr(tool, "inputSchema", None)
                            or getattr(tool, "input_schema", None),
                        }
                    )
            return normalized

        return await self._with_session(server, _list)

    async def _call_tool_async(
        self, server: MCPServer, tool_name: str, arguments: Dict[str, Any]
    ) -> str:
        async def _call(session: Any) -> str:
            result = await session.call_tool(tool_name, arguments=arguments)
            return self._render_tool_result(result)

        return await self._with_session(server, _call)

    async def _with_session(self, server: MCPServer, fn):
        try:
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
            from mcp.client.streamable_http import streamable_http_client
        except Exception as exc:
            raise RuntimeError(
                "mcp SDK not installed. Install with 'pip install -e .[mcp]'."
            ) from exc

        if server.transport == "stdio":
            if not server.command:
                raise ValueError(f"MCP server '{server.name}' missing command.")
            expanded_args = [os.path.expandvars(a) for a in (server.args or [])]
            expanded_env = {
                k: os.path.expandvars(v) for k, v in (server.env or {}).items()
            }
            params = StdioServerParameters(
                command=server.command,
                args=expanded_args,
                env=expanded_env,
            )
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return await fn(session)

        if server.transport in {"http", "streamable_http"}:
            if not server.url:
                raise ValueError(f"MCP server '{server.name}' missing url.")
            # mcp 2.x talks through httpx2 (a drop-in fork of httpx) and
            # `streamable_http_client(http_client=...)` is typed httpx2.AsyncClient;
            # build that, not a plain httpx client that merely duck-types today.
            import httpx2 as _httpx
            http_kwargs: dict[str, Any] = {}
            from noomesh._providers import default_http_context
            _http_ctx = default_http_context()
            if server.headers:
                http_kwargs["http_client"] = _httpx.AsyncClient(
                    headers=server.headers,
                    timeout=_httpx.Timeout(60.0, connect=10.0),
                    verify=_http_ctx.verify,
                    cert=_http_ctx.cert,
                )
            # mcp 2.x yields (read, write); 1.x yielded a third item, the
            # session-id getter, which nothing here used.
            async with streamable_http_client(server.url, **http_kwargs) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return await fn(session)

        raise ValueError(f"Unsupported MCP transport: {server.transport}")

    def _render_tool_result(self, result: Any) -> str:
        content = getattr(result, "content", None)
        structured = getattr(result, "structuredContent", None)

        if isinstance(result, dict):
            content = result.get("content", content)
            structured = result.get("structuredContent", structured)

        outputs: List[str] = []

        if content:
            for item in content:
                if isinstance(item, dict):
                    text = item.get("text") or item.get("data")
                else:
                    text = getattr(item, "text", None) or getattr(item, "data", None)
                if text:
                    outputs.append(str(text))

        if structured:
            outputs.append(str(structured))

        if not outputs:
            return "(no output)"
        return "\n".join(outputs)

    def _format_tool_name(self, server_name: str, tool_name: Optional[str]) -> str:
        base = f"{self.tool_prefix}_{server_name}_{tool_name or 'tool'}"
        return re.sub(r"[^a-zA-Z0-9_]+", "_", base)

    @staticmethod
    def _run_async(coro):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)

        if not loop.is_running():
            return loop.run_until_complete(coro)

        # If we're already in an event loop, run the coroutine in a thread.
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(asyncio.run, coro)
            return future.result()
