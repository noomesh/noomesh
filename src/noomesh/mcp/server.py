# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Mesh MCP Server (standalone).

Exposes PAI gateway tools via the Model Context Protocol so that
external LLM clients (Claude Code, Cursor, etc.) can discover and
call them.

NOTE: this is NOT what the running stack serves. The MCP doors are Rust —
the gateway serves ``/mcp/operator`` (``mcp_local.rs``) and ``/mcp/user``
(``mcp_external.rs``) on its own port. The Python MCPHub that used to back a
separate :3100 listener was retired 2026-08-11 (MCP_HUB_PORT.md phase 3), and
that listener itself was removed from the gateway in stack-v0.2.40. Prefer the
gateway door (https://<gateway>:8080/mcp/operator); this standalone server
exists for direct stdio/HTTP use without a gateway.

Usage:
    # stdio (default — for Claude Code / Cursor subprocess)
    python -m noomesh.mcp.server

    # Streamable HTTP (for remote access)
    python -m noomesh.mcp.server --transport http --port 3100
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import structlog
import sys

logger = structlog.get_logger("noo_mcp_server")


# ---------------------------------------------------------------------------
# Server construction
# ---------------------------------------------------------------------------

def _build_server():
    """Create and configure the MCP Server with PAI tools."""
    from mcp.server import Server
    from mcp.types import (
        CallToolRequestParams,
        CallToolResult,
        ListToolsResult,
        TextContent,
        Tool,
    )

    from ._sdk import invalid_arguments
    from .tool_models import get_enabled_tools, handle_tool_call

    # mcp 2.x: handlers are constructor arguments `(ctx, params) -> Result`,
    # not decorators (`@server.list_tools()` / `@server.call_tool()` are gone).
    async def list_tools(ctx, params) -> ListToolsResult:
        return ListToolsResult(
            tools=[
                Tool(
                    name=t["name"],
                    description=t["description"],
                    input_schema=t["input_schema"],
                )
                for t in get_enabled_tools()
            ]
        )

    async def call_tool(ctx, params: CallToolRequestParams) -> CallToolResult:
        name = params.name
        bad = invalid_arguments(
            next((x["input_schema"] for x in get_enabled_tools() if x["name"] == name), None),
            params.arguments,
        )
        if bad is not None:
            return bad
        try:
            result = await handle_tool_call(name, params.arguments or {})
            return CallToolResult(content=[TextContent(type="text", text=result)])
        except Exception as exc:
            logger.warning("tool_call_error: %s — %s", name, exc)
            return CallToolResult(content=[TextContent(type="text", text=f"Error: {exc}")])

    server = Server("mesh", on_list_tools=list_tools, on_call_tool=call_tool)

    return server


# ---------------------------------------------------------------------------
# Transport runners
# ---------------------------------------------------------------------------

async def _run_stdio(server) -> None:
    """Run the MCP server over stdio (stdin/stdout JSON-RPC)."""
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def _build_http_app(server):
    """The Streamable HTTP ASGI app for `server`, served at ``/mcp``.

    mcp 2.x builds this itself (`Server.streamable_http_app`), including the
    session manager and its lifespan, and serves both protocol eras: the
    legacy ``initialize`` handshake and the stateless 2026-07-28 revision. The
    1.x code drove a bare ``StreamableHTTPServerTransport`` from a hand-rolled
    ASGI function; that constructor and ``connect(scope, receive, send)`` are
    gone. The bind host is 0.0.0.0, so the SDK's localhost-only DNS-rebinding
    guard is not auto-enabled, exactly as before.
    """
    return server.streamable_http_app(streamable_http_path="/mcp", host="0.0.0.0")


async def _run_http(server, port: int) -> None:
    """Run the MCP server over Streamable HTTP."""
    import uvicorn

    config = uvicorn.Config(_build_http_app(server), host="0.0.0.0", port=port, log_level="info")
    uvi = uvicorn.Server(config)
    logger.info("Starting MCP HTTP server on port %d", port)
    await uvi.serve()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mesh MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Environment variables:\n"
            "  NOO_GATEWAY_URL     Gateway base URL (default: http://localhost:8000)\n"
            "  NOO_GATEWAY_KEY     This process's own service key (mutation tools)\n"
            "  NOO_JWT_TOKEN       Pre-generated JWT for user auth\n"
            "  NOO_MCP_PORT        Port for HTTP transport (default: 3100)\n"
            "  NOO_MCP_TOOLS       Comma-separated tool allowlist, or 'all' (default)\n"
        ),
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(__import__("noomesh.config", fromlist=["env_or_yaml"]).env_or_yaml(
            "NOO_MCP_PORT", lambda c: c.mcp.port, 3100)),
        help="Port for HTTP transport (default: 3100)",
    )
    args = parser.parse_args()

    try:
        import mcp  # noqa: F401
    except ImportError:
        print(
            "Error: mcp SDK not installed.\n"
            "Install with: pip install 'noomesh[mcp]'",
            file=sys.stderr,
        )
        sys.exit(1)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,  # keep stdout clean for stdio JSON-RPC
    )

    server = _build_server()

    if args.transport == "stdio":
        asyncio.run(_run_stdio(server))
    else:
        asyncio.run(_run_http(server, args.port))


if __name__ == "__main__":
    main()
