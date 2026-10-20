# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Shims over the MCP Python SDK (mcp 2.x) shared by the three stdio/HTTP servers.

mcp 1.x validated `tools/call` arguments against the tool's `inputSchema` inside
the `@server.call_tool()` decorator. The 2.x low-level `Server` takes handlers as
constructor arguments and no longer validates them, so a schema-invalid call
would reach the handler and fail there as a `KeyError` string instead of a
protocol-visible `isError` result. :func:`invalid_arguments` restores the 1.x
behaviour in one place.
"""

from __future__ import annotations

from typing import Any, Mapping

from mcp.types import CallToolResult, TextContent


def invalid_arguments(
    schema: Mapping[str, Any] | None, arguments: Mapping[str, Any] | None
) -> CallToolResult | None:
    """An `isError` result when `arguments` violate `schema`, else None."""
    if not schema:
        return None
    import jsonschema

    try:
        jsonschema.validate(instance=dict(arguments or {}), schema=dict(schema))
    except jsonschema.ValidationError as exc:
        return CallToolResult(
            content=[TextContent(type="text", text=f"Input validation error: {exc.message}")],
            is_error=True,
        )
    return None
