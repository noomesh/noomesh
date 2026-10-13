# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

from .client import MCPClientManager, MCPServer

# MCPHub moved to legacy/python-mcp-reference/ (task #23 sweep) — both MCP
# doors are served by the Rust gateway on its own port (mcp_local.rs at
# /mcp/operator, mcp_external.rs at /mcp/user). The client (external MCP servers consumed BY
# Mesh via `noo mcp` / factory) stays live.
__all__ = ["MCPClientManager", "MCPServer"]
