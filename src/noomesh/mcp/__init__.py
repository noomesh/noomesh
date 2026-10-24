# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

from .client import MCPClientManager, MCPServer

# MCPHub was removed in the task #23 sweep (history in git log before 2026-08-08) — both MCP
# doors are served by the Rust gateway on its own port (mcp_local.rs at
# /mcp/operator, mcp_external.rs at /mcp/user). The client (external MCP servers consumed BY
# Mesh via `noo mcp` / factory) stays live.
__all__ = ["MCPClientManager", "MCPServer"]
