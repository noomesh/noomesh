# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Integration tests for MCP filesystem server.

Requires: npx on PATH + @modelcontextprotocol/server-filesystem package.
Auto-skipped if npx is not available.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from noomesh.mcp.client import MCPClientManager, MCPServer

pytestmark = pytest.mark.integration

_HAS_NPX = shutil.which("npx") is not None


@pytest.fixture
def tmp_workspace():
    """Create a temporary directory with a known file."""
    d = tempfile.mkdtemp(prefix="mcp_test_")
    p = Path(d)
    (p / "hello.txt").write_text("Hello from MCP test!", encoding="utf-8")
    (p / "sub").mkdir()
    (p / "sub" / "nested.txt").write_text("nested content", encoding="utf-8")
    yield p
    shutil.rmtree(d, ignore_errors=True)


def _make_fs_manager(allowed_dir: str) -> MCPClientManager:
    server = MCPServer(
        name="fs",
        transport="stdio",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem", allowed_dir],
    )
    return MCPClientManager([server])


@pytest.mark.skipif(not _HAS_NPX, reason="npx not on PATH")
def test_discover_filesystem_tools(tmp_workspace):
    mgr = _make_fs_manager(str(tmp_workspace))
    tools = mgr.list_tools()
    names = [t["name"] for t in tools]
    assert any("read_file" in n for n in names), f"Expected read_file in {names}"
    assert any("list_directory" in n for n in names), f"Expected list_directory in {names}"


@pytest.mark.skipif(not _HAS_NPX, reason="npx not on PATH")
def test_read_file(tmp_workspace):
    mgr = _make_fs_manager(str(tmp_workspace))
    # Discover tools first
    mgr._run_async(mgr._discover_tools())
    # Find the read_file tool name
    read_tool = [n for n in mgr._tool_map if "read_file" in n]
    assert read_tool, f"No read_file tool found in {list(mgr._tool_map.keys())}"
    result = mgr.call_tool(read_tool[0], {"path": str(tmp_workspace / "hello.txt")})
    assert "Hello from MCP test!" in result


@pytest.mark.skipif(not _HAS_NPX, reason="npx not on PATH")
def test_list_directory(tmp_workspace):
    mgr = _make_fs_manager(str(tmp_workspace))
    mgr._run_async(mgr._discover_tools())
    list_tool = [n for n in mgr._tool_map if "list_directory" in n]
    assert list_tool, f"No list_directory tool found in {list(mgr._tool_map.keys())}"
    result = mgr.call_tool(list_tool[0], {"path": str(tmp_workspace)})
    assert "hello.txt" in result
    assert "sub" in result
