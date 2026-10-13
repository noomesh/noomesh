# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Unit tests for PAI Filesystem MCP Server."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from noomesh.mcp.filesystem_server import (
    TOOLS,
    _HANDLERS,
    _human_size,
    _set_allowed,
    _validate_path,
    create_directory,
    directory_tree,
    edit_file,
    get_file_info,
    list_allowed_directories,
    list_directory,
    list_directory_with_sizes,
    move_file,
    read_media_file,
    read_multiple_files,
    read_text_file,
    search_files,
    write_file,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def tmp_sandbox(tmp_path):
    """Set up a temp directory as the only allowed root."""
    _set_allowed([str(tmp_path)])
    # Create some test files
    (tmp_path / "hello.txt").write_text("Hello World\nLine 2\nLine 3\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "nested.txt").write_text("nested content")
    (tmp_path / "image.bin").write_bytes(b"\x89PNG\r\n\x1a\nfakedata")
    yield tmp_path


# ---------------------------------------------------------------------------
# Sandbox validation
# ---------------------------------------------------------------------------

class TestSandbox:
    def test_valid_path(self, tmp_sandbox):
        p = _validate_path(str(tmp_sandbox / "hello.txt"))
        assert p == (tmp_sandbox / "hello.txt").resolve()

    def test_path_outside_sandbox_raises(self, tmp_sandbox):
        with pytest.raises(PermissionError, match="Access denied"):
            _validate_path("/etc/passwd")

    def test_relative_escape_blocked(self, tmp_sandbox):
        with pytest.raises(PermissionError, match="Access denied"):
            _validate_path(str(tmp_sandbox / ".." / ".." / "etc" / "passwd"))


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

class TestToolRegistry:
    def test_13_tools_registered(self):
        assert len(TOOLS) == 13

    def test_all_tools_have_handlers(self):
        for t in TOOLS:
            assert t["name"] in _HANDLERS, f"Missing handler for {t['name']}"


# ---------------------------------------------------------------------------
# Read tools
# ---------------------------------------------------------------------------

class TestReadTools:
    @pytest.mark.asyncio
    async def test_read_text_file(self, tmp_sandbox):
        result = await read_text_file({"path": str(tmp_sandbox / "hello.txt")})
        assert "Hello World" in result
        assert "Line 3" in result

    @pytest.mark.asyncio
    async def test_read_text_file_head(self, tmp_sandbox):
        result = await read_text_file({"path": str(tmp_sandbox / "hello.txt"), "head": 1})
        assert "Hello World" in result
        assert "Line 2" not in result

    @pytest.mark.asyncio
    async def test_read_text_file_tail(self, tmp_sandbox):
        result = await read_text_file({"path": str(tmp_sandbox / "hello.txt"), "tail": 1})
        assert "Hello World" not in result
        assert "Line 3" in result

    @pytest.mark.asyncio
    async def test_read_media_file(self, tmp_sandbox):
        result = await read_media_file({"path": str(tmp_sandbox / "image.bin")})
        import base64
        decoded = base64.b64decode(result)
        assert decoded.startswith(b"\x89PNG")

    @pytest.mark.asyncio
    async def test_read_multiple_files(self, tmp_sandbox):
        result = await read_multiple_files({"paths": [
            str(tmp_sandbox / "hello.txt"),
            str(tmp_sandbox / "sub" / "nested.txt"),
        ]})
        assert "Hello World" in result
        assert "nested content" in result

    @pytest.mark.asyncio
    async def test_read_multiple_files_with_error(self, tmp_sandbox):
        result = await read_multiple_files({"paths": [
            str(tmp_sandbox / "hello.txt"),
            str(tmp_sandbox / "nonexistent.txt"),
        ]})
        assert "Hello World" in result
        assert "Error:" in result


# ---------------------------------------------------------------------------
# Write tools
# ---------------------------------------------------------------------------

class TestWriteTools:
    @pytest.mark.asyncio
    async def test_write_file(self, tmp_sandbox):
        target = str(tmp_sandbox / "new.txt")
        result = await write_file({"path": target, "content": "new content"})
        assert "Wrote" in result
        assert Path(target).read_text() == "new content"

    @pytest.mark.asyncio
    async def test_write_file_creates_parents(self, tmp_sandbox):
        target = str(tmp_sandbox / "deep" / "nested" / "file.txt")
        await write_file({"path": target, "content": "deep"})
        assert Path(target).read_text() == "deep"

    @pytest.mark.asyncio
    async def test_write_outside_sandbox_denied(self, tmp_sandbox):
        with pytest.raises(PermissionError):
            await write_file({"path": "/tmp/evil.txt", "content": "bad"})


# ---------------------------------------------------------------------------
# Edit tool
# ---------------------------------------------------------------------------

class TestEditTool:
    @pytest.mark.asyncio
    async def test_edit_file_replace(self, tmp_sandbox):
        result = await edit_file({
            "path": str(tmp_sandbox / "hello.txt"),
            "edits": [{"old_text": "Hello World", "new_text": "Hi There"}],
        })
        assert "replaced 1" in result
        assert "Hi There" in (tmp_sandbox / "hello.txt").read_text()

    @pytest.mark.asyncio
    async def test_edit_file_dry_run(self, tmp_sandbox):
        original = (tmp_sandbox / "hello.txt").read_text()
        result = await edit_file({
            "path": str(tmp_sandbox / "hello.txt"),
            "edits": [{"old_text": "Hello World", "new_text": "Changed"}],
            "dry_run": True,
        })
        assert "Dry run" in result
        assert (tmp_sandbox / "hello.txt").read_text() == original

    @pytest.mark.asyncio
    async def test_edit_file_not_found_text(self, tmp_sandbox):
        result = await edit_file({
            "path": str(tmp_sandbox / "hello.txt"),
            "edits": [{"old_text": "NONEXISTENT", "new_text": "x"}],
        })
        assert "not found" in result


# ---------------------------------------------------------------------------
# Directory tools
# ---------------------------------------------------------------------------

class TestDirectoryTools:
    @pytest.mark.asyncio
    async def test_create_directory(self, tmp_sandbox):
        target = str(tmp_sandbox / "newdir" / "child")
        result = await create_directory({"path": target})
        assert "ensured" in result
        assert Path(target).is_dir()

    @pytest.mark.asyncio
    async def test_list_directory(self, tmp_sandbox):
        result = await list_directory({"path": str(tmp_sandbox)})
        assert "sub" in result
        assert "hello.txt" in result
        assert "[DIR]" in result

    @pytest.mark.asyncio
    async def test_list_directory_with_sizes(self, tmp_sandbox):
        result = await list_directory_with_sizes({"path": str(tmp_sandbox)})
        assert "hello.txt" in result
        assert "[DIR]" in result

    @pytest.mark.asyncio
    async def test_directory_tree(self, tmp_sandbox):
        result = await directory_tree({"path": str(tmp_sandbox)})
        tree = json.loads(result)
        assert tree["type"] == "directory"
        child_names = [c["name"] for c in tree["children"] if isinstance(c, dict)]
        assert "sub" in child_names
        assert "hello.txt" in child_names

    @pytest.mark.asyncio
    async def test_directory_tree_max_depth(self, tmp_sandbox):
        result = await directory_tree({"path": str(tmp_sandbox), "max_depth": 0})
        tree = json.loads(result)
        assert "depth limit" in str(tree["children"])

    @pytest.mark.asyncio
    async def test_directory_tree_excludes(self, tmp_sandbox):
        result = await directory_tree({
            "path": str(tmp_sandbox),
            "exclude_patterns": ["sub"],
        })
        tree = json.loads(result)
        child_names = [c["name"] for c in tree["children"] if isinstance(c, dict)]
        assert "sub" not in child_names


# ---------------------------------------------------------------------------
# File operations
# ---------------------------------------------------------------------------

class TestFileOps:
    @pytest.mark.asyncio
    async def test_move_file(self, tmp_sandbox):
        src = str(tmp_sandbox / "hello.txt")
        dst = str(tmp_sandbox / "moved.txt")
        result = await move_file({"source": src, "destination": dst})
        assert "Moved" in result
        assert not Path(src).exists()
        assert Path(dst).exists()

    @pytest.mark.asyncio
    async def test_search_files(self, tmp_sandbox):
        result = await search_files({
            "path": str(tmp_sandbox),
            "pattern": "*.txt",
        })
        assert "hello.txt" in result
        assert "nested.txt" in result

    @pytest.mark.asyncio
    async def test_search_files_no_results(self, tmp_sandbox):
        result = await search_files({
            "path": str(tmp_sandbox),
            "pattern": "*.xyz",
        })
        assert "No files found" in result

    @pytest.mark.asyncio
    async def test_get_file_info(self, tmp_sandbox):
        result = await get_file_info({"path": str(tmp_sandbox / "hello.txt")})
        info = json.loads(result)
        assert info["type"] == "file"
        assert info["size"] > 0
        assert "modified" in info

    @pytest.mark.asyncio
    async def test_list_allowed_directories(self, tmp_sandbox):
        result = await list_allowed_directories({})
        assert str(tmp_sandbox.resolve()) in result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_human_size_bytes(self):
        assert _human_size(512) == "512B"

    def test_human_size_kb(self):
        assert "KB" in _human_size(2048)

    def test_human_size_mb(self):
        assert "MB" in _human_size(5 * 1024 * 1024)
