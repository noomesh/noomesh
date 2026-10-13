# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""PAI Filesystem MCP Server.

Sandboxed file operations restricted to explicitly allowed directories.
Pure Python — no Node.js / npx required.

Usage:
    python -m noomesh.mcp.filesystem_server /path/to/allowed/dir [...]
    noo-mcp-filesystem ~/projects /tmp/scratch
"""
from __future__ import annotations

import argparse
import asyncio
import base64
from .. import json_fast as json
import logging
import structlog
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = structlog.get_logger("noo_mcp_filesystem")

# ---------------------------------------------------------------------------
# Allowed-directory sandbox
# ---------------------------------------------------------------------------

_allowed_roots: list[Path] = []


def _set_allowed(dirs: list[str]) -> None:
    global _allowed_roots
    _allowed_roots = [Path(d).resolve() for d in dirs]


def _validate_path(path_str: str) -> Path:
    """Resolve a path and verify it falls under an allowed root."""
    resolved = Path(path_str).resolve()
    for root in _allowed_roots:
        if resolved == root or root in resolved.parents:
            return resolved
    raise PermissionError(
        f"Access denied: {path_str} is outside allowed directories "
        f"({', '.join(str(r) for r in _allowed_roots)})"
    )


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

TOOLS: list[dict[str, Any]] = []
_HANDLERS: dict[str, Any] = {}


def _tool(name: str, description: str, schema: dict):
    """Decorator to register a tool handler."""
    def decorator(fn):
        TOOLS.append({"name": name, "description": description, "input_schema": schema})
        _HANDLERS[name] = fn
        return fn
    return decorator


@_tool(
    "read_text_file",
    "Read a text file. Optionally return only the first or last N lines.",
    {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File path"},
            "head": {"type": "integer", "description": "Return only the first N lines"},
            "tail": {"type": "integer", "description": "Return only the last N lines"},
        },
        "required": ["path"],
    },
)
async def read_text_file(args: dict) -> str:
    p = _validate_path(args["path"])
    text = p.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines(keepends=True)
    if args.get("head"):
        lines = lines[: args["head"]]
    elif args.get("tail"):
        lines = lines[-args["tail"] :]
    return "".join(lines)


@_tool(
    "read_media_file",
    "Read an image, audio, or binary file and return its content as base64.",
    {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File path"},
        },
        "required": ["path"],
    },
)
async def read_media_file(args: dict) -> str:
    p = _validate_path(args["path"])
    data = p.read_bytes()
    return base64.b64encode(data).decode("ascii")


@_tool(
    "read_multiple_files",
    "Read multiple text files at once. Returns each file's content labeled by path.",
    {
        "type": "object",
        "properties": {
            "paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of file paths",
            },
        },
        "required": ["paths"],
    },
)
async def read_multiple_files(args: dict) -> str:
    parts = []
    for path_str in args["paths"]:
        try:
            p = _validate_path(path_str)
            content = p.read_text(encoding="utf-8", errors="replace")
            parts.append(f"--- {path_str} ---\n{content}")
        except Exception as e:
            parts.append(f"--- {path_str} ---\nError: {e}")
    return "\n\n".join(parts)


@_tool(
    "write_file",
    "Create or overwrite a file with the given content.",
    {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File path"},
            "content": {"type": "string", "description": "Content to write"},
        },
        "required": ["path", "content"],
    },
)
async def write_file(args: dict) -> str:
    p = _validate_path(args["path"])
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(args["content"], encoding="utf-8")
    return f"Wrote {len(args['content'])} chars to {p}"


@_tool(
    "edit_file",
    "Apply find-and-replace edits to a file. Each edit replaces old_text with new_text.",
    {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File path"},
            "edits": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "old_text": {"type": "string"},
                        "new_text": {"type": "string"},
                    },
                    "required": ["old_text", "new_text"],
                },
                "description": "List of {old_text, new_text} replacements",
            },
            "dry_run": {
                "type": "boolean",
                "description": "If true, show diff without writing (default: false)",
            },
        },
        "required": ["path", "edits"],
    },
)
async def edit_file(args: dict) -> str:
    p = _validate_path(args["path"])
    original = p.read_text(encoding="utf-8")
    content = original
    applied = []
    for i, edit in enumerate(args["edits"]):
        old = edit["old_text"]
        new = edit["new_text"]
        if old not in content:
            applied.append(f"  edit {i + 1}: old_text not found (skipped)")
            continue
        count = content.count(old)
        content = content.replace(old, new)
        applied.append(f"  edit {i + 1}: replaced {count} occurrence(s)")

    if args.get("dry_run"):
        return "Dry run — no changes written.\n" + "\n".join(applied)

    if content != original:
        p.write_text(content, encoding="utf-8")
    return "Applied edits:\n" + "\n".join(applied)


@_tool(
    "create_directory",
    "Create a directory (and parents). No error if it already exists.",
    {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Directory path"},
        },
        "required": ["path"],
    },
)
async def create_directory(args: dict) -> str:
    p = _validate_path(args["path"])
    p.mkdir(parents=True, exist_ok=True)
    return f"Directory ensured: {p}"


@_tool(
    "list_directory",
    "List files and subdirectories in a directory.",
    {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Directory path"},
        },
        "required": ["path"],
    },
)
async def list_directory(args: dict) -> str:
    p = _validate_path(args["path"])
    entries = sorted(p.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower()))
    lines = []
    for e in entries:
        prefix = "[DIR] " if e.is_dir() else "      "
        lines.append(f"{prefix}{e.name}")
    return "\n".join(lines) if lines else "(empty directory)"


@_tool(
    "list_directory_with_sizes",
    "List directory contents with file sizes.",
    {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Directory path"},
            "sort_by": {
                "type": "string",
                "enum": ["name", "size"],
                "description": "Sort order (default: name)",
            },
        },
        "required": ["path"],
    },
)
async def list_directory_with_sizes(args: dict) -> str:
    p = _validate_path(args["path"])
    entries = list(p.iterdir())
    items = []
    for e in entries:
        try:
            size = e.stat().st_size if e.is_file() else None
        except OSError:
            size = None
        items.append((e.name, e.is_dir(), size))

    if args.get("sort_by") == "size":
        items.sort(key=lambda x: (x[2] is None, -(x[2] or 0)))
    else:
        items.sort(key=lambda x: (not x[1], x[0].lower()))

    lines = []
    for name, is_dir, size in items:
        if is_dir:
            lines.append(f"[DIR]  {name}")
        else:
            sz = _human_size(size) if size is not None else "?"
            lines.append(f"{sz:>8s}  {name}")
    return "\n".join(lines) if lines else "(empty directory)"


@_tool(
    "move_file",
    "Move or rename a file or directory.",
    {
        "type": "object",
        "properties": {
            "source": {"type": "string", "description": "Source path"},
            "destination": {"type": "string", "description": "Destination path"},
        },
        "required": ["source", "destination"],
    },
)
async def move_file(args: dict) -> str:
    src = _validate_path(args["source"])
    dst = _validate_path(args["destination"])
    shutil.move(str(src), str(dst))
    return f"Moved {src} -> {dst}"


@_tool(
    "search_files",
    "Recursively search for files matching a glob pattern.",
    {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Directory to search in"},
            "pattern": {"type": "string", "description": "Glob pattern (e.g. '*.py', '**/*.ts')"},
            "exclude_patterns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Glob patterns to exclude",
            },
        },
        "required": ["path", "pattern"],
    },
)
async def search_files(args: dict) -> str:
    p = _validate_path(args["path"])
    excludes = set(args.get("exclude_patterns") or [])
    matches = []
    for match in p.rglob(args["pattern"]):
        if any(match.match(ex) for ex in excludes):
            continue
        rel = match.relative_to(p)
        matches.append(str(rel))
        if len(matches) >= 500:
            matches.append("... (truncated at 500 results)")
            break
    return "\n".join(matches) if matches else "No files found."


@_tool(
    "directory_tree",
    "Get a JSON tree representation of a directory structure.",
    {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Root directory path"},
            "max_depth": {
                "type": "integer",
                "description": "Maximum recursion depth (default: 4)",
            },
            "exclude_patterns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Directory/file names to exclude (e.g. ['node_modules', '.git'])",
            },
        },
        "required": ["path"],
    },
)
async def directory_tree(args: dict) -> str:
    p = _validate_path(args["path"])
    max_depth = args.get("max_depth", 4)
    excludes = set(args.get("exclude_patterns") or [])

    def _walk(current: Path, depth: int) -> dict:
        node: dict[str, Any] = {"name": current.name, "type": "directory"}
        if depth >= max_depth:
            node["children"] = ["... (depth limit)"]
            return node
        children = []
        try:
            for entry in sorted(current.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower())):
                if entry.name in excludes:
                    continue
                if entry.is_dir():
                    children.append(_walk(entry, depth + 1))
                else:
                    children.append({"name": entry.name, "type": "file", "size": entry.stat().st_size})
        except PermissionError:
            children.append({"error": "permission denied"})
        node["children"] = children
        return node

    tree = _walk(p, 0)
    return json.dumps(tree, indent=2)


@_tool(
    "get_file_info",
    "Get file metadata: size, timestamps, permissions.",
    {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "File or directory path"},
        },
        "required": ["path"],
    },
)
async def get_file_info(args: dict) -> str:
    p = _validate_path(args["path"])
    st = p.stat()
    info = {
        "path": str(p),
        "type": "directory" if p.is_dir() else "file",
        "size": st.st_size,
        "size_human": _human_size(st.st_size),
        "created": datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).isoformat(),
        "modified": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
        "permissions": oct(st.st_mode)[-3:],
    }
    return json.dumps(info, indent=2)


@_tool(
    "list_allowed_directories",
    "List the directories this server is allowed to access.",
    {"type": "object", "properties": {}},
)
async def list_allowed_directories(args: dict) -> str:
    return "\n".join(str(r) for r in _allowed_roots) or "(none configured)"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


# ---------------------------------------------------------------------------
# Server wiring
# ---------------------------------------------------------------------------

def _build_server():
    from mcp.server import Server
    from mcp.types import TextContent, Tool

    server = Server("noo-filesystem")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(name=t["name"], description=t["description"], inputSchema=t["input_schema"])
            for t in TOOLS
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict | None) -> list[TextContent]:
        handler = _HANDLERS.get(name)
        if not handler:
            return [TextContent(type="text", text=f"Error: unknown tool '{name}'")]
        try:
            result = await handler(arguments or {})
            return [TextContent(type="text", text=result)]
        except PermissionError as exc:
            return [TextContent(type="text", text=f"Permission denied: {exc}")]
        except FileNotFoundError as exc:
            return [TextContent(type="text", text=f"File not found: {exc}")]
        except Exception as exc:
            logger.warning("tool error: %s — %s", name, exc)
            return [TextContent(type="text", text=f"Error: {exc}")]

    return server


async def _run_stdio(server) -> None:
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PAI Filesystem MCP Server",
        epilog="Paths outside the allowed directories will be rejected.",
    )
    parser.add_argument(
        "directories",
        nargs="+",
        help="Directories the server is allowed to access",
    )
    args = parser.parse_args()

    for d in args.directories:
        if not Path(d).is_dir():
            print(f"Error: '{d}' is not a directory", file=sys.stderr)
            sys.exit(1)

    _set_allowed(args.directories)

    try:
        import mcp  # noqa: F401
    except ImportError:
        print("Error: mcp SDK not installed. pip install 'noomesh[mcp]'", file=sys.stderr)
        sys.exit(1)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s", stream=sys.stderr)
    logger.info("Allowed directories: %s", [str(r) for r in _allowed_roots])

    server = _build_server()
    asyncio.run(_run_stdio(server))


if __name__ == "__main__":
    main()
