# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""PAI GitHub MCP Server.

Wraps the ``gh`` CLI — reuses the user's existing ``gh auth`` session.
No API tokens or Node.js required.

Usage:
    python -m noomesh.mcp.github_server
    noo-mcp-github
"""
from __future__ import annotations

import asyncio
from .. import json_fast as json
import logging
import structlog
import shutil
import sys
from typing import Any

logger = structlog.get_logger("noo_mcp_github")

# ---------------------------------------------------------------------------
# gh CLI wrapper
# ---------------------------------------------------------------------------


async def _gh(args: list[str], timeout: float = 30.0) -> str:
    """Run a ``gh`` CLI command and return stdout."""
    proc = await asyncio.create_subprocess_exec(
        "gh", *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise TimeoutError(f"gh {' '.join(args)} timed out after {timeout}s")
    if proc.returncode != 0:
        err = stderr.decode().strip()
        raise RuntimeError(f"gh {' '.join(args[:3])}... failed (exit {proc.returncode}): {err}")
    return stdout.decode()


async def _gh_json(args: list[str], timeout: float = 30.0) -> Any:
    """Run a ``gh`` command with --json and parse the output."""
    raw = await _gh(args, timeout=timeout)
    return json.loads(raw) if raw.strip() else {}


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

TOOLS: list[dict[str, Any]] = []
_HANDLERS: dict[str, Any] = {}


def _tool(name: str, description: str, schema: dict):
    def decorator(fn):
        TOOLS.append({"name": name, "description": description, "input_schema": schema})
        _HANDLERS[name] = fn
        return fn
    return decorator


@_tool(
    "search_repositories",
    "Search GitHub repositories by keyword.",
    {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "limit": {"type": "integer", "description": "Max results (default: 10)"},
        },
        "required": ["query"],
    },
)
async def search_repositories(args: dict) -> str:
    limit = str(min(args.get("limit", 10), 30))
    result = await _gh([
        "search", "repos", args["query"],
        "--limit", limit,
        "--json", "fullName,description,stargazersCount,updatedAt,url",
    ])
    repos = json.loads(result) if result.strip() else []
    if not repos:
        return "No repositories found."
    lines = []
    for r in repos:
        stars = r.get("stargazersCount", 0)
        lines.append(f"- {r['fullName']} ({stars} stars): {r.get('description', '')}")
        lines.append(f"  {r.get('url', '')}")
    return "\n".join(lines)


@_tool(
    "get_repo_info",
    "Get detailed information about a repository.",
    {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "Repository (owner/name)"},
        },
        "required": ["repo"],
    },
)
async def get_repo_info(args: dict) -> str:
    return await _gh(["repo", "view", args["repo"]])


@_tool(
    "list_issues",
    "List issues for a repository.",
    {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "Repository (owner/name)"},
            "state": {
                "type": "string",
                "enum": ["open", "closed", "all"],
                "description": "Filter by state (default: open)",
            },
            "limit": {"type": "integer", "description": "Max results (default: 20)"},
            "labels": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Filter by labels",
            },
        },
        "required": ["repo"],
    },
)
async def list_issues(args: dict) -> str:
    cmd = ["issue", "list", "-R", args["repo"]]
    cmd += ["--state", args.get("state", "open")]
    cmd += ["--limit", str(min(args.get("limit", 20), 50))]
    for label in args.get("labels") or []:
        cmd += ["--label", label]
    cmd += ["--json", "number,title,state,author,createdAt,labels"]
    data = await _gh_json(cmd)
    if not data:
        return "No issues found."
    lines = []
    for i in data:
        labels = ", ".join(l["name"] for l in i.get("labels", []))
        label_str = f" [{labels}]" if labels else ""
        author = i.get("author", {}).get("login", "?")
        lines.append(f"#{i['number']} ({i['state']}) {i['title']}{label_str} — @{author}")
    return "\n".join(lines)


@_tool(
    "get_issue",
    "Get details of a specific issue.",
    {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "Repository (owner/name)"},
            "number": {"type": "integer", "description": "Issue number"},
        },
        "required": ["repo", "number"],
    },
)
async def get_issue(args: dict) -> str:
    return await _gh(["issue", "view", str(args["number"]), "-R", args["repo"]])


@_tool(
    "create_issue",
    "Create a new issue in a repository.",
    {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "Repository (owner/name)"},
            "title": {"type": "string", "description": "Issue title"},
            "body": {"type": "string", "description": "Issue body (markdown)"},
            "labels": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Labels to apply",
            },
        },
        "required": ["repo", "title"],
    },
)
async def create_issue(args: dict) -> str:
    cmd = ["issue", "create", "-R", args["repo"], "--title", args["title"]]
    if args.get("body"):
        cmd += ["--body", args["body"]]
    for label in args.get("labels") or []:
        cmd += ["--label", label]
    return await _gh(cmd)


@_tool(
    "list_pull_requests",
    "List pull requests for a repository.",
    {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "Repository (owner/name)"},
            "state": {
                "type": "string",
                "enum": ["open", "closed", "merged", "all"],
                "description": "Filter by state (default: open)",
            },
            "limit": {"type": "integer", "description": "Max results (default: 20)"},
        },
        "required": ["repo"],
    },
)
async def list_pull_requests(args: dict) -> str:
    cmd = ["pr", "list", "-R", args["repo"]]
    cmd += ["--state", args.get("state", "open")]
    cmd += ["--limit", str(min(args.get("limit", 20), 50))]
    cmd += ["--json", "number,title,state,author,createdAt,headRefName"]
    data = await _gh_json(cmd)
    if not data:
        return "No pull requests found."
    lines = []
    for pr in data:
        author = pr.get("author", {}).get("login", "?")
        branch = pr.get("headRefName", "?")
        lines.append(f"#{pr['number']} ({pr['state']}) {pr['title']} [{branch}] — @{author}")
    return "\n".join(lines)


@_tool(
    "get_pull_request",
    "Get details of a specific pull request.",
    {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "Repository (owner/name)"},
            "number": {"type": "integer", "description": "PR number"},
        },
        "required": ["repo", "number"],
    },
)
async def get_pull_request(args: dict) -> str:
    return await _gh(["pr", "view", str(args["number"]), "-R", args["repo"]])


@_tool(
    "create_pull_request",
    "Create a new pull request.",
    {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "Repository (owner/name)"},
            "title": {"type": "string", "description": "PR title"},
            "body": {"type": "string", "description": "PR description (markdown)"},
            "head": {"type": "string", "description": "Source branch"},
            "base": {"type": "string", "description": "Target branch (default: main)"},
        },
        "required": ["repo", "title", "head"],
    },
)
async def create_pull_request(args: dict) -> str:
    cmd = [
        "pr", "create", "-R", args["repo"],
        "--title", args["title"],
        "--head", args["head"],
        "--base", args.get("base", "main"),
    ]
    if args.get("body"):
        cmd += ["--body", args["body"]]
    return await _gh(cmd)


@_tool(
    "get_file_contents",
    "Get the contents of a file from a GitHub repository.",
    {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "Repository (owner/name)"},
            "path": {"type": "string", "description": "File path in the repo"},
            "ref": {"type": "string", "description": "Branch, tag, or commit SHA (default: HEAD)"},
        },
        "required": ["repo", "path"],
    },
)
async def get_file_contents(args: dict) -> str:
    ref = args.get("ref", "HEAD")
    endpoint = f"repos/{args['repo']}/contents/{args['path']}?ref={ref}"
    raw = await _gh(["api", endpoint, "--jq", ".content"])
    # GitHub API returns base64-encoded content
    import base64 as b64
    try:
        return b64.b64decode(raw.strip().replace("\n", "")).decode("utf-8")
    except Exception:
        return raw


@_tool(
    "list_repo_files",
    "List files in a repository directory.",
    {
        "type": "object",
        "properties": {
            "repo": {"type": "string", "description": "Repository (owner/name)"},
            "path": {"type": "string", "description": "Directory path (default: root)"},
            "ref": {"type": "string", "description": "Branch, tag, or commit SHA (default: HEAD)"},
        },
        "required": ["repo"],
    },
)
async def list_repo_files(args: dict) -> str:
    path = args.get("path", "")
    ref = args.get("ref", "HEAD")
    endpoint = f"repos/{args['repo']}/contents/{path}?ref={ref}"
    raw = await _gh(["api", endpoint])
    data = json.loads(raw) if raw.strip() else []
    if isinstance(data, dict):
        # Single file, not a directory
        return f"{data.get('name', '?')} ({data.get('type', '?')}, {data.get('size', '?')} bytes)"
    lines = []
    for item in sorted(data, key=lambda x: (x.get("type") != "dir", x.get("name", "").lower())):
        prefix = "[DIR] " if item.get("type") == "dir" else "      "
        size = f" ({item['size']}B)" if item.get("size") else ""
        lines.append(f"{prefix}{item['name']}{size}")
    return "\n".join(lines) if lines else "(empty)"


# ---------------------------------------------------------------------------
# Server wiring
# ---------------------------------------------------------------------------

def _build_server():
    from mcp.server import Server
    from mcp.types import TextContent, Tool

    server = Server("noo-github")

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
        except Exception as exc:
            logger.warning("tool error: %s — %s", name, exc)
            return [TextContent(type="text", text=f"Error: {exc}")]

    return server


async def _run_stdio(server) -> None:
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    if not shutil.which("gh"):
        print("Error: 'gh' CLI not found. Install from https://cli.github.com", file=sys.stderr)
        sys.exit(1)

    try:
        import mcp  # noqa: F401
    except ImportError:
        print("Error: mcp SDK not installed. pip install 'noomesh[mcp]'", file=sys.stderr)
        sys.exit(1)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s", stream=sys.stderr)

    server = _build_server()
    asyncio.run(_run_stdio(server))


if __name__ == "__main__":
    main()
