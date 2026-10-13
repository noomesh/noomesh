# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Unit tests for PAI GitHub MCP Server."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from noomesh.mcp.github_server import (
    TOOLS,
    _HANDLERS,
    _gh,
    _gh_json,
    create_issue,
    create_pull_request,
    get_file_contents,
    get_issue,
    get_pull_request,
    get_repo_info,
    list_issues,
    list_pull_requests,
    list_repo_files,
    search_repositories,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_proc(stdout: str = "", stderr: str = "", returncode: int = 0):
    """Create a mock subprocess result."""
    proc = AsyncMock()
    proc.communicate.return_value = (stdout.encode(), stderr.encode())
    proc.returncode = returncode
    proc.kill = AsyncMock()
    return proc


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

class TestToolRegistry:
    def test_tools_registered(self):
        assert len(TOOLS) >= 10

    def test_all_tools_have_handlers(self):
        for t in TOOLS:
            assert t["name"] in _HANDLERS, f"Missing handler for {t['name']}"

    def test_tool_has_input_schema(self):
        for t in TOOLS:
            assert "input_schema" in t
            assert t["input_schema"]["type"] == "object"


# ---------------------------------------------------------------------------
# _gh / _gh_json helpers
# ---------------------------------------------------------------------------

class TestGhHelpers:
    @pytest.mark.asyncio
    async def test_gh_returns_stdout(self):
        proc = _mock_proc(stdout="output text\n")
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            result = await _gh(["status"])
        assert result == "output text\n"

    @pytest.mark.asyncio
    async def test_gh_raises_on_nonzero_exit(self):
        proc = _mock_proc(stderr="not found", returncode=1)
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            with pytest.raises(RuntimeError, match="failed"):
                await _gh(["repo", "view", "bad/repo"])

    @pytest.mark.asyncio
    async def test_gh_timeout(self):
        proc = AsyncMock()
        proc.communicate.side_effect = TimeoutError("timed out")
        proc.kill = AsyncMock()
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            with patch("noomesh.mcp.github_server.asyncio.wait_for", side_effect=TimeoutError("timed out")):
                # _gh catches asyncio.TimeoutError specifically
                import asyncio
                with patch("noomesh.mcp.github_server.asyncio.wait_for", side_effect=asyncio.TimeoutError()):
                    with pytest.raises(TimeoutError, match="timed out"):
                        await _gh(["slow", "command"], timeout=0.1)

    @pytest.mark.asyncio
    async def test_gh_json_parses_output(self):
        data = [{"name": "repo1"}, {"name": "repo2"}]
        proc = _mock_proc(stdout=json.dumps(data))
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            result = await _gh_json(["search", "repos"])
        assert result == data

    @pytest.mark.asyncio
    async def test_gh_json_empty_output(self):
        proc = _mock_proc(stdout="")
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            result = await _gh_json(["search", "repos"])
        assert result == {}


# ---------------------------------------------------------------------------
# Search repositories
# ---------------------------------------------------------------------------

class TestSearchRepositories:
    @pytest.mark.asyncio
    async def test_search_repos_formats_results(self):
        repos = [
            {"fullName": "org/repo1", "stargazersCount": 100, "description": "A tool", "url": "https://github.com/org/repo1"},
            {"fullName": "org/repo2", "stargazersCount": 50, "description": "Another", "url": "https://github.com/org/repo2"},
        ]
        proc = _mock_proc(stdout=json.dumps(repos))
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            result = await search_repositories({"query": "python mcp"})
        assert "org/repo1" in result
        assert "100 stars" in result
        assert "org/repo2" in result

    @pytest.mark.asyncio
    async def test_search_repos_no_results(self):
        proc = _mock_proc(stdout="[]")
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            result = await search_repositories({"query": "nonexistent"})
        assert "No repositories found" in result

    @pytest.mark.asyncio
    async def test_search_repos_limit_capped(self):
        proc = _mock_proc(stdout="[]")
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
            await search_repositories({"query": "test", "limit": 100})
            # limit should be capped to 30
            call_args = mock_exec.call_args[0]
            limit_idx = list(call_args).index("--limit")
            assert call_args[limit_idx + 1] == "30"


# ---------------------------------------------------------------------------
# Repo info
# ---------------------------------------------------------------------------

class TestGetRepoInfo:
    @pytest.mark.asyncio
    async def test_get_repo_info(self):
        proc = _mock_proc(stdout="org/repo — A great repo\nStars: 42")
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            result = await get_repo_info({"repo": "org/repo"})
        assert "org/repo" in result


# ---------------------------------------------------------------------------
# Issues
# ---------------------------------------------------------------------------

class TestIssues:
    @pytest.mark.asyncio
    async def test_list_issues(self):
        issues = [
            {"number": 1, "title": "Bug report", "state": "OPEN", "author": {"login": "user1"}, "labels": [{"name": "bug"}]},
            {"number": 2, "title": "Feature req", "state": "OPEN", "author": {"login": "user2"}, "labels": []},
        ]
        proc = _mock_proc(stdout=json.dumps(issues))
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            result = await list_issues({"repo": "org/repo"})
        assert "#1" in result
        assert "Bug report" in result
        assert "[bug]" in result
        assert "#2" in result
        assert "@user1" in result

    @pytest.mark.asyncio
    async def test_list_issues_no_results(self):
        proc = _mock_proc(stdout="[]")
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            result = await list_issues({"repo": "org/repo"})
        assert "No issues found" in result

    @pytest.mark.asyncio
    async def test_list_issues_with_filters(self):
        proc = _mock_proc(stdout="[]")
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
            await list_issues({"repo": "org/repo", "state": "closed", "labels": ["bug", "critical"], "limit": 5})
            call_args = list(mock_exec.call_args[0])
            assert "--state" in call_args
            state_idx = call_args.index("--state")
            assert call_args[state_idx + 1] == "closed"
            assert call_args.count("--label") == 2

    @pytest.mark.asyncio
    async def test_get_issue(self):
        proc = _mock_proc(stdout="Issue #42: Fix the thing\nBody: Details here")
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            result = await get_issue({"repo": "org/repo", "number": 42})
        assert "Fix the thing" in result

    @pytest.mark.asyncio
    async def test_create_issue(self):
        proc = _mock_proc(stdout="https://github.com/org/repo/issues/99")
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
            result = await create_issue({"repo": "org/repo", "title": "New bug", "body": "Details", "labels": ["bug"]})
            call_args = list(mock_exec.call_args[0])
            assert "--title" in call_args
            assert "--body" in call_args
            assert "--label" in call_args
        assert "issues/99" in result


# ---------------------------------------------------------------------------
# Pull Requests
# ---------------------------------------------------------------------------

class TestPullRequests:
    @pytest.mark.asyncio
    async def test_list_pull_requests(self):
        prs = [
            {"number": 10, "title": "Add feature", "state": "OPEN", "author": {"login": "dev"}, "headRefName": "feature-branch"},
        ]
        proc = _mock_proc(stdout=json.dumps(prs))
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            result = await list_pull_requests({"repo": "org/repo"})
        assert "#10" in result
        assert "Add feature" in result
        assert "[feature-branch]" in result
        assert "@dev" in result

    @pytest.mark.asyncio
    async def test_list_pull_requests_no_results(self):
        proc = _mock_proc(stdout="[]")
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            result = await list_pull_requests({"repo": "org/repo"})
        assert "No pull requests found" in result

    @pytest.mark.asyncio
    async def test_get_pull_request(self):
        proc = _mock_proc(stdout="PR #10: Add feature\nMergeable: true")
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            result = await get_pull_request({"repo": "org/repo", "number": 10})
        assert "Add feature" in result

    @pytest.mark.asyncio
    async def test_create_pull_request(self):
        proc = _mock_proc(stdout="https://github.com/org/repo/pull/11")
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
            result = await create_pull_request({
                "repo": "org/repo",
                "title": "New PR",
                "head": "my-branch",
                "base": "develop",
                "body": "Changes",
            })
            call_args = list(mock_exec.call_args[0])
            assert "--base" in call_args
            base_idx = call_args.index("--base")
            assert call_args[base_idx + 1] == "develop"
        assert "pull/11" in result

    @pytest.mark.asyncio
    async def test_create_pull_request_default_base(self):
        proc = _mock_proc(stdout="https://github.com/org/repo/pull/12")
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
            await create_pull_request({"repo": "org/repo", "title": "PR", "head": "branch"})
            call_args = list(mock_exec.call_args[0])
            base_idx = call_args.index("--base")
            assert call_args[base_idx + 1] == "main"


# ---------------------------------------------------------------------------
# File contents
# ---------------------------------------------------------------------------

class TestFileContents:
    @pytest.mark.asyncio
    async def test_get_file_contents(self):
        import base64
        content = base64.b64encode(b"print('hello')").decode()
        proc = _mock_proc(stdout=content + "\n")
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            result = await get_file_contents({"repo": "org/repo", "path": "main.py"})
        assert "print('hello')" in result

    @pytest.mark.asyncio
    async def test_get_file_contents_with_ref(self):
        import base64
        content = base64.b64encode(b"v2 content").decode()
        proc = _mock_proc(stdout=content + "\n")
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc) as mock_exec:
            await get_file_contents({"repo": "org/repo", "path": "file.py", "ref": "v2.0"})
            call_args = list(mock_exec.call_args[0])
            # Should include ref=v2.0 in the API endpoint
            api_arg = [a for a in call_args if "ref=" in str(a)]
            assert any("v2.0" in str(a) for a in api_arg)


# ---------------------------------------------------------------------------
# List repo files
# ---------------------------------------------------------------------------

class TestListRepoFiles:
    @pytest.mark.asyncio
    async def test_list_repo_files_directory(self):
        items = [
            {"name": "src", "type": "dir", "size": 0},
            {"name": "README.md", "type": "file", "size": 1234},
            {"name": "main.py", "type": "file", "size": 567},
        ]
        proc = _mock_proc(stdout=json.dumps(items))
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            result = await list_repo_files({"repo": "org/repo"})
        assert "[DIR]" in result
        assert "src" in result
        assert "README.md" in result
        # Dirs should come before files
        dir_pos = result.index("src")
        file_pos = result.index("README.md")
        assert dir_pos < file_pos

    @pytest.mark.asyncio
    async def test_list_repo_files_single_file(self):
        item = {"name": "main.py", "type": "file", "size": 500}
        proc = _mock_proc(stdout=json.dumps(item))
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            result = await list_repo_files({"repo": "org/repo", "path": "main.py"})
        assert "main.py" in result
        assert "500 bytes" in result

    @pytest.mark.asyncio
    async def test_list_repo_files_empty(self):
        proc = _mock_proc(stdout="[]")
        with patch("noomesh.mcp.github_server.asyncio.create_subprocess_exec", return_value=proc):
            result = await list_repo_files({"repo": "org/repo", "path": "empty_dir"})
        assert "(empty)" in result
