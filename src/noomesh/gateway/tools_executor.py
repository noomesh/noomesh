# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tool execution for agentic loop.

Safely executes tools called by the LLM and returns results.
"""

from __future__ import annotations

import asyncio
import re
import sys
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx
import structlog

logger = structlog.get_logger()


@dataclass
class ToolResult:
    """Result of tool execution."""
    success: bool
    output: str
    error: Optional[str] = None

    def to_prompt(self) -> str:
        """Format result for inclusion in prompt.

        Moderates output through the security module to redact prompt
        injection, XSS, and other malicious patterns before the text
        enters LLM context.
        """
        output = self.output
        try:
            from .security import moderate_external_content
            output = moderate_external_content(output, source="tool_result")
        except ImportError:
            pass
        if self.success:
            return f"Tool output:\n```\n{output}\n```"
        else:
            return f"Tool error: {self.error}\n{output}"


class ToolExecutor(ABC):
    """Base class for tool executors."""

    @abstractmethod
    async def execute(self, **kwargs) -> ToolResult:
        """Execute the tool with given arguments."""
        pass


class PythonExecutor(ToolExecutor):
    """Execute Python code safely — via Docker sandbox if configured, else local subprocess."""

    def __init__(
        self,
        timeout: float = 30.0,
        max_output: int = 10000,
        sandbox_url: Optional[str] = None,
    ):
        self.timeout = timeout
        self.max_output = max_output
        self.sandbox_url = sandbox_url

    async def execute(self, code: str, **kwargs) -> ToolResult:
        """Run Python code and capture output."""
        logger.info("python_executor_start", code_length=len(code),
                     sandbox=bool(self.sandbox_url))

        if self.sandbox_url:
            return await self._execute_sandbox(code, **kwargs)
        return await self._execute_local(code, **kwargs)

    async def _execute_sandbox(self, code: str, **kwargs) -> ToolResult:
        """Route execution to the Docker sandbox container."""
        from ..tools.python_tool import sandbox_exec_url, sandbox_tls_kwargs

        timeout = float(kwargs.get("timeout", self.timeout))
        cwd = kwargs.get("cwd")
        try:
            url = sandbox_exec_url(self.sandbox_url)
            async with httpx.AsyncClient(timeout=timeout + 5, **sandbox_tls_kwargs()) as client:
                resp = await client.post(
                    url,
                    json={"code": code, "timeout": timeout, "cwd": cwd},
                )
                resp.raise_for_status()
                payload = resp.json()
                output = payload.get("output", "(no output)")
                if len(output) > self.max_output:
                    output = output[:self.max_output] + "\n... (truncated)"
                logger.info("python_executor_sandbox_success", output_length=len(output))
                return ToolResult(success=True, output=output)
        except httpx.TimeoutException:
            return ToolResult(
                success=False, output="",
                error=f"Sandbox execution timed out after {timeout}s",
            )
        except Exception as e:
            logger.error("python_executor_sandbox_error", error=str(e))
            return ToolResult(
                success=False, output="",
                error=f"Sandbox execution failed: {e}",
            )

    async def _execute_local(self, code: str, **kwargs) -> ToolResult:
        """Run code in a local subprocess (fallback when no sandbox configured)."""
        try:
            # Write code to temp file
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.py',
                delete=False
            ) as f:
                f.write(code)
                temp_path = f.name

            try:
                # Run in subprocess with timeout
                proc = await asyncio.create_subprocess_exec(
                    sys.executable, temp_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=tempfile.gettempdir()
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=self.timeout
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    return ToolResult(
                        success=False,
                        output="",
                        error=f"Execution timed out after {self.timeout}s"
                    )

                output = stdout.decode('utf-8', errors='replace')
                errors = stderr.decode('utf-8', errors='replace')

                # Truncate if too long
                if len(output) > self.max_output:
                    output = output[:self.max_output] + "\n... (truncated)"

                if proc.returncode != 0:
                    return ToolResult(
                        success=False,
                        output=output,
                        error=errors or f"Exit code {proc.returncode}"
                    )

                combined = output
                if errors:
                    combined += f"\nStderr: {errors}"

                logger.info("python_executor_success", output_length=len(combined))
                return ToolResult(success=True, output=combined)

            finally:
                # Clean up temp file
                Path(temp_path).unlink(missing_ok=True)

        except Exception as e:
            logger.error("python_executor_error", error=str(e))
            return ToolResult(
                success=False,
                output="",
                error=f"Execution failed: {str(e)}"
            )


class WebSearchExecutor(ToolExecutor):
    """Execute web searches using DuckDuckGo."""

    def __init__(self, max_results: int = 5, timeout: float = 10.0):
        self.max_results = max_results
        self.timeout = timeout

    @staticmethod
    def _sanitize(text: str) -> str:
        """Moderate search snippet through the security module."""
        if not text:
            return ""
        try:
            from .security import moderate_external_content
            return moderate_external_content(text, source="web_search")
        except ImportError:
            import html as _html
            return re.sub(r"<[^>]+>", "", _html.unescape(text)).strip()

    async def execute(self, query: str, **kwargs) -> ToolResult:
        """Search the web and return results."""
        logger.info("web_search_start", query=query)

        try:
            try:
                from ddgs import DDGS
            except ImportError:
                return ToolResult(
                    success=False,
                    output="",
                    error="Web search not available (ddgs not installed). pip install ddgs"
                )

            def search_sync():
                ddgs = DDGS()
                return list(ddgs.text(query, max_results=self.max_results))

            results = await asyncio.get_event_loop().run_in_executor(
                None, search_sync
            )

            if not results:
                return ToolResult(success=True, output="No results found.")

            # Format and sanitize results
            output_lines = [f"Search results for: {query}\n"]
            for i, r in enumerate(results, 1):
                title = self._sanitize(r.get("title", "No title"))
                url = r.get("href", "No URL")
                snippet = self._sanitize(r.get("body", "No description"))[:300]
                output_lines.append(f"{i}. {title}")
                output_lines.append(f"   URL: {url}")
                output_lines.append(f"   {snippet}")
                output_lines.append("")

            output = "\n".join(output_lines)
            logger.info("web_search_success", num_results=len(results))
            return ToolResult(success=True, output=output)

        except Exception as e:
            logger.error("web_search_error", error=str(e))
            return ToolResult(
                success=False,
                output="",
                error=f"Search failed: {str(e)}"
            )


class FileExecutor(ToolExecutor):
    """Read and write files within allowed paths."""

    def __init__(
        self,
        allowed_paths: Optional[list[Path]] = None,
        writable_paths: Optional[list[Path]] = None,
    ):
        # Start with temp directory and cwd, then extend with caller-supplied paths.
        self.allowed_paths = [
            Path(tempfile.gettempdir()),
            Path.cwd(),
        ]
        if allowed_paths:
            self.allowed_paths.extend(allowed_paths)
        self.writable_paths: list[Path] = list(writable_paths) if writable_paths else []

    def _is_path_allowed(self, path: Path) -> bool:
        """Check if path is within allowed directories."""
        resolved = path.resolve()
        return any(
            resolved.is_relative_to(allowed.resolve())
            for allowed in self.allowed_paths
        )

    @staticmethod
    def _workspace_root() -> Optional[Path]:
        """The configured workspace mount (e.g. /workspace), or None."""
        try:
            from ..config import get_config
            ws = get_config().workspace.path
            if ws:
                return Path(ws)
        except Exception:
            pass
        return None

    def _is_writable(self, path: Path) -> bool:
        """Check if path is within a writable directory."""
        if not self.writable_paths:
            return False
        resolved = path.resolve()
        return any(
            resolved.is_relative_to(wp.resolve())
            for wp in self.writable_paths
        )

    async def execute(
        self,
        action: str,
        path: str,
        content: Optional[str] = None,
        **kwargs
    ) -> ToolResult:
        """Read or write a file."""
        logger.info("file_executor_start", action=action, path=path)

        # Small models name the write payload inconsistently — gemma has
        # sent "text", "contents", "data" and "body" for the same field.
        # Accept the aliases rather than failing a round trip (each retry
        # costs a fresh exec-approval under approval mode).
        if content is None:
            for alias in ("text", "contents", "data", "body", "file_content"):
                value = kwargs.get(alias)
                if isinstance(value, str):
                    content = value
                    break

        try:
            file_path = Path(path)

            if not self._is_path_allowed(file_path):
                return ToolResult(
                    success=False,
                    output="",
                    error=f"Access denied: {path} is outside allowed directories"
                )

            if action == "read":
                if not file_path.exists():
                    return ToolResult(
                        success=False,
                        output="",
                        error=f"File not found: {path}"
                    )

                text = file_path.read_text(encoding='utf-8', errors='replace')
                # Truncate large files
                if len(text) > 50000:
                    text = text[:50000] + "\n... (truncated)"

                return ToolResult(success=True, output=text)

            elif action == "write":
                # Workspace convention (operator, 2026-08-09): ad-hoc
                # user-requested files land in <workspace>/requested/, not
                # the workspace root. Only bare-root writes are redirected —
                # an explicit subdirectory (research/, activity/, …) is
                # respected as chosen.
                workspace_root = self._workspace_root()
                if workspace_root and file_path.parent == workspace_root:
                    file_path = workspace_root / "requested" / file_path.name
                    path = str(file_path)

                if not self._is_writable(file_path):
                    return ToolResult(
                        success=False,
                        output="",
                        error=f"Write denied: {path} is not in a writable directory. "
                              "Toggle the directory to writable via the dashboard first.",
                    )

                if content is None:
                    return ToolResult(
                        success=False,
                        output="",
                        error="No content provided for write operation"
                    )

                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_text(content, encoding='utf-8')
                # Report workspace-relative ("requested/foo.txt") — that is
                # the name the operator sees in their synced folder.
                display = path
                if workspace_root:
                    try:
                        display = str(file_path.relative_to(workspace_root))
                    except ValueError:
                        pass
                return ToolResult(
                    success=True,
                    output=f"File written: {display} ({len(content)} bytes)"
                )

            elif action == "list":
                if not file_path.is_dir():
                    return ToolResult(
                        success=False,
                        output="",
                        error=f"Not a directory: {path}"
                    )

                files = list(file_path.iterdir())[:100]  # Limit entries
                output = "\n".join(
                    f"{'[D]' if f.is_dir() else '[F]'} {f.name}"
                    for f in sorted(files)
                )
                return ToolResult(success=True, output=output or "(empty directory)")

            else:
                return ToolResult(
                    success=False,
                    output="",
                    error=f"Unknown action: {action}. Use 'read', 'write', or 'list'"
                )

        except Exception as e:
            logger.error("file_executor_error", error=str(e))
            return ToolResult(
                success=False,
                output="",
                error=f"File operation failed: {str(e)}"
            )


class RAGQueryExecutor(ToolExecutor):
    """Query the PageIndex RAG system for document-grounded evidence."""

    def __init__(self, rag=None):
        self.rag = rag

    async def execute(
        self,
        query: str,
        strategy: str = "hybrid",
        **kwargs,
    ) -> ToolResult:
        """Query PageIndex RAG and return evidence with citations."""
        if not self.rag or not getattr(self.rag, "_started", False):
            return ToolResult(
                success=False,
                output="",
                error="PageIndex RAG is not initialized",
            )

        logger.info("rag_query_executor_start", query=query, strategy=strategy)
        try:
            response = await self.rag.query(query, strategy=strategy)

            parts: list[str] = []
            parts.append(f"Strategy: {response.strategy_used} | Intent: {response.intent}")

            # Verification summary
            if response.verification:
                v = response.verification
                parts.append(
                    f"Verification: {v.status} (confidence: {v.confidence:.0%}, "
                    f"supported: {len(v.supported_claims)}, unsupported: {len(v.unsupported_claims)})"
                )

            # Hypotheses from graph
            if response.hypotheses:
                parts.append("\nGraph hypotheses:")
                for h in response.hypotheses[:5]:
                    parts.append(f"  [{h.confidence:.0%}] {' > '.join(h.path[:4])}: {h.description[:80]}")

            # Citations with excerpts
            if response.citations:
                parts.append(f"\nCitations ({len(response.citations)} sources):")
                for i, c in enumerate(response.citations, 1):
                    excerpt = c.excerpt[:300] if c.excerpt else ""
                    parts.append(
                        f"\n[{i}] {c.title} (page {c.page_no}, confidence: {c.confidence:.0%})\n{excerpt}"
                    )
            else:
                parts.append("\nNo citations found.")

            # Full evidence text for grounding
            if response.evidence:
                parts.append("\n--- Full evidence pages ---")
                for ep in response.evidence[:3]:
                    parts.append(f"\n## {ep.title} — page {ep.page_no}")
                    parts.append(ep.page_text[:1500])

            output = "\n".join(parts)
            logger.info("rag_query_executor_success", citations=len(response.citations))
            return ToolResult(success=True, output=output)

        except Exception as e:
            logger.error("rag_query_executor_error", error=str(e))
            return ToolResult(
                success=False,
                output="",
                error=f"RAG query failed: {str(e)}",
            )


class SkillToolExecutor(ToolExecutor):
    """Bridge that exposes a registered sandbox capability as an agent tool.

    Routes through the pipeline capability layer
    (``pipeline.sandbox_capabilities.execute_sandbox_capability``) so the
    ``skill_execute`` tool / ``worker.tool.skill`` subject and pipeline
    Steps share one execution path. Response shape is byte-compatible with
    the pre-fold implementation (including the "Unknown skill: <name>" and
    "Skill system not available" error strings).
    """

    async def execute(self, skill_name: str, **kwargs) -> ToolResult:
        """Execute a sandbox capability by name, passing remaining kwargs as inputs."""
        try:
            from ..pipeline.sandbox_capabilities import execute_sandbox_capability
        except Exception:
            return ToolResult(
                success=False, output="",
                error="Skill system not available",
            )

        node_id = kwargs.pop("node_id", None)
        try:
            result = await execute_sandbox_capability(skill_name, kwargs, node_id=node_id)
        except Exception as e:
            return ToolResult(success=False, output="", error=str(e))
        if result.success:
            from .. import json_fast as _json
            return ToolResult(
                success=True,
                output=_json.dumps(result.output, indent=2, default=str),
            )
        return ToolResult(success=False, output="", error=result.error)


class BrowserToolExecutor(ToolExecutor):
    """Bridge that exposes the browser automation tool to the agent."""

    def __init__(self):
        self._tool = None

    def _ensure_loaded(self):
        if self._tool is None:
            try:
                from ..tools.browser_tool import get_browser_tool
                self._tool = get_browser_tool()
            except Exception:
                pass

    async def execute(self, action: str, **kwargs) -> ToolResult:
        """Execute a browser action (navigate, click, type, extract, screenshot, execute, stop)."""
        self._ensure_loaded()
        if not self._tool:
            return ToolResult(
                success=False, output="",
                error="Browser tool not available",
            )

        try:
            result = await self._tool.execute(action=action, **kwargs)
        except Exception as exc:
            return ToolResult(success=False, output="", error=f"Browser action failed: {exc}")

        if "error" in result:
            return ToolResult(success=False, output="", error=result["error"])

        from .. import json_fast as _json
        return ToolResult(success=True, output=_json.dumps(result, indent=2, default=str))


class ToolRegistry:
    """Registry of available tool executors."""

    def __init__(self):
        # Pull config for file paths and sandbox URL
        file_allowed: list[Path] = []
        file_writable: list[Path] = []
        sandbox_url: Optional[str] = None
        try:
            from ..config import get_file_allowed_paths, get_config
            from ..secrets import get_secret
            file_allowed = [Path(p) for p in get_file_allowed_paths()]
            cfg = get_config()
            if cfg.watched_folders.enabled:
                file_writable = [Path(p) for p in cfg.watched_folders.writable_mount_paths]
            if cfg.workspace.path:
                file_writable.append(Path(cfg.workspace.path))
            sandbox_url = get_secret("NOO_SANDBOX_URL") or cfg.sandbox.url
        except Exception:
            pass

        self._file_allowed_display = [str(p) for p in file_allowed]
        # NOTE: "local_files" is deliberately NOT registered.
        # File I/O executes natively in the Rust gateway
        # (gateway-rust/src/local_files.rs) — zero hops between the
        # exec-approval gate and the write. The FileExecutor class above
        # stays as the behavioral reference (its pinning tests define
        # parity), but nothing dispatches to it in production. `_` keeps
        # the writable-path resolution exercised so config errors surface.
        _ = (FileExecutor, file_writable)
        # "python_tool" is also NOT registered (port-lane item 3): the Rust
        # gateway POSTs to the sandbox /exec itself — the trellion layer
        # added only a proxy hop, and the in-process local-subprocess
        # fallback (sandbox_url=None) is exactly the path that must not
        # exist. PythonExecutor stays as the behavioral reference.
        _ = (PythonExecutor, sandbox_url)
        self.executors: dict[str, ToolExecutor] = {
            "web_search": WebSearchExecutor(),
            "skill_execute": SkillToolExecutor(),
            "browser": BrowserToolExecutor(),
        }

    def register(self, name: str, executor: ToolExecutor) -> None:
        """Register an additional tool executor."""
        self.executors[name] = executor

    def get_executor(self, tool_name: str) -> Optional[ToolExecutor]:
        """Get executor for a tool."""
        return self.executors.get(tool_name)

    async def execute_tool(self, tool_name: str, **kwargs) -> ToolResult:
        """Execute a tool by name."""
        executor = self.get_executor(tool_name)
        if not executor:
            return ToolResult(
                success=False,
                output="",
                error=f"Unknown tool: {tool_name}"
            )

        return await executor.execute(**kwargs)

    def get_tool_definitions(self) -> list[dict]:
        """Get tool definitions for prompt formatting."""
        defs = [
            {
                "name": "python_tool",
                "description": "Execute Python code and return the output. Use for calculations, data processing, or any programmatic task.",
                "parameters": {
                    "code": "Python code to execute (required)"
                }
            },
            {
                "name": "web_search",
                "description": "Search the web for information. Use for current events, facts, or any information not in training data.",
                "parameters": {
                    "query": "Search query string (required)"
                }
            },
            {
                "name": "local_files",
                "description": (
                    "Read, write, or list files in allowed directories."
                    + (f" Allowed directories: {', '.join(self._file_allowed_display)}"
                       if self._file_allowed_display else "")
                ),
                "parameters": {
                    "action": "One of: read, write, list (required)",
                    "path": (
                        "File or directory path (required)"
                        + (f". Must be under: {', '.join(self._file_allowed_display)}"
                           if self._file_allowed_display else "")
                    ),
                    "content": "Content to write (required for write action)"
                }
            },
        ]
        # RAG tools (rag_query, rag_ingest) are now MCP-only (noo_rag_query, noo_rag_ingest).
        # No ToolRegistry definitions needed — coordinator uses MCP tools exclusively for RAG.
        # Add skill_execute tool
        if "skill_execute" in self.executors:
            defs.append({
                "name": "skill_execute",
                "description": (
                    "Run a containerized skill. Skills are sandboxed capabilities "
                    "like text summarization, file conversion, or data extraction. "
                    "Pass the skill name and its required inputs as keyword arguments."
                ),
                "parameters": {
                    "skill_name": "Name of the skill to run (required)",
                    "**inputs": "Skill-specific inputs (see skill info for details)",
                }
            })
        # Add browser tool
        if "browser" in self.executors:
            defs.append({
                "name": "browser",
                "description": (
                    "Browse the web, interact with pages, and extract information. "
                    "Runs a sandboxed Playwright browser in a Docker container. "
                    "Actions: navigate (go to URL), click (CSS selector), type (fill input), "
                    "extract (get text/attributes from elements), screenshot (capture page), "
                    "execute (run JavaScript), stop (end session)."
                ),
                "parameters": {
                    "action": "One of: navigate, click, type, extract, screenshot, execute, stop (required)",
                    "url": "URL to navigate to (for navigate action)",
                    "selector": "CSS selector (for click, type, extract actions)",
                    "text": "Text to type (for type action)",
                    "script": "JavaScript to execute (for execute action)",
                    "attribute": "Element attribute to extract (for extract action, optional)",
                    "all_matches": "Extract all matching elements (for extract action, default false)",
                }
            })
        return defs


# Global registry instance
_tool_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    """Get or create the global tool registry."""
    global _tool_registry
    if _tool_registry is None:
        _tool_registry = ToolRegistry()
    return _tool_registry
