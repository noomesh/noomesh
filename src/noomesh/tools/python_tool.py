# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

from __future__ import annotations

import os
import subprocess
import sys
from typing import Dict, Optional

import httpx
import structlog

from .base import ToolSpec
from ..validation import ToolInputValidator, ValidationError

logger = structlog.get_logger(__name__)


def _local_exec_allowed() -> bool:
    """In-process python_exec is arbitrary RCE on the host, so it's OFF unless an
    operator explicitly opts in (dev only). The safe path is the sandbox."""
    return os.getenv("NOO_ALLOW_LOCAL_PYTHON_EXEC", "").strip().lower() in ("1", "true", "yes")


def build_python_tool(sandbox_url: Optional[str] = None) -> ToolSpec:
    return ToolSpec(
        name="python_exec",
        description="Run a Python snippet (local or sandbox if configured) and return stdout/stderr.",
        parameters={
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Python code to execute."},
                "timeout": {
                    "type": "number",
                    "description": "Timeout in seconds (default 10).",
                },
                "cwd": {
                    "type": "string",
                    "description": "Working directory (optional).",
                },
            },
            "required": ["code"],
        },
        handler=lambda args: _run_python(args, sandbox_url),
    )

def _run_python(args: Dict, sandbox_url: Optional[str]) -> str:
    code = args.get("code")
    if not code:
        return "Error: 'code' is required."

    # Validate and sanitize code
    try:
        # Sandbox allows dangerous operations, local execution is more restrictive
        allow_dangerous = sandbox_url is not None
        code = ToolInputValidator.sanitize_code(code, allow_dangerous=allow_dangerous)
    except ValidationError as e:
        return f"Error: Code validation failed: {e}"

    timeout = float(args.get("timeout", 10))
    cwd = args.get("cwd")

    # Validate path if provided
    if cwd:
        try:
            cwd = ToolInputValidator.sanitize_path(cwd, allow_absolute=True)
        except ValidationError as e:
            return f"Error: Path validation failed: {e}"

    if sandbox_url:
        # Isolated execution — the sandbox container is the security boundary.
        return _run_via_sandbox(sandbox_url, code, timeout, cwd)

    # No sandbox configured. Running the model's Python IN-PROCESS is arbitrary
    # code execution on the gateway host (the regex denylist is bypassable and
    # not a real boundary), so refuse by default (H-I2). Operators can set
    # NOO_SANDBOX_URL for isolated execution, or explicitly opt into unsafe
    # local exec for development with NOO_ALLOW_LOCAL_PYTHON_EXEC=1.
    if not _local_exec_allowed():
        logger.warning("python_exec.refused_no_sandbox")
        return (
            "Error: python_exec is disabled — no sandbox is configured. "
            "Set NOO_SANDBOX_URL to run code in the isolated sandbox, or set "
            "NOO_ALLOW_LOCAL_PYTHON_EXEC=1 to explicitly permit (unsafe) "
            "in-process execution."
        )

    logger.warning(
        "python_exec.local_in_process",
        note="running untrusted code in-process via NOO_ALLOW_LOCAL_PYTHON_EXEC",
    )
    try:
        result = subprocess.run(
            [sys.executable, "-"],
            input=code,
            text=True,
            capture_output=True,
            timeout=timeout,
            cwd=cwd,
        )
    except subprocess.TimeoutExpired:
        return f"Error: Python execution timed out after {timeout:.1f}s."
    except Exception as exc:
        return f"Error: {exc}"

    output = []
    if result.stdout:
        output.append("[stdout]\n" + result.stdout.strip())
    if result.stderr:
        output.append("[stderr]\n" + result.stderr.strip())
    if not output:
        output.append("(no output)")
    return "\n\n".join(output)


def _run_via_sandbox(
    sandbox_url: str, code: str, timeout: float, cwd: Optional[str]
) -> str:
    url = sandbox_url.rstrip("/") + "/exec"
    try:
        response = httpx.post(
            url,
            json={"code": code, "timeout": timeout, "cwd": cwd},
            timeout=timeout + 5,
        )
        response.raise_for_status()
        payload = response.json()
        return payload.get("output", "(no output)")
    except Exception as exc:
        return f"Error: sandbox call failed: {exc}"
