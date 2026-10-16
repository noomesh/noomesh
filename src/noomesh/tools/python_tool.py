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


def _inside_the_stack() -> bool:
    """True in a container or under the sanctioned launcher: the deployed stack.

    The in-process hatch is a source-checkout development tool. Inside the
    stack it would run model-written code with the worker's credentials and
    network, so no env value opens it there. This narrows the hatch instead
    of removing it: a developer running from a checkout is unaffected.

    Why a refusal and not a posture gate: posture is gateway-side state and the
    Python worker has no gateway lookup at tool-call time; and a gate cannot be
    set before the release that introduces it, so an install carrying the env
    var today would keep the hole until a second roll. A refusal closes it on
    the roll itself.
    """
    return (
        os.path.exists("/.dockerenv")
        or os.path.exists("/run/.containerenv")
        or os.getenv("NOO_LAUNCHED", "").strip() == "1"
    )


def _local_exec_allowed() -> bool:
    """In-process python_exec is arbitrary RCE on the host, so it's OFF unless an
    operator explicitly opts in (dev only, outside the stack). The safe path is
    the sandbox."""
    opted_in = os.getenv("NOO_ALLOW_LOCAL_PYTHON_EXEC", "").strip().lower() in ("1", "true", "yes")
    if opted_in and _inside_the_stack():
        logger.error(
            "python_exec.local_exec_refused_in_stack",
            note="NOO_ALLOW_LOCAL_PYTHON_EXEC is ignored inside the deployed stack; unset it",
        )
        return False
    return opted_in


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
            "NOO_ALLOW_LOCAL_PYTHON_EXEC=1 to permit (unsafe) in-process "
            "execution from a source checkout — it is refused inside the "
            "deployed stack (container or launcher)."
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


def sandbox_exec_url(sandbox_url: str) -> str:
    """`<sandbox_url>/exec`, refusing anything but https.

    mTLS doors phase 1 (i77): the sandbox listener requires a cluster-CA
    client certificate, so a plaintext URL (a stale `.env` override) can
    only fail — say why instead of dialling it."""
    if not sandbox_url.strip().lower().startswith("https://"):
        raise ValueError(
            f"NOO_SANDBOX_URL={sandbox_url} is not https — the sandbox serves mTLS only; "
            "set it to https://sandbox:9000 or unset it"
        )
    return sandbox_url.rstrip("/") + "/exec"


def sandbox_tls_kwargs() -> dict:
    """The cluster CA to verify the sandbox with and this process's own
    leaf to present (NOO_TLS_CA / NOO_TLS_CERT / NOO_TLS_KEY), for httpx."""
    from .._providers.http_context import default_http_context

    ctx = default_http_context()
    return {"verify": ctx.verify, "cert": ctx.cert}


def _run_via_sandbox(
    sandbox_url: str, code: str, timeout: float, cwd: Optional[str]
) -> str:
    try:
        url = sandbox_exec_url(sandbox_url)
        response = httpx.post(
            url,
            json={"code": code, "timeout": timeout, "cwd": cwd},
            timeout=timeout + 5,
            **sandbox_tls_kwargs(),
        )
        response.raise_for_status()
        payload = response.json()
        return payload.get("output", "(no output)")
    except Exception as exc:
        return f"Error: sandbox call failed: {exc}"
