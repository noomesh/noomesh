# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The sandbox: the airgapped executor behind the `python_exec` tool.

The gateway POSTs `{code, timeout}` to `/exec` and gets `{output}` back.
Nothing else reaches this service and it never dials out (its Docker
network is `internal: true`). The container boundary — dropped
capabilities, read-only rootfs, tmpfs, resource limits, no-new-privileges
— is the outer wall. This module is the INNER one: every call runs in a
process tree of its own, with a scrubbed environment, a private scratch
directory and hard resource limits, and — when the container allows it —
inside a Bubblewrap sandbox with its own root, PID space and no network.

Isolation modes (`NOO_SANDBOX_ISOLATION`):

* ``bwrap`` (default) — each call runs under `bwrap --unshare-all`. The
  code sees a read-only copy of the system directories, a private /tmp,
  its scratch directory at /work, and no network interface at all. It
  cannot see this server's process, other calls, or the container's
  filesystem. Requires the container to be started with
  docker/seccomp-sandbox.json (both launchers do that); if the kernel or
  the container's security profile refuses user namespaces, `/exec`
  REFUSES to run code and `/health` reports unhealthy rather than
  quietly falling back. The operator can choose the fallback:
* ``process`` — a plain child process with the same scrubbed environment,
  scratch directory, rlimits and process-group kill, but sharing the
  container's filesystem view and /tmp with concurrent calls. Container
  isolation only. Set it explicitly when Bubblewrap cannot run (Ubuntu's
  AppArmor userns restriction, an old kernel); the health endpoint says
  which mode is active so the operator can see it.

The `cwd` field of the request is accepted for wire compatibility and
ignored: the working directory is always the call's own scratch dir.
"""
from __future__ import annotations

import json
import logging
import math
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

log = logging.getLogger("noomesh.sandbox")

app = FastAPI(title="PAI Sandbox")

ISOLATION_MODES = ("bwrap", "process")

# Bounds. Code size guards the request body; the output cap guards the
# server's memory against `print("x" * 10**9)`; the per-call limits guard
# the container's CPU/memory budget against one runaway call.
MAX_CODE_BYTES = 256_000
MAX_OUTPUT_BYTES = 64_000
MAX_TIMEOUT_SECS = 300.0
DEFAULT_TIMEOUT_SECS = 10.0

# Directories the code may READ inside the Bubblewrap root. Bound
# read-only when present; the interpreter (uv-managed under /opt, linked
# from /usr/local/bin) and site-packages live under these. /app is the
# noomesh source the deps image's .pth file points at, so `import
# noomesh` keeps working exactly as it did — without network or secrets
# it is inert. Nothing else from the container is visible: no /etc
# beyond the loader cache, no /run, no /home, no server process.
RO_PATHS = (
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/opt",
    "/app",
    "/etc/ld.so.cache",
    "/etc/alternatives",
)


def isolation_mode() -> str:
    mode = os.environ.get("NOO_SANDBOX_ISOLATION", "bwrap").strip().lower() or "bwrap"
    if mode not in ISOLATION_MODES:
        log.warning("NOO_SANDBOX_ISOLATION=%r is not one of %s; using bwrap", mode, ISOLATION_MODES)
        return "bwrap"
    return mode


def _limit_mb(name: str, default: int) -> int:
    try:
        return max(16, int(os.environ.get(name, default)))
    except ValueError:
        return default


def child_env(scratch: str) -> dict[str, str]:
    """The ONLY environment the code sees. Never the server's: the
    container's env is small, but nothing in it is the code's business
    and an allow-list cannot leak whatever gets added later."""
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": scratch,
        "TMPDIR": scratch,
        "LANG": "C.UTF-8",
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def rlimits(timeout: float) -> dict[int, tuple[int, int]]:
    """Hard per-call limits, applied in the child before exec and
    inherited by everything it spawns (Bubblewrap included)."""
    cpu = int(math.ceil(timeout)) + 1
    mem = _limit_mb("NOO_SANDBOX_EXEC_MEM_MB", 384) * 1024 * 1024
    fsize = _limit_mb("NOO_SANDBOX_EXEC_FILE_MB", 32) * 1024 * 1024
    nproc = _limit_mb("NOO_SANDBOX_EXEC_NPROC", 96)
    return {
        resource.RLIMIT_CPU: (cpu, cpu),
        # RLIMIT_DATA, not RLIMIT_AS: AS counts the address-space
        # reservations numpy/torch make on import and would refuse
        # them long before real memory is used.
        resource.RLIMIT_DATA: (mem, mem),
        resource.RLIMIT_FSIZE: (fsize, fsize),
        resource.RLIMIT_CORE: (0, 0),
        resource.RLIMIT_NOFILE: (128, 128),
        # Counted per uid (threads included), so this caps a fork bomb
        # at 96 tasks for the whole container — the server's thread pool
        # shares the uid and is well under that. The compose nproc/pids
        # limits are the outer bound. Tunable because a developer's uid
        # on a workstation already exceeds it.
        resource.RLIMIT_NPROC: (nproc, nproc),
    }


# Applies the rlimits in the child and execs the real command. A tiny
# interpreter hop instead of `preexec_fn`, which is documented unsafe in
# a threaded parent — and uvicorn runs these handlers on a thread pool.
# A limit above the container's own hard ceiling is refused by the
# kernel; the ceiling then applies, which is stricter, not looser.
_LIMIT_SHIM = (
    "import json, os, resource, sys\n"
    "for which, (soft, hard) in json.loads(sys.argv[1]).items():\n"
    "    try:\n"
    "        resource.setrlimit(int(which), (soft, hard))\n"
    "    except (ValueError, OSError):\n"
    "        pass\n"
    "os.execv(sys.argv[2], sys.argv[2:])\n"
)


def with_rlimits(limits: dict[int, tuple[int, int]], argv: list[str]) -> list[str]:
    """Wrap `argv` (absolute executable first) so it runs under `limits`."""
    encoded = json.dumps({str(k): list(v) for k, v in limits.items()})
    return [sys.executable, "-I", "-c", _LIMIT_SHIM, encoded, *argv]


def bwrap_argv(scratch: str, ro_paths: tuple[str, ...] = RO_PATHS) -> list[str]:
    """The Bubblewrap command line for one call. `--unshare-all` gives the
    code its own user, PID, IPC, UTS, cgroup AND network namespaces —
    no interface but loopback, whatever the container is attached to."""
    argv = [
        shutil.which("bwrap") or "bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--bind", scratch, "/work",
        "--chdir", "/work",
    ]
    for path in ro_paths:
        if os.path.exists(path):
            argv += ["--ro-bind", path, path]
    for key, value in child_env("/work").items():
        argv += ["--setenv", key, value]
    argv += ["--", sys.executable, "-I", "-"]
    return argv


def process_argv() -> list[str]:
    return [sys.executable, "-I", "-"]


# ── Bubblewrap availability ─────────────────────────────────────────────
# Probed once, lazily, by running the real command line against a
# trivial program. A failed probe is remembered with its reason so
# /health and /exec can say WHY, not just "no".

_probe_lock = threading.Lock()
_probe_result: Optional[tuple[bool, str]] = None


def _run_bwrap_probe() -> tuple[bool, str]:
    if shutil.which("bwrap") is None:
        return False, "bwrap is not installed in the sandbox image"
    scratch = tempfile.mkdtemp(prefix="probe-")
    try:
        proc = subprocess.run(
            bwrap_argv(scratch),
            input=b"import os; print('ok', os.getpid())",
            capture_output=True,
            timeout=15,
            env=child_env(scratch),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"bwrap probe failed to run: {exc}"
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    if proc.returncode == 0 and proc.stdout.startswith(b"ok"):
        return True, "bwrap"
    detail = (proc.stderr or proc.stdout).decode(errors="replace").strip().splitlines()
    return False, (detail[-1] if detail else f"bwrap exited {proc.returncode}")


def bwrap_available(refresh: bool = False) -> tuple[bool, str]:
    global _probe_result
    with _probe_lock:
        if _probe_result is None or refresh:
            _probe_result = _run_bwrap_probe()
            if not _probe_result[0]:
                log.error("sandbox: Bubblewrap unavailable: %s", _probe_result[1])
        return _probe_result


def active_isolation() -> tuple[str, bool, str]:
    """(configured mode, usable, detail). `usable` is False only when the
    configured mode is bwrap and it cannot run — the process mode is
    always usable."""
    mode = isolation_mode()
    if mode == "process":
        return mode, True, "container isolation only (NOO_SANDBOX_ISOLATION=process)"
    ok, detail = bwrap_available()
    return mode, ok, detail


# ── Execution ───────────────────────────────────────────────────────────


def _clamp_timeout(timeout: float) -> float:
    if not timeout or timeout <= 0:
        return DEFAULT_TIMEOUT_SECS
    return min(float(timeout), MAX_TIMEOUT_SECS)


def _truncate(data: bytes, limit: Optional[int] = None) -> str:
    limit = MAX_OUTPUT_BYTES if limit is None else limit
    if len(data) <= limit:
        return data.decode(errors="replace")
    return data[:limit].decode(errors="replace") + f"\n… [truncated: {len(data) - limit} more bytes]"


def run_code(code: str, timeout: float, mode: str) -> dict:
    """Run one snippet under `mode` and return the wire result."""
    timeout = _clamp_timeout(timeout)
    scratch = tempfile.mkdtemp(prefix="exec-")
    limits = rlimits(timeout)
    argv = with_rlimits(limits, bwrap_argv(scratch) if mode == "bwrap" else process_argv())
    timed_out = False
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=scratch,
            env=child_env(scratch),
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(code.encode(), timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            # The whole session, not just the direct child: a snippet
            # that forked keeps running otherwise. Under bwrap the PID
            # namespace dies with it.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = proc.communicate()
    except OSError as exc:
        return {"output": f"Error: {exc}", "isolation": mode, "exit_code": None, "timed_out": False}
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    sections = []
    if timed_out:
        sections.append(f"Error: Python execution timed out after {timeout:.1f}s.")
    out, err = _truncate(stdout).strip(), _truncate(stderr).strip()
    if out:
        sections.append("[stdout]\n" + out)
    if err:
        sections.append("[stderr]\n" + err)
    if not sections:
        sections.append("(no output)")
    return {
        "output": "\n\n".join(sections),
        "isolation": mode,
        "exit_code": proc.returncode,
        "timed_out": timed_out,
    }


class ExecRequest(BaseModel):
    code: str
    timeout: float = DEFAULT_TIMEOUT_SECS
    cwd: Optional[str] = None  # accepted, ignored — see module doc


@app.get("/health")
def health() -> dict:
    mode, usable, detail = active_isolation()
    status = {
        "status": "healthy" if usable else "unhealthy",
        "service": "sandbox",
        "isolation": {"mode": mode, "active": mode if usable else "none", "detail": detail},
        "checks": {},
    }
    try:
        result = subprocess.run(
            [sys.executable, "-c", "import sys; print(sys.version)"],
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        if result.returncode == 0:
            status["checks"]["python"] = "healthy"
            status["python_version"] = result.stdout.strip().split()[0]
        else:
            status["status"] = "unhealthy"
            status["checks"]["python"] = f"unhealthy: {result.stderr}"
    except Exception as e:  # noqa: BLE001 - reported, not raised
        status["status"] = "unhealthy"
        status["checks"]["python"] = f"unhealthy: {e}"
    status["checks"]["isolation"] = "healthy" if usable else f"unhealthy: {detail}"
    return status


@app.post("/exec")
def exec_code(request: ExecRequest) -> dict:
    if len(request.code.encode()) > MAX_CODE_BYTES:
        return {"output": f"Error: code exceeds {MAX_CODE_BYTES} bytes."}
    mode, usable, detail = active_isolation()
    if not usable:
        # Loud, not lenient: the container-only mode is a choice the
        # operator makes by name, never a fallback this service takes.
        return {
            "output": (
                f"Error: sandbox isolation unavailable ({detail}). Code was NOT run. "
                "Start the sandbox with docker/seccomp-sandbox.json, or set "
                "NOO_SANDBOX_ISOLATION=process to accept container-only isolation."
            ),
            "isolation": "none",
            "exit_code": None,
            "timed_out": False,
        }
    return run_code(request.code, request.timeout, mode)
