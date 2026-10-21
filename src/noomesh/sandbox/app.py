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
  container's filesystem view, network and /tmp with concurrent calls.
  Container isolation only. Set it explicitly when Bubblewrap cannot run
  (Ubuntu's AppArmor userns restriction, an old kernel); the health
  endpoint says which mode is active so the operator can see it.

In both modes the code runs as an executor uid, never as this server. The
image declares ``sandbox-exec`` (uid 65600, the first of 64) and compose
starts the container as root under setpriv, which keeps only CAP_SETUID,
CAP_SETGID and CAP_KILL as ambient capabilities and drops to ``nonroot``
before uvicorn starts. Each call is launched through setpriv again, into
its own uid from that range with every capability cleared (`executor`,
`drop_argv`), so the code cannot read the sandbox's own leaf key (0640,
handed to nonroot), signal this server or another call, or come back to
either uid; a timeout kills everything that uid owns, which is exactly
that call. Without the user in the image or without the capabilities (a
workstation, an older compose file) the code runs as the server's uid as
it did before, and /health says so under ``executor``.

The `cwd` field of the request is accepted for wire compatibility and
ignored: the working directory is always the call's own scratch dir.
"""
from __future__ import annotations

import contextlib
import json
import logging
import math
import os
import pwd
import queue
import resource
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from typing import Iterator, Optional

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


# ── The executor user ───────────────────────────────────────────────────
# One uid per concurrent call, from a range the image declares: the kill
# after a timeout and the per-uid RLIMIT_NPROC then belong to that call
# alone. CAP_KILL stays with the server rather than a helper that
# switches uid, because the kill must reach a fork-bombed executor and
# setuid() into a uid that is at its RLIMIT_NPROC fails with EAGAIN.

EXECUTOR_USER = "sandbox-exec"
EXECUTOR_SLOTS = 64
_CAP_KILL, _CAP_SETGID, _CAP_SETUID = 5, 6, 7
_EXECUTOR_CAPS = (1 << _CAP_SETUID) | (1 << _CAP_SETGID) | (1 << _CAP_KILL)


def effective_caps(status_path: str = "/proc/self/status") -> int:
    """This process's effective capability mask (0 when unreadable)."""
    try:
        with open(status_path) as f:
            for line in f:
                if line.startswith("CapEff:"):
                    return int(line.split()[1], 16)
    except (OSError, ValueError, IndexError):
        pass
    return 0


def executor() -> tuple[Optional[int], str]:
    """(first executor uid, detail), or (None, why the code runs as the
    server's own uid instead). The uids are `base .. base + EXECUTOR_SLOTS - 1`
    and each is also its gid; only the first has a passwd entry."""
    try:
        pw = pwd.getpwnam(EXECUTOR_USER)
    except KeyError:
        return None, f"no {EXECUTOR_USER} user in this image: code runs as the server's uid"
    if pw.pw_uid <= os.getuid() < pw.pw_uid + EXECUTOR_SLOTS:
        return None, f"{EXECUTOR_USER} overlaps the server's own uid: code runs as the server's uid"
    if effective_caps() & _EXECUTOR_CAPS != _EXECUTOR_CAPS:
        return None, (
            "the server holds no CAP_SETUID/CAP_SETGID/CAP_KILL (start it through the compose "
            "entrypoint): code runs as the server's uid"
        )
    if shutil.which("setpriv") is None:
        return None, "setpriv is not installed: code runs as the server's uid"
    return pw.pw_uid, f"{EXECUTOR_USER} (uids {pw.pw_uid}-{pw.pw_uid + EXECUTOR_SLOTS - 1})"


def drop_argv(exec_user: Optional[tuple[int, int]]) -> list[str]:
    """The setpriv prefix that turns the child into the executor with no
    capability in any set the kernel carries across exec. With no
    executor user but capabilities held (an image without the user under
    the compose launcher) the uid stays and the capabilities still go:
    the code never inherits one, and Bubblewrap refuses to start in a
    process that holds any ("Unexpected capabilities but not setuid").
    Empty when there is nothing to drop. The bounding set is left alone:
    clearing it needs CAP_SETPCAP, which the server does not hold, and
    no-new-privileges already stops a file capability from granting
    anything at exec."""
    setpriv = shutil.which("setpriv")
    if setpriv is None or (exec_user is None and effective_caps() == 0):
        return []
    argv = [setpriv]
    if exec_user is not None:
        argv += ["--reuid", str(exec_user[0]), "--regid", str(exec_user[1]), "--clear-groups"]
    return argv + ["--inh-caps=-all", "--ambient-caps=-all", "--"]


_slots: "queue.Queue[int]" = queue.Queue()
for _slot in range(EXECUTOR_SLOTS):
    _slots.put(_slot)


@contextlib.contextmanager
def executor_slot() -> Iterator[Optional[tuple[int, int]]]:
    """The (uid, gid) one call runs as, held until the call is cleaned up;
    None when the code runs as the server. Blocks when every slot is in
    use — the server's thread pool is smaller than the range."""
    base, _ = executor()
    if base is None:
        yield None
        return
    slot = _slots.get()
    try:
        yield (base + slot, base + slot)
    finally:
        _slots.put(slot)


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
        # Only the first executor uid has a passwd entry; these keep
        # getpass.getuser() and friends answering for the others.
        "USER": EXECUTOR_USER,
        "LOGNAME": EXECUTOR_USER,
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
        # Counted per uid (threads included). With an executor uid per
        # call this caps a fork bomb at 96 tasks for that call alone;
        # where the code shares the server's uid the thread pool counts
        # too and is well under that. The compose nproc/pids limits are
        # the outer bound. Tunable because a developer's uid on a
        # workstation already exceeds it.
        resource.RLIMIT_NPROC: (nproc, nproc),
    }


# Makes the call's scratch directory, applies the rlimits and execs the
# real command — in the child, already as the executor, so the directory
# is the executor's own (0700) and nothing the server owns is handed to
# the code. A tiny interpreter hop instead of `preexec_fn`, which is
# documented unsafe in a threaded parent — and uvicorn runs these
# handlers on a thread pool. A limit above the container's own hard
# ceiling is refused by the kernel; the ceiling then applies, which is
# stricter, not looser. A path that already exists (a guess at the name)
# is a refusal, never reused.
_LIMIT_SHIM = (
    "import json, os, resource, sys\n"
    "scratch = sys.argv[2]\n"
    "try:\n"
    "    os.mkdir(scratch, 0o700)\n"
    "except OSError as exc:\n"
    "    sys.stderr.write(f'sandbox: cannot create the scratch directory: {exc}\\n')\n"
    "    sys.exit(125)\n"
    "os.chdir(scratch)\n"
    "for which, (soft, hard) in json.loads(sys.argv[1]).items():\n"
    "    try:\n"
    "        resource.setrlimit(int(which), (soft, hard))\n"
    "    except (ValueError, OSError):\n"
    "        pass\n"
    "os.execv(sys.argv[3], sys.argv[3:])\n"
)


def with_rlimits(limits: dict[int, tuple[int, int]], scratch: str, argv: list[str]) -> list[str]:
    """Wrap `argv` (absolute executable first) so it runs under `limits`
    from inside a freshly made `scratch`."""
    encoded = json.dumps({str(k): list(v) for k, v in limits.items()})
    return [sys.executable, "-I", "-c", _LIMIT_SHIM, encoded, scratch, *argv]


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


def launch_argv(
    mode: str,
    scratch: str,
    limits: dict[int, tuple[int, int]],
    exec_user: Optional[tuple[int, int]],
) -> list[str]:
    """The whole command line for one call: become the executor (when
    there is one), make the scratch dir and apply the limits, then
    Bubblewrap or the bare interpreter."""
    inner = bwrap_argv(scratch) if mode == "bwrap" else process_argv()
    return drop_argv(exec_user) + with_rlimits(limits, scratch, inner)


def _scratch_path() -> str:
    """A fresh, unguessable path under the server's tmp dir. Not created
    here: the shim makes it as the executor, so the directory and
    everything in it belong to that uid."""
    return os.path.join(tempfile.gettempdir(), f"exec-{secrets.token_hex(8)}")


_RMTREE = "import shutil, sys; shutil.rmtree(sys.argv[1], ignore_errors=True)"


def cleanup(scratch: str, exec_user: Optional[tuple[int, int]]) -> None:
    """Remove the scratch dir. The executor's files can only be removed
    as the executor (the server has no CAP_DAC_OVERRIDE and /tmp is
    sticky), so the removal goes through the same drop; the server's own
    rmtree afterwards is the no-executor case."""
    if exec_user is not None:
        try:
            subprocess.run(
                drop_argv(exec_user) + [sys.executable, "-I", "-c", _RMTREE, scratch],
                capture_output=True,
                timeout=30,
                env=child_env(scratch),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.warning("sandbox: scratch cleanup as the executor failed: %s", exc)
    shutil.rmtree(scratch, ignore_errors=True)


def kill_everything_of(uid: int, proc_root: str = "/proc") -> int:
    """SIGKILL every process whose real uid is `uid` (CAP_KILL). After a
    timeout this reaches what the process-group kill cannot: a snippet
    that left the group with setsid() in process mode. The uid is this
    call's alone, so nothing else is in range. Returns how many were
    signalled."""
    seen: set[int] = set()
    for _ in range(3):
        found = 0
        for entry in os.listdir(proc_root):
            if not entry.isdigit() or int(entry) in seen:
                continue
            try:
                with open(os.path.join(proc_root, entry, "status")) as f:
                    for line in f:
                        if line.startswith("Uid:"):
                            if int(line.split()[1]) == uid:
                                os.kill(int(entry), signal.SIGKILL)
                                seen.add(int(entry))
                                found += 1
                            break
            except (OSError, ValueError):
                continue
        if not found:
            break
    return len(seen)


# ── Bubblewrap availability ─────────────────────────────────────────────
# Probed once, lazily, by running the real command line against a
# trivial program. A failed probe is remembered with its reason so
# /health and /exec can say WHY, not just "no".

_probe_lock = threading.Lock()
_probe_result: Optional[tuple[bool, str]] = None


def _run_bwrap_probe() -> tuple[bool, str]:
    if shutil.which("bwrap") is None:
        return False, "bwrap is not installed in the sandbox image"
    # The real command line, executor drop included: a probe that ran as
    # the server would prove a path no call takes.
    with executor_slot() as exec_user:
        scratch = _scratch_path()
        try:
            proc = subprocess.run(
                launch_argv("bwrap", scratch, rlimits(10), exec_user),
                input=b"import os; print('ok', os.getpid())",
                capture_output=True,
                timeout=15,
                env=child_env(scratch),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"bwrap probe failed to run: {exc}"
        finally:
            cleanup(scratch, exec_user)
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
    limits = rlimits(timeout)
    timed_out = False
    with executor_slot() as exec_user:
        scratch = _scratch_path()
        argv = launch_argv(mode, scratch, limits, exec_user)
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=child_env(scratch),
                start_new_session=True,
            )
            try:
                stdout, stderr = proc.communicate(code.encode(), timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                # The whole session, not just the direct child: a snippet
                # that forked keeps running otherwise. Under bwrap the PID
                # namespace dies with it. Then everything the call's uid
                # still owns, which is what setsid() took out of the group.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if exec_user is not None:
                    kill_everything_of(exec_user[0])
                stdout, stderr = proc.communicate()
        except OSError as exc:
            return {"output": f"Error: {exc}", "isolation": mode, "exit_code": None, "timed_out": False}
        finally:
            cleanup(scratch, exec_user)

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
        "executor": exec_user[0] if exec_user is not None else None,
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
    base, exec_detail = executor()
    status = {
        "status": "healthy" if usable else "unhealthy",
        "service": "sandbox",
        "isolation": {"mode": mode, "active": mode if usable else "none", "detail": detail},
        # The uid the code runs as — the server's own when `uid` is null.
        "executor": {"uid": base, "slots": EXECUTOR_SLOTS if base is not None else 0, "detail": exec_detail},
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
