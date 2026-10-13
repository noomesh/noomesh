# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Per-call isolation in the sandbox executor (src/noomesh/sandbox/app.py).

The container is the outer wall; these tests pin the INNER one: every
call gets a scrubbed environment, its own scratch directory, hard
rlimits, a process-group kill on timeout, a bounded output — and, when
Bubblewrap is configured but cannot run, a refusal rather than a quiet
fallback. Bubblewrap itself is exercised only where it is installed
(the sandbox image); everything else runs anywhere.

Runnable via pytest or `PYTHONPATH=src python3 -m pytest tests/test_sandbox_exec_isolation.py`.
"""
from __future__ import annotations

import os
import resource
import functools
import shutil
import subprocess
import sys
import tempfile
import time

import pytest

pytest.importorskip("fastapi")

import noomesh.sandbox.app as sandbox  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_probe(monkeypatch):
    monkeypatch.setattr(sandbox, "_probe_result", None)
    monkeypatch.delenv("NOO_SANDBOX_ISOLATION", raising=False)
    # RLIMIT_NPROC counts every task of the uid; a developer's uid on a
    # workstation is far past the container default, so fork() would
    # fail here and never in the sandbox.
    monkeypatch.setenv("NOO_SANDBOX_EXEC_NPROC", "8192")
    yield


# ── an interpreter that survives the scrubbed environment ─────────────────
#
# The sandbox runs its child as `sys.executable` under `child_env()`, which
# carries no LD_LIBRARY_PATH — by design: a loader path is exactly what must
# not reach untrusted code. In the sandbox container `sys.executable` is a
# normal build and that is fine. On a self-hosted CI runner it is
# actions/setup-python's tool-cache build, which cannot even start without
# LD_LIBRARY_PATH, so every spawning test failed with "error while loading
# shared libraries: libpython3.12.so.1.0" — and one PASSED, because the
# loader's message was long enough to trip the output cap it was checking.
#
# None of these tests is about WHICH Python runs the child: they check
# isolation, limits, timeouts and exit codes. So each one runs the child
# under an interpreter proven to start in the sandbox's own environment,
# and skips — naming why — only when this host has none. The sandbox's
# scrubbing is not touched.


def _starts_scrubbed(interp: str) -> bool:
    try:
        r = subprocess.run(
            [interp, "-I", "-c", "import resource"],
            env=sandbox.child_env(tempfile.gettempdir()),
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


@functools.lru_cache(maxsize=None)
def _scrubbed_interpreter(executable: str) -> str | None:
    path = sandbox.child_env(tempfile.gettempdir())["PATH"]
    candidates = [executable, shutil.which("python3", path=path), "/usr/bin/python3"]
    seen = []
    for c in candidates:
        if c and c not in seen and os.path.exists(c):
            seen.append(c)
            if _starts_scrubbed(c):
                return c
    return None


@pytest.fixture
def scrubbed_python(monkeypatch):
    interp = _scrubbed_interpreter(sys.executable)
    if interp is None:
        pytest.skip(
            f"no interpreter here starts under the sandbox's scrubbed env: {sys.executable} "
            "needs LD_LIBRARY_PATH (a tool-cache build) and no system python3 does either"
        )
    if interp != sys.executable:
        monkeypatch.setattr(sys, "executable", interp)
    return interp


def test_a_tool_cache_python_is_swapped_for_one_that_starts_scrubbed(tmp_path):
    """The runner's case, reproduced: an interpreter that dies without
    LD_LIBRARY_PATH is passed over for one that starts in child_env()."""
    fallback = _scrubbed_interpreter(sys.executable)
    if fallback is None:
        pytest.skip("no interpreter on this host starts scrubbed to fall back to")
    fake = tmp_path / "toolcache-python"
    fake.write_text(
        "#!/bin/sh\n"
        '[ -n "$LD_LIBRARY_PATH" ] || { echo "python: error while loading shared libraries: '
        'libpython3.12.so.1.0" >&2; exit 127; }\n'
        f'exec {fallback} "$@"\n'
    )
    fake.chmod(0o755)
    assert not _starts_scrubbed(str(fake)), "the stand-in must fail exactly as the runner's python did"
    chosen = _scrubbed_interpreter(str(fake))
    assert chosen is not None and chosen != str(fake)
    assert _starts_scrubbed(chosen)


# ── the command line ────────────────────────────────────────────────────


def test_bwrap_argv_unshares_everything_and_binds_only_scratch_rw(tmp_path):
    argv = sandbox.bwrap_argv(str(tmp_path), ro_paths=("/usr", "/definitely/not/here"))
    assert "--unshare-all" in argv
    assert "--clearenv" in argv
    assert "--die-with-parent" in argv
    assert "--new-session" in argv
    # The scratch dir is the one read-write bind and the working dir.
    assert argv[argv.index("--bind") + 1 : argv.index("--bind") + 3] == [str(tmp_path), "/work"]
    assert argv[argv.index("--chdir") + 1] == "/work"
    # Read-only binds are exactly the existing paths — a missing path is
    # skipped, never bound to nothing.
    ro = [argv[i + 1] for i, a in enumerate(argv) if a == "--ro-bind"]
    assert ro == ["/usr"]
    # No write-mode bind for anything but scratch.
    assert argv.count("--bind") == 1
    # Isolated interpreter reading the snippet from stdin.
    assert argv[-3:] == [sys.executable, "-I", "-"]


def test_bwrap_argv_sets_only_the_scrubbed_environment(tmp_path):
    argv = sandbox.bwrap_argv(str(tmp_path))
    env = {argv[i + 1]: argv[i + 2] for i, a in enumerate(argv) if a == "--setenv"}
    assert env == sandbox.child_env("/work")
    assert env["HOME"] == "/work"


def test_child_env_never_carries_the_servers_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("NOO_SECRET_THING", "leak")
    monkeypatch.setenv("DATABASE_URL", "postgres://leak")
    env = sandbox.child_env(str(tmp_path))
    assert not any(k.startswith("NOO_") for k in env)
    assert "DATABASE_URL" not in env
    assert env["TMPDIR"] == str(tmp_path)


def test_rlimits_scale_cpu_with_timeout_and_forbid_cores(monkeypatch):
    monkeypatch.setenv("NOO_SANDBOX_EXEC_MEM_MB", "100")
    limits = sandbox.rlimits(4.2)
    assert limits[resource.RLIMIT_CPU] == (6, 6)
    assert limits[resource.RLIMIT_DATA] == (100 * 1024 * 1024,) * 2
    assert limits[resource.RLIMIT_CORE] == (0, 0)
    assert resource.RLIMIT_AS not in limits


def test_with_rlimits_wraps_the_real_argv():
    wrapped = sandbox.with_rlimits({resource.RLIMIT_CORE: (0, 0)}, ["/bin/true", "x"])
    assert wrapped[:3] == [sys.executable, "-I", "-c"]
    assert wrapped[-2:] == ["/bin/true", "x"]


# ── process mode, live ──────────────────────────────────────────────────


def test_process_mode_runs_code_in_a_private_scratch_dir(monkeypatch, scrubbed_python):
    seen = []
    real = tempfile.mkdtemp

    def spy(*a, **kw):
        d = real(*a, **kw)
        seen.append(d)
        return d

    monkeypatch.setattr(sandbox.tempfile, "mkdtemp", spy)
    result = sandbox.run_code(
        "import os; print(os.getcwd() == os.environ['HOME'], sorted(os.environ)[:2])",
        5,
        "process",
    )
    assert result["exit_code"] == 0, result
    assert "[stdout]\nTrue ['HOME', 'LANG']" in result["output"]
    assert result["isolation"] == "process"
    # The scratch dir is gone afterwards — nothing survives between calls.
    assert seen and not os.path.exists(seen[-1])


def test_rlimits_are_enforced_in_the_child(scrubbed_python):
    result = sandbox.run_code(
        "import resource; print(resource.getrlimit(resource.RLIMIT_CORE), resource.getrlimit(resource.RLIMIT_NOFILE))",
        5,
        "process",
    )
    assert "(0, 0) (128, 128)" in result["output"], result


def test_timeout_kills_the_whole_process_group(scrubbed_python):
    started = time.monotonic()
    result = sandbox.run_code(
        "import subprocess, time\n"
        "subprocess.Popen(['sleep', '30'])\n"
        "print('spawned', flush=True)\n"
        "time.sleep(30)\n",
        1,
        "process",
    )
    elapsed = time.monotonic() - started
    assert result["timed_out"] is True, result
    assert "timed out after 1.0s" in result["output"]
    assert "spawned" in result["output"]  # output captured before the kill
    assert elapsed < 10, f"killpg did not end the session: {elapsed:.1f}s"


def test_output_is_capped_not_unbounded(monkeypatch, scrubbed_python):
    monkeypatch.setattr(sandbox, "MAX_OUTPUT_BYTES", 100)
    result = sandbox.run_code("print('x' * 5000)", 5, "process")
    assert "[truncated: " in result["output"]
    assert len(result["output"]) < 400


def test_stderr_and_exit_code_are_reported(scrubbed_python):
    result = sandbox.run_code("import sys; sys.stderr.write('boom'); sys.exit(3)", 5, "process")
    assert "[stderr]\nboom" in result["output"]
    assert result["exit_code"] == 3


# ── the refusal ─────────────────────────────────────────────────────────


def test_bwrap_mode_refuses_to_run_when_bwrap_cannot(monkeypatch):
    monkeypatch.setattr(sandbox, "_run_bwrap_probe", lambda: (False, "No permissions to create new namespace"))
    body = sandbox.exec_code(sandbox.ExecRequest(code="print('PWNED')"))
    assert "PWNED" not in body["output"]
    assert "Code was NOT run" in body["output"]
    assert "NOO_SANDBOX_ISOLATION=process" in body["output"]
    assert "No permissions" in body["output"]
    assert body["isolation"] == "none"
    health = sandbox.health()
    assert health["status"] == "unhealthy"
    assert health["isolation"] == {"mode": "bwrap", "active": "none", "detail": "No permissions to create new namespace"}


def test_process_mode_is_an_explicit_choice_and_reports_itself(monkeypatch, scrubbed_python):
    monkeypatch.setenv("NOO_SANDBOX_ISOLATION", "process")
    monkeypatch.setattr(sandbox, "_run_bwrap_probe", lambda: (False, "should not be consulted"))
    body = sandbox.exec_code(sandbox.ExecRequest(code="print(6 * 7)", cwd="/ignored"))
    assert "42" in body["output"]
    assert body["isolation"] == "process"
    health = sandbox.health()
    assert health["status"] == "healthy"
    assert health["isolation"]["active"] == "process"


def test_unknown_mode_falls_to_bwrap_not_to_process(monkeypatch):
    monkeypatch.setenv("NOO_SANDBOX_ISOLATION", "yolo")
    assert sandbox.isolation_mode() == "bwrap"


def test_oversized_code_is_refused_before_anything_runs(monkeypatch):
    monkeypatch.setattr(sandbox, "_run_bwrap_probe", lambda: (True, "bwrap"))
    body = sandbox.exec_code(sandbox.ExecRequest(code="#" * (sandbox.MAX_CODE_BYTES + 1)))
    assert body["output"].startswith("Error: code exceeds")


def test_probe_result_is_cached_until_refreshed(monkeypatch):
    calls = []

    def probe():
        calls.append(1)
        return (True, "bwrap")

    monkeypatch.setattr(sandbox, "_run_bwrap_probe", probe)
    sandbox.bwrap_available()
    sandbox.bwrap_available()
    assert len(calls) == 1
    sandbox.bwrap_available(refresh=True)
    assert len(calls) == 2


# ── bwrap, where it exists ──────────────────────────────────────────────


@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap not installed here")
def test_bwrap_live_has_no_network_and_a_private_root(scrubbed_python):
    ok, detail = sandbox.bwrap_available(refresh=True)
    if not ok:
        pytest.skip(f"bwrap present but cannot run here: {detail}")
    result = sandbox.run_code(
        "import os, socket\n"
        "print(os.getpid(), os.getcwd(), sorted(os.listdir('/')))\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 53), timeout=1); print('NET')\n"
        "except OSError as e:\n"
        "    print('nonet', type(e).__name__)\n",
        10,
        "bwrap",
    )
    assert result["exit_code"] == 0, result
    assert "nonet" in result["output"] and "NET\n" not in result["output"]
    assert "/work" in result["output"]
    assert "'work'" in result["output"] and "'home'" not in result["output"]
