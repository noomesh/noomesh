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
    wrapped = sandbox.with_rlimits({resource.RLIMIT_CORE: (0, 0)}, "/tmp/scratch-x", ["/bin/true", "x"])
    assert wrapped[:3] == [sys.executable, "-I", "-c"]
    assert wrapped[5] == "/tmp/scratch-x"
    assert wrapped[-2:] == ["/bin/true", "x"]


# ── the executor uid ────────────────────────────────────────────────────


class _PW:
    def __init__(self, uid):
        self.pw_uid = uid
        self.pw_gid = uid


def _with_executor(monkeypatch, uid=65600, caps=sandbox._EXECUTOR_CAPS, setpriv="/usr/bin/setpriv"):
    monkeypatch.setattr(sandbox.pwd, "getpwnam", lambda name: _PW(uid) if name == sandbox.EXECUTOR_USER else (_ for _ in ()).throw(KeyError(name)))
    monkeypatch.setattr(sandbox, "effective_caps", lambda *a: caps)
    real_which = shutil.which
    monkeypatch.setattr(sandbox.shutil, "which", lambda name, *a, **kw: setpriv if name == "setpriv" else real_which(name, *a, **kw))


def test_no_executor_without_the_user_the_caps_or_setpriv(monkeypatch):
    monkeypatch.setattr(sandbox.pwd, "getpwnam", lambda name: (_ for _ in ()).throw(KeyError(name)))
    base, detail = sandbox.executor()
    assert base is None and "no sandbox-exec user" in detail
    _with_executor(monkeypatch, caps=0)
    base, detail = sandbox.executor()
    assert base is None and "CAP_SETUID/CAP_SETGID/CAP_KILL" in detail
    _with_executor(monkeypatch, caps=sandbox._EXECUTOR_CAPS & ~(1 << sandbox._CAP_KILL))
    assert sandbox.executor()[0] is None, "two of the three capabilities is not enough"
    _with_executor(monkeypatch, setpriv=None)
    base, detail = sandbox.executor()
    assert base is None and "setpriv" in detail
    _with_executor(monkeypatch, uid=os.getuid())
    assert sandbox.executor()[0] is None, "the range must not contain the server's uid"
    _with_executor(monkeypatch)
    assert sandbox.executor() == (65600, "sandbox-exec (uids 65600-65663)")


def test_effective_caps_reads_the_mask(tmp_path):
    status = tmp_path / "status"
    status.write_text("Name:\tx\nCapInh:\t0000000000000000\nCapPrm:\t00000000000000e0\nCapEff:\t00000000000000e0\n")
    assert sandbox.effective_caps(str(status)) == sandbox._EXECUTOR_CAPS
    assert sandbox.effective_caps(str(tmp_path / "missing")) == 0


def test_drop_argv_clears_every_set_the_kernel_carries_across_exec(monkeypatch):
    _with_executor(monkeypatch)
    argv = sandbox.drop_argv((65601, 65601))
    assert argv[0].endswith("setpriv")
    assert argv[1:] == ["--reuid", "65601", "--regid", "65601", "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all", "--"]
    # No bounding-set drop: that needs CAP_SETPCAP the server does not hold.
    assert not any(a.startswith("--bounding-set") for a in argv)
    # Capabilities held but no executor user: the uid stays, the caps still go.
    assert sandbox.drop_argv(None) == [argv[0], "--inh-caps=-all", "--ambient-caps=-all", "--"]
    # Nothing held, nothing to drop; no setpriv, nothing to drop with.
    _with_executor(monkeypatch, caps=0)
    assert sandbox.drop_argv(None) == []
    _with_executor(monkeypatch, setpriv=None)
    assert sandbox.drop_argv((65601, 65601)) == []


def test_launch_argv_drops_first_then_shim_then_the_real_command(tmp_path, monkeypatch):
    _with_executor(monkeypatch)
    scratch = str(tmp_path / "scratch")
    argv = sandbox.launch_argv("process", scratch, {resource.RLIMIT_CORE: (0, 0)}, (65601, 65601))
    sep = argv.index("--")
    assert argv[0].endswith("setpriv") and argv[sep + 1] == sys.executable
    assert argv[sep + 2 : sep + 4] == ["-I", "-c"]
    assert argv[sep + 6] == scratch
    assert argv[-3:] == [sys.executable, "-I", "-"]
    # Without an executor and without capabilities the prefix is simply absent.
    _with_executor(monkeypatch, caps=0)
    plain = sandbox.launch_argv("process", scratch, {resource.RLIMIT_CORE: (0, 0)}, None)
    assert plain == argv[sep + 1 :]
    _with_executor(monkeypatch)
    # bwrap mode: the jail sits inside the drop, so the namespaces are the executor's.
    jailed = sandbox.launch_argv("bwrap", scratch, {resource.RLIMIT_CORE: (0, 0)}, (65601, 65601))
    assert jailed[0].endswith("setpriv") and "--unshare-all" in jailed


def test_executor_slots_hand_out_distinct_uids_and_give_them_back(monkeypatch):
    _with_executor(monkeypatch)
    with sandbox.executor_slot() as a, sandbox.executor_slot() as b:
        assert a != b and a[0] == a[1] and 65600 <= a[0] < 65664 and 65600 <= b[0] < 65664
    assert sandbox._slots.qsize() == sandbox.EXECUTOR_SLOTS
    monkeypatch.setattr(sandbox.pwd, "getpwnam", lambda name: (_ for _ in ()).throw(KeyError(name)))
    with sandbox.executor_slot() as none:
        assert none is None
    assert sandbox._slots.qsize() == sandbox.EXECUTOR_SLOTS


def test_the_shim_makes_the_scratch_dir_itself_and_refuses_an_existing_one(tmp_path, scrubbed_python):
    scratch = tmp_path / "fresh"
    argv = sandbox.with_rlimits({resource.RLIMIT_CORE: (0, 0)}, str(scratch), [scrubbed_python, "-I", "-c", "import os; print(os.getcwd())"])
    r = subprocess.run(argv, capture_output=True, text=True, timeout=30, env=sandbox.child_env(str(scratch)))
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == os.path.realpath(scratch)
    assert oct(scratch.stat().st_mode & 0o777) == "0o700"
    # A path that already exists is never reused — a guess at the name
    # cannot hand the code a directory someone else prepared.
    r = subprocess.run(argv, capture_output=True, text=True, timeout=30, env=sandbox.child_env(str(scratch)))
    assert r.returncode == 125 and "cannot create the scratch directory" in r.stderr


def test_cleanup_runs_as_the_executor_then_sweeps(monkeypatch, tmp_path):
    _with_executor(monkeypatch)
    calls = []
    monkeypatch.setattr(sandbox.subprocess, "run", lambda argv, **kw: calls.append(argv))
    scratch = tmp_path / "s"
    scratch.mkdir()
    sandbox.cleanup(str(scratch), (65602, 65602))
    assert calls and calls[0][:5] == ["/usr/bin/setpriv", "--reuid", "65602", "--regid", "65602"]
    assert calls[0][-1] == str(scratch) and "rmtree" in calls[0][-2]
    assert not scratch.exists(), "the server's own sweep still runs"
    scratch.mkdir()
    sandbox.cleanup(str(scratch), None)
    assert len(calls) == 1 and not scratch.exists()


def test_kill_everything_of_signals_only_that_uid(monkeypatch, tmp_path):
    # 101 is the server (sandbox-server, 65590): never one of the call's.
    for pid, uid in (("100", 65605), ("101", 65590), ("102", 65605), ("notapid", 65605)):
        d = tmp_path / pid
        d.mkdir()
        (d / "status").write_text(f"Name:\tx\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    killed = []
    monkeypatch.setattr(sandbox.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    assert sandbox.kill_everything_of(65605, proc_root=str(tmp_path)) == 2
    assert sorted(killed) == [(100, 9), (102, 9)]


def test_run_code_reports_the_executor_and_kills_by_uid_on_timeout(monkeypatch, scrubbed_python):
    """With a (fake) executor the launch goes through setpriv, which a
    workstation cannot do — so stand in for the drop with a no-op prefix
    and check the server's side: the uid in the result, the uid kill
    after a timeout, the cleanup as the executor."""
    _with_executor(monkeypatch, setpriv="/usr/bin/env")
    monkeypatch.setattr(sandbox, "drop_argv", lambda exec_user: ["/usr/bin/env", "--"])
    killed, cleaned = [], []
    monkeypatch.setattr(sandbox, "kill_everything_of", lambda uid: killed.append(uid) or 0)
    real_cleanup = sandbox.cleanup
    monkeypatch.setattr(sandbox, "cleanup", lambda scratch, eu: cleaned.append(eu) or real_cleanup(scratch, None))
    result = sandbox.run_code("print('hi')", 5, "process")
    assert result["exit_code"] == 0, result
    uid = result["executor"]
    assert 65600 <= uid < 65600 + sandbox.EXECUTOR_SLOTS, result
    assert cleaned == [(uid, uid)] and killed == []
    result = sandbox.run_code("import time; time.sleep(30)", 1, "process")
    assert result["timed_out"] is True and killed == [result["executor"]]


def test_health_reports_the_executor(monkeypatch):
    monkeypatch.setattr(sandbox, "_run_bwrap_probe", lambda: (True, "bwrap"))
    monkeypatch.setattr(sandbox.pwd, "getpwnam", lambda name: (_ for _ in ()).throw(KeyError(name)))
    h = sandbox.health()
    assert h["executor"]["uid"] is None and h["executor"]["slots"] == 0 and "sandbox-exec" in h["executor"]["detail"]
    _with_executor(monkeypatch)
    h = sandbox.health()
    assert h["executor"] == {"uid": 65600, "slots": 64, "detail": "sandbox-exec (uids 65600-65663)"}
    # The server's own uid, which `noo cluster verify` judges against the
    # key's reader (sandbox-server, a uid no other service shares).
    monkeypatch.setattr(sandbox.os, "getuid", lambda: 65590)
    assert sandbox.health()["server"] == {"uid": 65590}


# ── process mode, live ──────────────────────────────────────────────────


def test_process_mode_runs_code_in_a_private_scratch_dir(monkeypatch, scrubbed_python):
    seen = []
    real = sandbox._scratch_path

    def spy():
        d = real()
        seen.append(d)
        return d

    monkeypatch.setattr(sandbox, "_scratch_path", spy)
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
