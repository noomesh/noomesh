# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The launcher treats a missing compose v2 plugin as a prerequisite failure,
and a failed pull shows compose's real last line (not a guess about the
network).

Found on stock Ubuntu 24.04 with the distro `docker.io` (no compose v2):
`docker compose -f …` answered "unknown shorthand flag: 'f' in -f" (rc 125),
and the pull loop retried three times, then said "check the registry login
and network". Semantics pinned here:

  compose ABSENT or OLD (v1 only) -> require_compose_v2 fails naming the package
  compose present, pull fails     -> every failed attempt and the summary show
                                     compose's last non-empty line; rc 125 is
                                     reported as a compose refusal, not network

Fake `docker` on PATH only; the real functions from scripts/lib-compose.sh run
under bash. The launcher's own wiring is guarded textually.
"""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "scripts" / "lib-compose.sh"
START = ROOT / "scripts" / "noomesh-start.sh"


def _docker(tmp_path: Path, body: str, docker_ce: bool = False) -> dict:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    # The host's package database must not decide the answer: a fake dpkg-query.
    q = bindir / "dpkg-query"
    q.write_text(f"#!/bin/sh\nexit {0 if docker_ce else 1}\n")
    q.chmod(0o755)
    d = bindir / "docker"
    d.write_text("#!/bin/sh\n" + body)
    d.chmod(0o755)
    return {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}


def _run(script: str, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-c", f". {LIB}\n{script}"], env=env,
                          capture_output=True, text=True, timeout=60)


NO_COMPOSE = "[ \"$1\" = compose ] && { echo \"unknown shorthand flag: 'f' in -f\" >&2; exit 125; }\nexit 0\n"


@pytest.mark.parametrize("osr,pkg", [
    ('ID=ubuntu\nID_LIKE=debian\n', "docker-compose-v2"),
    ('ID=debian\n', "docker-compose-v2"),
    ('ID=fedora\n', "install it"),
])
def test_absent_compose_fails_naming_the_package(tmp_path, osr, pkg):
    (tmp_path / "os-release").write_text(osr)
    env = _docker(tmp_path, NO_COMPOSE)
    env["NOO_OS_RELEASE"] = str(tmp_path / "os-release")
    r = _run("require_compose_v2", env)
    assert r.returncode == 1
    assert pkg in r.stderr and "v2 plugin" in r.stderr, r.stderr


def test_docker_ce_from_dockers_own_repo_names_the_plugin_package(tmp_path):
    (tmp_path / "os-release").write_text("ID=ubuntu\n")
    env = _docker(tmp_path, NO_COMPOSE, docker_ce=True)
    env["NOO_OS_RELEASE"] = str(tmp_path / "os-release")
    r = _run("require_compose_v2", env)
    assert r.returncode == 1 and "docker-compose-plugin" in r.stderr, r.stderr


def test_present_compose_passes_silently(tmp_path):
    env = _docker(tmp_path, "exit 0\n")
    r = _run("require_compose_v2", env)
    assert (r.returncode, r.stderr) == (0, "")


def test_last_error_line_skips_blanks_ansi_and_progress_redraws(tmp_path):
    f = tmp_path / "err"
    f.write_bytes(b"pulling a\r\x1b[2Kpulling b\nError response from daemon: denied\n\n  \n")
    r = _run(f'last_error_line "{f}"', os.environ.copy())
    assert r.stdout.strip() == "Error response from daemon: denied"
    assert _run(f'last_error_line "{tmp_path}/nope"', os.environ.copy()).stdout == ""


def _pull_loop_script() -> str:
    """The launcher's real pull loop, lifted verbatim, sleep shortened."""
    text = START.read_text()
    a = text.index("            _attempt=1\n")
    b = text.index("        else\n            docker compose $COMPOSE_FILES $PROFILE_ARGS pull --ignore-pull-failures")
    loop = text[a:b].replace("sleep 15", "true")
    return textwrap.dedent(f"""
        set -e
        ui_warned() {{ echo "WARN $*"; }}
        ui_note() {{ echo "NOTE $*"; }}
        COMPOSE_FILES=""; PROFILE_ARGS=""; _dist_services="svc"
        {loop}
        echo PULLED
    """)


def test_pull_failure_shows_the_real_line_and_rc_125_is_not_blamed_on_the_network(tmp_path):
    env = _docker(tmp_path, NO_COMPOSE)
    r = _run(_pull_loop_script(), env)
    assert r.returncode == 1
    assert r.stderr.count("pull failed (attempt") == 2
    assert "unknown shorthand flag" in r.stderr
    assert "not a registry or network failure" in r.stderr
    assert "check the registry login" not in r.stderr


def test_network_failure_keeps_the_network_advice_and_the_real_line(tmp_path):
    env = _docker(tmp_path, "echo 'Get https://ghcr.io/v2/: i/o timeout' >&2\nexit 1\n")
    r = _run(_pull_loop_script(), env)
    assert r.returncode == 1
    assert "check the registry login and network" in r.stderr
    assert "i/o timeout" in r.stderr.split("check the registry login")[1]


def test_pull_that_recovers_on_retry_succeeds(tmp_path):
    marker = tmp_path / "n"
    env = _docker(tmp_path, f"if [ -e {marker} ]; then exit 0; fi\ntouch {marker}\necho flaky >&2\nexit 1\n")
    r = _run(_pull_loop_script(), env)
    assert r.returncode == 0 and "PULLED" in r.stdout
    assert "NOTE flaky" in r.stderr


def test_launcher_checks_compose_before_the_pull_and_has_no_blind_retry():
    text = START.read_text()
    assert text.index("require_compose_v2 || exit 1") < text.index("_attempt=1")
    assert "until docker compose" not in text


def _run_on_a_terminal(script: str, env: dict) -> str:
    """Run under a pseudo-terminal, as an operator's shell does; returns what
    the terminal showed."""
    import pty

    out = bytearray()

    def _read(fd):
        data = os.read(fd, 4096)
        out.extend(data)
        return data

    pid, fd = pty.fork()
    if pid == 0:  # child
        os.execvpe("bash", ["bash", "-c", f". {LIB}\n{script}"], {**env, "TERM": "xterm"})
    try:
        while True:
            try:
                if not _read(fd):
                    break
            except OSError:
                break
    finally:
        os.waitpid(pid, 0)
    return out.decode(errors="replace")


# The fake compose reports whether its own output fds are a terminal.
PROBE = ('[ -t 1 ] && echo "STDOUT=tty" || echo "STDOUT=pipe"\n'
         '[ -t 2 ] && echo "STDERR=tty" >&2 || echo "STDERR=pipe" >&2\n'
         'echo "ARGS=$*"\nexit 0\n')


def test_on_a_terminal_compose_draws_on_the_terminal_not_through_a_pipe(tmp_path):
    # A piped compose cannot rewind its frames: every redraw lands below the
    # last (seen live on the v0.2.95 roll). It must own the terminal.
    shown = _run_on_a_terminal(_pull_loop_script(), _docker(tmp_path, PROBE))
    assert "PULLED" in shown
    assert "STDOUT=tty" in shown and "STDERR=tty" in shown, shown
    assert "--progress" not in shown, "compose picks its display itself on a terminal"


def test_off_a_terminal_the_pull_is_captured_and_plain(tmp_path):
    r = _run(_pull_loop_script(), _docker(tmp_path, PROBE))
    assert r.returncode == 0 and "PULLED" in r.stdout
    assert "STDERR=pipe" in r.stderr
    assert "--progress" not in r.stderr
