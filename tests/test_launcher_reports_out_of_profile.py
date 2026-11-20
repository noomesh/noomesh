# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A whole-stack `up` records what the stack runs and reports a RUNNING
container of a profile it does not run; it never reaps one.

ctrl kept `noo-stunnel-ollama` (compose service stunnel-ollama, profiles
ollama/gpu-tier2, stunnel v0.6.2, created 2026-10-15) Up for a month after the
controller stopped running that profile: `up` ignores unselected profiles,
`--remove-orphans` is never passed, and noo_created_guard removes only Created
containers. The 0.6.25 `stack images` gate failed on it. Now, after the up,
`noomesh-start.sh` calls `compose_record_active` (writes `.noo-stack-services`,
which `noo cluster verify` reads) and `compose_report_out_of_profile`.
"""

from __future__ import annotations

import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
ACTIVE = "gateway\nollama-embed\nstunnel-ollama-embed\n"
RUNNING = (
    "gateway noo-gateway\n"
    "ollama-embed noo-ollama-embed\n"
    "stunnel-ollama-embed noo-stunnel-ollama-embed\n"
    "stunnel-ollama noo-stunnel-ollama\n"
    " noo-vllm\n"
)


def _run(tmp: Path, fn: str, running: str = RUNNING, *, ps_rc: int = 0) -> subprocess.CompletedProcess:
    b = tmp / "bin"
    b.mkdir(exist_ok=True)
    (tmp / "running").write_text(running)
    d = b / "docker"
    d.write_text(
        "#!/bin/sh\n"
        'echo "$@" >> "$DOCKER_LOG"\n'
        'case "$1" in\n'
        f'  ps) [ {ps_rc} -ne 0 ] && exit {ps_rc}; cat "$TMP/running" ;;\n'
        "  stop|rm) echo REAPED >> \"$DOCKER_LOG\" ;;\n"
        "esac\n"
    )
    d.chmod(d.stat().st_mode | stat.S_IEXEC)
    env = {"PATH": f"{b}:/usr/bin:/bin", "TMP": str(tmp), "DOCKER_LOG": str(tmp / "docker.log"),
           "HOME": str(tmp), "COMPOSE_PROJECT_NAME": "noomesh"}
    (tmp / "docker.log").write_text("")
    script = f'. "{SCRIPTS}/lib-compose.sh" && {fn} "{tmp}" "$ACTIVE"; echo "rc=$?"'
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env={**env, "ACTIVE": ACTIVE}, cwd=tmp)


def test_the_dropped_profiles_running_container_is_reported_with_its_exact_removal(tmp_path: Path) -> None:
    r = _run(tmp_path, "compose_report_out_of_profile")
    assert "rc=0" in r.stdout
    lines = [l for l in r.stderr.splitlines() if l.startswith("!")]
    assert lines == [
        "! noo-stunnel-ollama is from a profile this stack does not run (service stunnel-ollama): "
        "docker stop noo-stunnel-ollama && docker rm noo-stunnel-ollama"
    ], r.stderr
    log = (tmp_path / "docker.log").read_text()
    assert "label=com.docker.compose.project=noomesh" in log, log
    assert "REAPED" not in log, "report, never reap"


def test_nothing_else_is_reported_and_a_failed_listing_says_so(tmp_path: Path) -> None:
    quiet = _run(tmp_path, "compose_report_out_of_profile", "gateway noo-gateway\n noo-vllm\n")
    assert quiet.stderr.strip() == "" and "rc=0" in quiet.stdout, quiet.stderr
    failed = _run(tmp_path, "compose_report_out_of_profile", ps_rc=1)
    assert "rc=0" in failed.stdout
    assert "were NOT looked for (not a pass)" in failed.stderr, failed.stderr


def test_the_record_names_the_project_and_the_active_services(tmp_path: Path) -> None:
    r = _run(tmp_path, "compose_record_active")
    assert "rc=0" in r.stdout and r.stderr.strip() == "", r.stderr
    rec = (tmp_path / ".noo-stack-services").read_text()
    assert rec == "# project noomesh\ngateway\nollama-embed\nstunnel-ollama-embed\n", rec
    assert not list(tmp_path.glob(".noo-stack-services.tmp.*")), "written atomically, no temp left"


def test_the_launcher_calls_both_after_its_whole_stack_up() -> None:
    src = (SCRIPTS / "noomesh-start.sh").read_text()
    up = src.index("start_inputs_full_up $BUILD_FLAG")
    rec = src.index('compose_record_active . "$ACTIVE_SVCS"')
    rep = src.index('compose_report_out_of_profile . "$ACTIVE_SVCS"')
    assert up < rec < rep, "after the up, record then report"
    assert "--remove-orphans" not in src.split("compose_report_undeclared", 1)[0].splitlines()[-1]
