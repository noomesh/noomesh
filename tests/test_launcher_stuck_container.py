# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""One unkillable container must not take the whole stack down
(scripts/lib-stuck-container.sh; controller pop-os, 2026-10-20).

`docker compose up --force-recreate` failed with "cannot stop container: <id>:
tried to kill container, but did not receive an exit event" for
noo-ollama-embed and aborted, leaving every service Created. The launcher
must name the stuck service, start every OTHER service, and exit 75 so
`noo upgrade` can say "stack up except <service>". Any other failure keeps
compose's own exit code, and a clean `up` stays silent.

A fake `docker` on PATH stands in for the daemon; nothing real is touched.
"""

from __future__ import annotations

import os
import re
import subprocess
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
STUCK_ID = "c5bba1c9" + "0" * 56

FAKE_DOCKER = r"""#!/bin/bash
echo "$*" >> "$FAKE_LOG"
case "$*" in
  *"config --services"*) printf '%s\n' postgres redis gateway ollama-embed ;;
  "inspect -f {{.Name}} "*) echo "/noo-ollama-embed" ;;
  "inspect -f {{ index .Config.Labels"*) echo "ollama-embed" ;;
  *" up "*" ollama-embed"*|*" up "*"--no-deps"*) [ -n "$FAKE_SECOND_UP_FAILS" ] && { echo "boom" >&2; exit 1; }; exit 0 ;;
  *" up "*) printf '%s\n' "$FAKE_UP_STDERR" >&2; exit "$FAKE_UP_RC" ;;
  *) exit 0 ;;
esac
"""


def _run(tmp_path: Path, up_stderr: str, up_rc: int = 1, second_fails: bool = False):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    d = bin_dir / "docker"
    d.write_text(FAKE_DOCKER)
    d.chmod(0o755)
    log = tmp_path / "docker.log"
    report = tmp_path / "report"
    script = textwrap.dedent(f"""
        . {SCRIPTS}/lib-ui.sh
        . {SCRIPTS}/lib-stuck-container.sh
        noo_compose_up_isolating_stuck compose -f a.yml --profile controller up -d --force-recreate --scale node-agent=0
        echo "RC=$?"
    """)
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "FAKE_LOG": str(log),
        "FAKE_UP_STDERR": up_stderr,
        "FAKE_UP_RC": str(up_rc),
        "FAKE_SECOND_UP_FAILS": "1" if second_fails else "",
        "NOO_STUCK_REPORT": str(report),
        "NO_COLOR": "1",
        "LC_ALL": "C",
    }
    p = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    calls = log.read_text().splitlines() if log.exists() else []
    rc = int(re.search(r"RC=(\d+)", p.stdout).group(1))
    return p, calls, rc, report


STUCK_MSG = (
    f"Error response from daemon: cannot stop container: {STUCK_ID}: "
    "tried to kill container, but did not receive an exit event"
)


def test_stuck_container_starts_everything_else_and_exits_75(tmp_path):
    p, calls, rc, report = _run(tmp_path, STUCK_MSG)
    assert rc == 75, p.stdout + p.stderr
    out = p.stdout + p.stderr
    assert ("noo-ollama-embed (ollama-embed) is stuck: its process will not exit (kill -9 and docker restart "
            "cannot clear it); a reboot of this host clears it. Starting everything else.") in out
    second = [c for c in calls if " up " in f" {c} " and "--no-deps" in c]
    assert len(second) == 1, calls
    c = second[0]
    assert c.endswith("postgres redis gateway"), c
    assert "ollama-embed" not in c
    assert "-f a.yml --profile controller" in c and "--force-recreate" in c and "--scale node-agent=0" in c
    assert report.read_text().split() == ["ollama-embed", STUCK_ID]
    assert not any(x.startswith("rename") or " kill" in x for x in calls), "never rename or kill"


def test_the_other_services_failing_keeps_composes_own_code(tmp_path):
    p, calls, rc, _ = _run(tmp_path, STUCK_MSG, second_fails=True)
    assert rc == 1, p.stdout + p.stderr


def test_any_other_failure_is_passed_through_untouched(tmp_path):
    p, calls, rc, report = _run(tmp_path, "Error response from daemon: toomanyrequests", up_rc=3)
    assert rc == 3
    assert not report.exists()
    assert not any("--no-deps" in c for c in calls), "no isolation for a transient registry error"
    assert "is stuck" not in p.stdout + p.stderr


def test_a_clean_up_is_silent_and_zero(tmp_path):
    p, calls, rc, _ = _run(tmp_path, "", up_rc=0)
    assert rc == 0
    assert len([c for c in calls if " up " in f" {c} "]) == 1


def test_both_launchers_use_it_and_the_rust_code_agrees():
    for name in ("noomesh-start.sh", "noomesh-restart.sh"):
        t = (SCRIPTS / name).read_text()
        assert "lib-stuck-container.sh" in t, name
        assert re.search(r"^\s*noo_compose_up_isolating_stuck compose .* up -d .*--force-recreate", t, re.M), name
        assert '"$NOO_EXIT_STACK_PARTIAL"' in t
    assert "NOO_EXIT_STACK_PARTIAL=75" in (SCRIPTS / "lib-stuck-container.sh").read_text()
    assert "lib-stuck-container.sh" in (REPO_ROOT / "noo-cli" / "build.rs").read_text()
