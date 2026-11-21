# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The root watchdog's kiosk.service restart is bounded (i1153).

A dedicated seat booted with kiosk.service's start job queued behind
plymouth-quit-wait.service, which never finished. The watchdog's blocking
`systemctl restart kiosk.service` queued behind the same job and hung its
tick, and with it every later tick. Now it restarts with --no-block, waits
for the job a bounded number of polls, and on timeout says what the job is
queued behind. These cases run the script's own functions against a fake
systemctl.
"""

from __future__ import annotations

import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WATCHDOG = ROOT / "noo-cli" / "src" / "commands" / "kiosk_assets" / "noo-kiosk-watchdog"
UNIT_RS = ROOT / "noo-cli" / "src" / "commands" / "kiosk.rs"


def _functions() -> str:
    src = WATCHDOG.read_text()
    start = src.index("RESTART_BOUND=")
    end = src.index("if ! as_kiosk noo-kiosk-cdp probe")
    return src[start:end]


def _exe(p: Path, body: str) -> None:
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


def _run(tmp: Path, job: str) -> subprocess.CompletedProcess[str]:
    b = tmp / "bin"
    b.mkdir()
    log = tmp / "systemctl.log"
    _exe(b / "systemctl", f"""echo "$*" >> {log}
case "$*" in
  "show -p Job --value kiosk.service") printf '%s\\n' "{job}" ;;
  "show -p After --value kiosk.service") echo "systemd-user-sessions.service plymouth-quit-wait.service kiosk-serve.service" ;;
  "list-jobs --no-legend --full --no-pager") printf '%s\\n' "7 kiosk.service start waiting" "3 plymouth-quit-wait.service start running" "9 other.service start running" ;;
esac
exit 0
""")
    _exe(b / "sleep", "exit 0\n")
    script = (
        'fail() { echo "FAIL: $1"; }\n'
        + _functions()
        + 'restart_kiosk_bounded; echo "rc=$?"\n'
    )
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=60,
        env={"PATH": f"{b}:/usr/bin:/bin"},
    )


def test_a_queued_restart_gives_up_at_the_bound_and_names_the_blocker(tmp_path: Path) -> None:
    out = _run(tmp_path, "7")
    assert "rc=1" in out.stdout, out
    assert (
        "FAIL: kiosk.service did not start within 60 s: a start job is queued behind plymouth-quit-wait.service"
        in out.stdout
    ), out.stdout
    calls = (tmp_path / "systemctl.log").read_text().splitlines()
    assert calls[0] == "restart kiosk.service --no-block", calls
    assert calls.count("show -p Job --value kiosk.service") == 60, "bounded: 60 polls, no more"


def test_a_restart_whose_job_finishes_returns_at_once(tmp_path: Path) -> None:
    out = _run(tmp_path, "")
    assert "rc=0" in out.stdout and "FAIL" not in out.stdout, out


def test_the_watchdog_never_runs_a_blocking_restart() -> None:
    code = [l for l in WATCHDOG.read_text().splitlines() if not l.lstrip().startswith("#")]
    restarts = [l.strip() for l in code if "systemctl restart" in l]
    assert restarts and all("--no-block" in l for l in restarts), restarts


def test_the_watchdog_unit_does_not_queue_behind_the_display_and_is_bounded() -> None:
    src = UNIT_RS.read_text()
    body = src[src.index("pub(crate) fn render_watchdog_service()"):]
    body = body[: body.index("\n}\n")]
    directives = [l for l in body.splitlines() if "#" not in l]
    assert not any("After=kiosk.service" in l for l in directives), "the rescue queues behind the stuck display"
    assert any("TimeoutStartSec=" in l for l in directives), "a hung tick stops the timer for good"
