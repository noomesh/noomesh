# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""noo-kiosk-launch says why before any exit, in $STATE/last-error and
through logger, never with the URL or an env value.

After the 0.6.25 roll node-h's kiosk.service exited 1 in the same second
in a restart loop, and the journal held only systemd's lines: the launcher
ran under `set -euo pipefail`, and only its proxy-wait path wrote a reason.
Each case here runs the real launcher with fakes for cage and logger.
"""

from __future__ import annotations

import os
import signal
import socket
import stat
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAUNCH = ROOT / "noo-cli" / "src" / "commands" / "kiosk_assets" / "noo-kiosk-launch"
SECRET_URL = "https://secret-host.example/?token=s3cr3t"


def _exe(p: Path, body: str) -> None:
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


def _env(tmp: Path, port: int, *, url: str | None = SECRET_URL, state: Path | None = None, cage: str = "exit 1\n") -> dict[str, str]:
    b = tmp / "bin"
    b.mkdir(exist_ok=True)
    _exe(b / "cage", cage)
    _exe(b / "logger", 'echo "$@" >> "$LOGGER_LOG"\n')
    e = {
        "PATH": f"{b}:/usr/bin:/bin",
        "HOME": str(tmp),
        "LOGGER_LOG": str(tmp / "logger.log"),
        "NOO_KIOSK_STATE": str(state or tmp / "state"),
        "NOO_KIOSK_SERVE_PORT": str(port),
    }
    if url is not None:
        e["NOO_KIOSK_URL"] = url
    (tmp / "logger.log").write_text("")
    return e


def _listener() -> socket.socket:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    return s


def _said(tmp: Path, state: Path) -> str:
    err = state / "last-error"
    return (err.read_text() if err.exists() else "") + "\n" + (tmp / "logger.log").read_text()


def test_cage_ending_at_once_is_named_without_the_url(tmp_path: Path) -> None:
    srv = _listener()
    try:
        env = _env(tmp_path, srv.getsockname()[1])
        r = subprocess.run(["bash", str(LAUNCH)], env=env, capture_output=True, text=True, timeout=30)
    finally:
        srv.close()
    assert r.returncode == 1, (r.returncode, r.stderr)
    said = _said(tmp_path, tmp_path / "state")
    assert "cage exited 1: the broker or the browser under it ended" in (tmp_path / "state" / "last-error").read_text(), said
    assert "-t noo-kiosk-launch -p user.err" in (tmp_path / "logger.log").read_text(), "logger reaches the journal"
    for leak in ("secret-host", "s3cr3t", "token="):
        assert leak not in said and leak not in r.stderr, (leak, said, r.stderr)


def test_an_unset_url_is_said_by_name(tmp_path: Path) -> None:
    env = _env(tmp_path, 9, url=None)
    r = subprocess.run(["bash", str(LAUNCH)], env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 1
    assert "NOO_KIOSK_URL is not set (see /etc/default/kiosk)" in _said(tmp_path, tmp_path / "state")


def test_a_set_e_trip_names_the_command_and_its_exit(tmp_path: Path) -> None:
    # $STATE is a file, so `mkdir -p "$PROFILE"` fails under set -e. The
    # reason goes to logger (last-error cannot be written under a file).
    blocker = tmp_path / "statefile"
    blocker.write_text("")
    env = _env(tmp_path, 9, state=blocker)
    r = subprocess.run(["bash", str(LAUNCH)], env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 1
    log = (tmp_path / "logger.log").read_text()
    assert "'mkdir' failed with exit 1" in log, log
    assert "secret-host" not in log


def test_a_stop_is_not_recorded_as_a_failure(tmp_path: Path) -> None:
    srv = _listener()
    try:
        env = _env(tmp_path, srv.getsockname()[1], cage="exec sleep 30\n")
        p = subprocess.Popen(["bash", str(LAUNCH)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             start_new_session=True)
        deadline = time.time() + 10
        while time.time() < deadline and not (tmp_path / "state" / "profile").exists():
            time.sleep(0.1)
        time.sleep(0.5)
        p.send_signal(signal.SIGTERM)
        p.wait(timeout=10)
    finally:
        srv.close()
        try:
            os.killpg(p.pid, signal.SIGKILL)  # the fake cage's sleep
        except (ProcessLookupError, PermissionError, NameError):
            pass
    assert p.returncode == 143, p.returncode
    assert not (tmp_path / "state" / "last-error").exists()
    assert (tmp_path / "logger.log").read_text() == ""
