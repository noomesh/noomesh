# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`noo-fetch.sh` fails its unit when the fetch could not reach the controller.

Finding 121: a self node polled https://localhost:8080 against a gateway bound
to the tailnet only. Every tick printed "bundle fetch FAILED (HTTP 000)" and
then exited 0, so `systemctl status noo-fetch.service` read status=0/SUCCESS
and nothing looked wrong.

The real script runs under `sh` with its config directory pointed at a scratch
dir and a fake `curl` first on PATH (the transport is faked, not the script):

- no HTTP answer (curl exit 7), a 5xx, a TLS refusal  -> exit 1, reason in stderr;
- 404 (nothing staged)                                 -> exit 0, quiet;
- not enrolled / no controller-url / throttled tick    -> exit 0, curl not called.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/noo-fetch.sh"

FAKE_CURL = """#!/bin/sh
# Records the call, then answers like curl -w '%{http_code}' would.
echo "$*" >> "$FAKE_CURL_LOG"
case "$FAKE_CURL_MODE" in
    refused) echo "curl: (7) Failed to connect to localhost port 8080" >&2; printf '000'; exit 7 ;;
    tls)     echo "curl: (60) SSL certificate problem" >&2; printf '000'; exit 60 ;;
    *)       printf '%s' "$FAKE_CURL_MODE"; exit 0 ;;
esac
"""


def _env(tmp: Path, mode: str, *, url: str | None = "https://localhost:8080", enrolled: bool = True,
         expect: bool = True) -> tuple[list[str], dict[str, str], Path]:
    conf = tmp / "etc-noo"
    conf.mkdir()
    if enrolled:
        (conf / "node-name").write_text("ctl\n")
        (conf / "birth.key").write_text("not a real key\n")
        (conf / "pki").mkdir()
        (conf / "pki/ca.crt").write_text("not a real ca\n")
    if url is not None:
        (conf / "controller-url").write_text(url + "\n")
    if expect:
        (conf / "expect-bundle").write_text("10\n")
    else:
        (conf / "fetch-state").write_text("0\n")  # next tick is 1 of 3: throttled
    script = tmp / "noo-fetch.sh"
    text = SCRIPT.read_text()
    assert "CONF_DIR=/etc/noo\n" in text, "noo-fetch.sh no longer names its config dir this way"
    script.write_text(text.replace("CONF_DIR=/etc/noo\n", f"CONF_DIR={conf}\n", 1))
    bindir = tmp / "bin"
    bindir.mkdir()
    curl = bindir / "curl"
    curl.write_text(FAKE_CURL)
    curl.chmod(curl.stat().st_mode | stat.S_IXUSR)
    log = tmp / "curl.log"
    env = {
        "PATH": f"{bindir}:/usr/bin:/bin",
        "FAKE_CURL_MODE": mode,
        "FAKE_CURL_LOG": str(log),
        "TMPDIR": str(tmp),
    }
    return ["/bin/sh", str(script)], env, log


def _run(tmp_path: Path, mode: str, **kw) -> tuple[subprocess.CompletedProcess, str]:
    argv, env, log = _env(tmp_path, mode, **kw)
    r = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=30)
    return r, (log.read_text() if log.exists() else "")


@pytest.mark.parametrize("mode,reason", [
    ("refused", "HTTP 000"),
    ("tls", "HTTP 000"),
    ("502", "HTTP 502"),
    ("503", "HTTP 503"),
])
def test_a_fetch_that_cannot_reach_the_controller_fails_the_unit(tmp_path, mode, reason):
    r, calls = _run(tmp_path, mode)
    assert "https://localhost:8080/bootstrap/bundle/ctl" in calls, f"the script never polled the recorded URL: {calls!r}"
    assert r.returncode == 1, (r.returncode, r.stderr)
    assert "bundle fetch FAILED" in r.stderr and reason in r.stderr, r.stderr


def test_nothing_staged_stays_green(tmp_path):
    r, calls = _run(tmp_path, "404")
    assert calls, "the fetch was not attempted"
    assert r.returncode == 0, (r.returncode, r.stderr)
    assert "FAILED" not in r.stderr, r.stderr


@pytest.mark.parametrize("kw", [
    {"enrolled": False},
    {"url": None},
    {"expect": False},
], ids=["not-enrolled", "no-controller-url", "throttled-tick"])
def test_the_nothing_to_do_paths_stay_green_without_calling_the_controller(tmp_path, kw):
    r, calls = _run(tmp_path, "refused", **kw)
    assert r.returncode == 0, (r.returncode, r.stderr)
    assert calls == "", f"curl was called on a nothing-to-do path: {calls!r}"
