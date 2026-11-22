# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Bounds on the two units that could wait for ever (i1160 risks 4 and 7).

Risk 4. `noo-fetch.service` is a oneshot with no start timeout, and the bundle
GET in `noo-fetch.sh` had only `--connect-timeout`. A transfer that stalled
after the headers (the controller lost power mid-pull) left the unit
`activating` for ever; its timer cannot fire while it is, so the node took no
new bundle until a reboot. Now:

- the bundle curl carries `--max-time`, `--speed-limit` and `--speed-time`;
- curl's exit status is read, so a body cut short after a 200 is discarded
  instead of hashed, recorded as undecryptable and never retried;
- every other curl in the script carries `--max-time`;
- the unit carries `TimeoutStartSec=` above the transfer bound plus the apply.

The real test runs the script's own `fetch_bundle` and its `case "$CODE"`
block with the real curl against a local HTTP server that sends the headers and
then stalls (or trickles), with only the time constants shortened, and checks
that it gives up inside the bound with a clear journal line.

Risk 7. `noo-addons-after-boot.service` (a oneshot `WantedBy=multi-user.target`)
had no start timeout, and a target is ordered After= every unit it Wants=
unless that unit sets `DefaultDependencies=no`, so it held multi-user.target for
its whole run. The rendered unit now carries both.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FETCH = ROOT / "scripts/noo-fetch.sh"
PREP = ROOT / "scripts/prep-host.sh"
AFTER_BOOT = ROOT / "noo-cli/src/commands/addon_after_boot.rs"

# What an apply and its report can take under the unit, after the transfer
# (noo-apply.sh: harness stop 150 s + agent stop 50 s and 40 s poll + hostd
# heartbeat 60 s + tailscaled 20 s poll + egress checks 45 s + backend
# restarts; noo-fetch.sh report(): up to 10 rounds of 2 x 20 s + 10 s). The
# unit timeout must leave at least this much above the curl --max-time.
APPLY_AND_REPORT_BUDGET_S = 25 * 60


def _fetch_bundle() -> str:
    m = re.search(r"^fetch_bundle\(\) \{\n.*?^\}\n", FETCH.read_text(), re.S | re.M)
    assert m, "noo-fetch.sh has no fetch_bundle() — this test reads the real function"
    return m.group(0)


def _limits() -> dict[str, int]:
    m = re.search(r'^    _lim="([^"]*)"$', _fetch_bundle(), re.M)
    assert m, "fetch_bundle sets no _lim (the transfer bounds)"
    words = m.group(1).split()
    flags = dict(zip(words[::2], words[1::2]))
    assert set(flags) == {"--max-time", "--speed-limit", "--speed-time"}, flags
    return {k: int(v) for k, v in flags.items()}


# ── source checks ─────────────────────────────────────────────────────

def test_the_bundle_transfer_is_bounded():
    lim = _limits()
    # 1 Mbit/s for the largest bundle seen (~400 MiB) needs 3355 s; the Mac
    # path's cap (900 s) is the floor.
    assert 3355 <= lim["--max-time"] <= 7200, lim
    assert lim["--speed-limit"] >= 1, lim
    assert 1 <= lim["--speed-time"] <= 600, lim
    body = _fetch_bundle()
    curls = re.findall(r'curl -sS[^\n]*', body)
    assert len(curls) == 2, curls
    for c in curls:
        assert "$_lim" in c, c
    assert '2>"$TMP/curlerr" || true' not in body, "curl's exit status must be read, not swallowed"
    assert body.count('2>"$TMP/curlerr")" || _crc=$?') == 2, body


def test_every_other_curl_in_the_fetcher_has_a_max_time():
    src = FETCH.read_text()
    fb = _fetch_bundle()
    rest = src.replace(fb, "")
    calls = re.findall(r'curl -sS[^\n]*', rest)
    assert len(calls) >= 3, calls  # two receipts and the report
    for c in calls:
        assert re.search(r"--max-time [0-9]+", c), c


def _unit(text: str, name: str) -> str:
    m = re.search(r"cat > /etc/systemd/system/" + re.escape(name) + r" <<'UNIT'\n(.*?)\nUNIT\n", text, re.S)
    assert m, f"no {name} heredoc"
    return m.group(1)


def test_the_fetch_unit_has_a_start_timeout_above_the_transfer_and_the_apply():
    unit = _unit(PREP.read_text(), "noo-fetch.service")
    m = re.search(r"^TimeoutStartSec=([0-9]+)$", unit, re.M)
    assert m, unit
    assert "\nType=oneshot\n" in unit, unit
    assert int(m.group(1)) >= _limits()["--max-time"] + APPLY_AND_REPORT_BUDGET_S, (m.group(1), _limits())
    # A timed-out run must be retried by the timer, not latched.
    assert "RemainAfterExit" not in unit and "StartLimit" not in unit, unit


def _after_boot_unit() -> str:
    m = re.search(r'pub fn render_unit\(.*?Ok\(format!\(\n\s*"([^"]*)"', AFTER_BOOT.read_text(), re.S)
    assert m, "render_unit's format string not found"
    return m.group(1).replace("\\n", "\n")


def test_the_after_boot_unit_is_bounded_and_does_not_hold_multi_user_target():
    u = _after_boot_unit()
    m = re.search(r"^TimeoutStartSec=([0-9]+)$", u, re.M)
    assert m, u
    # Gateway wait (300 s) plus at least one launcher run with its compose-lock wait (600 s).
    assert 900 <= int(m.group(1)) <= 3600, u
    assert "\nType=oneshot\n" in u and "\nWantedBy=multi-user.target\n" in u, u
    # No implicit multi-user.target After= this unit; a service's other
    # defaults restored by hand.
    for line in ("DefaultDependencies=no", "Requires=sysinit.target", "After=sysinit.target basic.target",
                 "Conflicts=shutdown.target", "Before=shutdown.target"):
        assert f"\n{line}\n" in u, (line, u)
    assert not re.search(r"^Before=.*multi-user", u, re.M), u


# ── the real transfer against a stalling server ───────────────────────

class _Handler(BaseHTTPRequestHandler):
    mode = "stall"

    def log_message(self, *a):  # keep pytest output clean
        pass

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", str(64 * 1024 * 1024))
        self.end_headers()
        try:
            if self.server.mode == "ok":
                self.wfile.write(b"x" * (64 * 1024 * 1024))
            elif self.server.mode == "short":
                # A 200 that promises 64 MiB, sends 100 bytes and closes:
                # curl gets the whole header and a body cut short (exit 18).
                self.wfile.write(b"x" * 100)
                self.wfile.flush()
            elif self.server.mode == "stall":
                self.wfile.write(b"x" * 100)
                self.wfile.flush()
                time.sleep(30)
            else:  # trickle: 8 KiB/s, above the speed floor, never finishing
                for _ in range(120):
                    self.wfile.write(b"x" * 4096)
                    self.wfile.flush()
                    time.sleep(0.5)
        except (BrokenPipeError, ConnectionResetError):
            pass


def _serve(mode: str):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    srv.mode = mode
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _run_real(tmp_path: Path, mode: str, swap: tuple[str, str] | None):
    if not shutil.which("curl"):
        pytest.skip("no curl here")
    src = FETCH.read_text()
    block = re.search(r"^fetch_bundle\ncase \"\$CODE\" in\n.*?^esac\n", src, re.S | re.M)
    assert block, "noo-fetch.sh has no `fetch_bundle` call followed by its case block"
    fn = _fetch_bundle()
    if swap:
        assert fn.count(swap[0]) == 1, (swap, fn)
        fn = fn.replace(swap[0], swap[1])
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    srv = _serve(mode)
    try:
        harness = (
            f"set -eu\nTMP={tmp}\nLAST={tmp_path}/last-bundle.sha256\nTLS=''\n"
            f"URL=http://127.0.0.1:{srv.server_address[1]}\nNODE=n1\n"
            f"{fn}{block.group(0)}echo REACHED-AFTER-CASE\n"
        )
        shell = shutil.which("dash") or "/bin/sh"
        t0 = time.monotonic()
        r = subprocess.run([shell, "-c", harness], capture_output=True, text=True, timeout=60)
        return r, time.monotonic() - t0, tmp / "blob"
    finally:
        srv.shutdown()
        srv.server_close()


def test_real_curl_gives_up_on_a_transfer_that_stalls_after_the_headers(tmp_path):
    lim = _limits()
    r, took, blob = _run_real(tmp_path, "stall", (f"--speed-time {lim['--speed-time']}", "--speed-time 3"))
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
    assert took < 15, took
    assert "noo-fetch: bundle transfer gave up after HTTP 200 (curl exit 28)" in r.stderr, r.stderr
    assert "noo-fetch: bundle fetch FAILED (HTTP 000): curl: (28)" in r.stderr, r.stderr
    assert "REACHED-AFTER-CASE" not in r.stdout
    assert not blob.exists(), "a cut-short body must not be left to hash"


def test_real_curl_discards_a_body_cut_short_after_a_200(tmp_path):
    # The discard itself, not the time bound: a 200 whose body ends early must
    # not go on to be hashed, recorded in $LAST or decrypted.
    r, took, blob = _run_real(tmp_path, "short", None)
    assert r.returncode != 0, (r.returncode, r.stdout, r.stderr)
    assert took < 15, took
    assert "noo-fetch: bundle transfer gave up after HTTP 200 (curl exit" in r.stderr, r.stderr
    assert "partial body discarded; the next tick retries" in r.stderr, r.stderr
    assert not blob.exists(), "a cut-short body must be removed, not left to hash"
    assert "REACHED-AFTER-CASE" not in r.stdout, r.stdout
    assert not (tmp_path / "last-bundle.sha256").exists()
    assert "decrypt" not in r.stdout + r.stderr


def test_real_curl_gives_up_at_max_time_on_a_trickle_above_the_speed_floor(tmp_path):
    lim = _limits()
    r, took, blob = _run_real(tmp_path, "trickle", (f"--max-time {lim['--max-time']}", "--max-time 4"))
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
    assert 3.5 <= took < 15, took
    assert "noo-fetch: bundle transfer gave up after HTTP 200 (curl exit 28)" in r.stderr, r.stderr
    assert "Operation timed out" in r.stderr, r.stderr
    assert not blob.exists()


def test_real_curl_still_takes_a_whole_bundle_within_the_bounds(tmp_path):
    r, _, blob = _run_real(tmp_path, "ok", None)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "REACHED-AFTER-CASE" in r.stdout
    assert blob.stat().st_size == 64 * 1024 * 1024
    assert "gave up" not in r.stderr
