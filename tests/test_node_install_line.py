# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The node install line the controller hands out downloads THEN runs, from a
private directory it removes (2026-11-12).

`curl … | sh` exits 0 when the download fails (the install matrix measured it
in bash and dash), so a node owner saw a curl error and then "noo: not found".
The line is now composed by gateway-rust's compose_install_command (and
noo-cli's public_install_line, byte-identical): mktemp -d (0700), fetch into
it, run, remove it whatever happened, and exit non-zero on any failure.

These run the gateway's REAL format string, read from its source, in sh, dash
and bash, with a fake curl: the transport is faked, not the line.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHELLS = [s for s in ("sh", "dash", "bash") if shutil.which(s)]


def _line(repo: str = "o/r") -> str:
    src = (ROOT / "gateway-rust/src/routes/bootstrap.rs").read_text()
    body = src[src.index("fn compose_install_command(repo: &str) -> String {"):]
    fmt = re.search(r'format!\(\s*"((?:[^"\\]|\\.)*)"\s*\)', body).group(1)
    return (fmt.replace('\\"', '"').replace("{{", "\x00").replace("}}", "\x01")
            .replace("{repo}", repo).replace("\x00", "{").replace("\x01", "}"))


def _run(tmp: Path, shell: str, curl_body: str, curl_rc: int = 0):
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    payload = tmp / "payload.sh"
    payload.write_text(curl_body)
    (bindir / "curl").write_text(f'#!/bin/sh\n[ {curl_rc} = 0 ] || {{ echo "curl: (6) no host" >&2; exit {curl_rc}; }}\ncat "{payload}"\n')
    (bindir / "curl").chmod(0o755)
    tmpdir = tmp / "tmpdir"
    tmpdir.mkdir(exist_ok=True)
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(tmp), "TMPDIR": str(tmpdir)}
    r = subprocess.run([shell, "-c", _line()], env=env, capture_output=True, text=True, timeout=60)
    return r, list(tmpdir.iterdir())


def test_the_line_has_the_documented_shape():
    line = _line()
    assert line.startswith("command -v noo >/dev/null || { d=\"$(mktemp -d)\" && curl -fsSL "), line
    assert "| sh" not in line and line.endswith('rm -rf "$d"; [ "$r" = 0 ]; }')


@pytest.mark.parametrize("shell", SHELLS)
def test_a_failed_download_fails_the_line_and_leaves_nothing(tmp_path, shell):
    r, left = _run(tmp_path, shell, "echo SHOULD-NOT-RUN\n", curl_rc=6)
    assert r.returncode != 0 and "SHOULD-NOT-RUN" not in r.stdout, (r.returncode, r.stdout)
    assert left == [], f"the private directory must be removed: {left}"


@pytest.mark.parametrize("shell", SHELLS)
def test_the_script_runs_from_a_private_directory_that_is_removed_after(tmp_path, shell):
    probe = 'set -e\nstat -c "mode=%a" "$(dirname "$0")"\necho installed\n'
    r, left = _run(tmp_path, shell, probe)
    assert r.returncode == 0 and "installed" in r.stdout, (r.returncode, r.stdout, r.stderr)
    assert "mode=700" in r.stdout, "mktemp -d gives a directory only this user can read"
    assert left == []


@pytest.mark.parametrize("shell", SHELLS)
def test_a_failing_installer_fails_the_line(tmp_path, shell):
    r, left = _run(tmp_path, shell, "echo half way\nexit 5\n")
    assert r.returncode != 0 and left == []
