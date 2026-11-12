# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The install line fails loudly, and a truncated installer runs nothing
(2026-11-12).

The install matrix (run 43160416462, ubuntu-22.04) lost DNS for a moment:
`curl -fsSL <url> | sh` printed a curl error, sh read an empty script, and the
line exited 0, so the stranger's next command said "noo: not found". Measured
in bash and dash: `curl … | sh` and `sh -c "$(curl …)"` both exit 0 on a
failed download; only download-then-run (`curl … -o install.sh && sh
install.sh`) exits non-zero. Every documented line now has that form, and
install.sh is one brace group, so a body cut short anywhere is a syntax error
before anything runs.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "noo-cli" / "install.sh"
DOCS = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
SHELLS = [s for s in ("sh", "dash", "bash", "zsh") if shutil.which(s)]


def _documented_install_lines() -> list[tuple[str, str]]:
    out = []
    for p in DOCS:
        if "archive" in p.parts:
            continue
        for line in p.read_text(errors="replace").splitlines():
            if "curl" in line and re.search(r"/install\.sh\b", line) and "raw.githubusercontent" not in line:
                out.append((str(p.relative_to(ROOT)), line.strip()))
    return out


def test_every_documented_install_line_downloads_then_runs():
    lines = _documented_install_lines()
    assert any(f == "README.md" for f, _ in lines), "the README's install line was not found"
    for f, line in lines:
        assert not re.search(r"\|\s*(\w+=\S+\s+)*sh\b", line), f"{f}: `curl … | sh` exits 0 when the download fails: {line}"
        assert "-o install.sh && sh install.sh" in line, f"{f}: {line}"


def _readme_line() -> str:
    return next(l for f, l in _documented_install_lines() if f == "README.md")


@pytest.mark.parametrize("shell", SHELLS)
def test_a_failed_download_fails_the_line_in_every_shell(tmp_path, shell):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "curl").write_text('#!/bin/sh\necho "curl: (6) Could not resolve host: github.com" >&2\nexit 6\n')
    (bindir / "curl").chmod(0o755)
    env = {"PATH": f"{bindir}:/usr/bin:/bin", "HOME": str(tmp_path)}
    new = subprocess.run([shell, "-c", _readme_line()], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert new.returncode != 0, (shell, new.stdout, new.stderr)
    old = subprocess.run([shell, "-c", _readme_line().replace(" -o install.sh && sh install.sh", " | sh")],
                         cwd=tmp_path, env=env, capture_output=True, text=True)
    assert old.returncode == 0, "the old form's silent success is why the line changed; if this changes, re-measure"


def _cut_points(data: bytes) -> list[int]:
    ends = [i + 1 for i, b in enumerate(data) if b == ord("\n")]
    every = list(range(1, len(data), max(1, len(data) // 150)))
    tail = list(range(max(1, len(data) - 200), len(data)))
    return sorted(set(ends + every + tail) - {len(data)})


@pytest.mark.parametrize("shell", [s for s in ("sh", "dash", "bash") if shutil.which(s)])
def test_a_truncated_installer_runs_nothing(tmp_path, shell):
    data = INSTALL.read_bytes()
    assert subprocess.run([shell, "-n", str(INSTALL)]).returncode == 0, "the whole script parses"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    marker = tmp_path / "ran"
    # Any external tool the script would reach first leaves a trace.
    for tool in ("uname", "curl", "wget", "mktemp", "id", "sha256sum", "shasum", "python3", "openssl", "tr", "sed"):
        (bindir / tool).write_text(f'#!/bin/sh\necho "{tool}" >> "{marker}"\nexit 0\n')
        (bindir / tool).chmod(0o755)
    cut = tmp_path / "cut.sh"
    real_end = len(data.rstrip(b"\n"))  # the bytes after the closing brace are only newlines
    opened = data.index(b"\n{") + 2       # the group opens on line 4, right after the copyright
    assert opened < 120, "the brace group must open at the top: a cut before it exits 0 silently"
    for n in _cut_points(data):
        if n >= real_end:
            continue  # the whole script, only trailing newline(s) missing
        cut.write_bytes(data[:n])
        r = subprocess.run([shutil.which(shell), str(cut)], env={"PATH": str(bindir), "HOME": str(tmp_path)},
                           capture_output=True, text=True, timeout=30)
        assert not marker.exists() and r.stdout == "", \
            f"{shell}: a script cut at byte {n} of {len(data)} ran: {r.stdout[:200]!r}"
        if n >= opened:
            assert r.returncode != 0, f"{shell}: a cut at byte {n} (inside the group) must fail, not exit 0"
