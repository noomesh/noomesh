# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""noo-deenroll (scripts/deenroll-node-local.sh) dismantles a node. It must
never act on a flag it does not know, and a person must confirm.

i545 finding 103: an outside tester ran `noo-deenroll --help` to read its
usage. The script ignored the flag, dismantled the node and logged it out of
Tailscale.

Safety of THIS test: the batch and CI can run tests as root. So the script is
never run whole. Only its prologue runs: everything above the first
destructive section ("# ── agent + containers"), with a marker appended. A
broken guard reaches the marker and fails the test; it cannot reach a single
`rm` or `systemctl` on the machine running the test.
"""
from __future__ import annotations

import os
import pty
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "deenroll-node-local.sh"
FIRST_DESTRUCTIVE = "# ── agent + containers"
MARKER = "PROLOGUE-PASSED-WOULD-DISMANTLE"


@pytest.fixture()
def prologue(tmp_path: Path) -> Path:
    src = SCRIPT.read_text()
    assert FIRST_DESTRUCTIVE in src, "the test cuts the script at its first destructive section"
    head = src.split(FIRST_DESTRUCTIVE, 1)[0]
    # The prologue must run no destructive command, or cutting here is not
    # safe. Read its CODE lines only: after the usage text, comments dropped.
    assert "USAGE\n}" in head, "the usage function is in the prologue"
    code = [ln for ln in head.split("USAGE\n}", 1)[1].splitlines() if not ln.strip().startswith("#")]
    for word in ("rm ", "systemctl ", "userdel ", "groupdel ", "docker ", "tailscale ", "shred "):
        hits = [ln for ln in code if word in ln and not ln.strip().startswith(("echo ", "printf "))]
        assert not hits, f"'{word.strip()}' runs before the first destructive section; move the cut: {hits}"
    p = tmp_path / "deenroll-prologue.sh"
    p.write_text(head + f"\necho {MARKER}\nexit 0\n")
    p.chmod(0o755)
    return p


def _fake_root(tmp_path: Path) -> dict[str, str]:
    """PATH with an `id` that says uid 0 and a fixed `hostname`, so the prologue
    runs as if under sudo without the test needing root."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("id", 'echo 0'), ("hostname", 'echo testnode')):
        f = bin_dir / name
        f.write_text(f"#!/bin/sh\n{body}\n")
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '/usr/bin:/bin')}"
    env.pop("SUDO_USER", None)
    return env


def _run(script: Path, *args: str, env=None, stdin=subprocess.DEVNULL):
    return subprocess.run(["bash", str(script), *args], env=env, stdin=stdin,
                          capture_output=True, text=True, timeout=20)


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help_prints_usage_and_changes_nothing(prologue: Path, tmp_path: Path, flag: str) -> None:
    # As fake root too: --help must win even where the script could act.
    r = _run(prologue, flag, env=_fake_root(tmp_path))
    assert r.returncode == 0, r.stderr
    assert "usage: sudo noo-deenroll" in r.stdout
    assert MARKER not in r.stdout, "--help went on towards the dismantle"


def test_an_unknown_argument_is_refused_before_anything_runs(prologue: Path, tmp_path: Path) -> None:
    r = _run(prologue, "--purge-everything", "--yes", env=_fake_root(tmp_path))
    assert r.returncode == 2, (r.returncode, r.stdout, r.stderr)
    assert "unknown argument '--purge-everything'" in r.stderr
    assert MARKER not in r.stdout


def test_no_terminal_and_no_yes_is_a_refusal(prologue: Path, tmp_path: Path) -> None:
    r = _run(prologue, env=_fake_root(tmp_path))  # stdin is /dev/null, not a terminal
    assert r.returncode == 2, (r.returncode, r.stdout, r.stderr)
    assert "pass --yes" in r.stderr
    assert MARKER not in r.stdout


def test_a_wrong_name_at_the_prompt_changes_nothing(prologue: Path, tmp_path: Path) -> None:
    master, slave = pty.openpty()
    try:
        os.write(master, b"not-this-box\n")
        r = _run(prologue, env=_fake_root(tmp_path), stdin=slave)
    finally:
        os.close(slave)
        os.close(master)
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
    assert MARKER not in r.stdout


def test_the_right_name_at_the_prompt_goes_ahead(prologue: Path, tmp_path: Path) -> None:
    master, slave = pty.openpty()
    try:
        os.write(master, b"testnode\n")
        r = _run(prologue, env=_fake_root(tmp_path), stdin=slave)
    finally:
        os.close(slave)
        os.close(master)
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert MARKER in r.stdout


@pytest.mark.parametrize("flag", ["--yes", "--from-gate"])
def test_yes_and_the_controllers_teardown_skip_the_prompt(prologue: Path, tmp_path: Path, flag: str) -> None:
    # --from-gate is how noo-apply's teardown runs it (no person, no terminal).
    r = _run(prologue, flag, env=_fake_root(tmp_path))
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert MARKER in r.stdout


def test_the_controllers_teardown_still_passes_only_known_flags() -> None:
    apply = (REPO / "scripts" / "noo-apply.sh").read_text()
    assert 'DEENROLL_ARGS="--from-gate"' in apply
    for extra in ("--purge-data", "--purge-tailscale"):
        assert f'DEENROLL_ARGS="$DEENROLL_ARGS {extra}"' in apply
