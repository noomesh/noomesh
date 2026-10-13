# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`scripts/prep-host.sh` names the platform itself and never guesses.

2026-10-10: a fresh Pop!_OS 24.04 box (`ID=pop`, `ID_LIKE="ubuntu debian"`)
was prepped by `get.docker.com`, which does not know `pop`, fell back to
Debian, read `/etc/debian_version` (`trixie/sid` on Ubuntu noble) and wrote a
`debian trixie` Docker repo; `apt-get install docker-ce` then died on held
broken packages, after the single-use enrollment token was already spent.

What this pins:

  1. the resolver maps each os-release fixture to the family, codename and
     package manager the Docker repo line is built from (Pop!_OS, Mint and
     Zorin resolve through UBUNTU_CODENAME to ubuntu);
  2. an Ubuntu-like os-release with no UBUNTU_CODENAME resolves to an
     unknown codename and check mode FAILs it;
  3. the script never reads `/etc/debian_version`;
  4. `PREP_CHECK=1` runs unprivileged and exits before the root guard.

The machine-dependent checks (systemd, docker, network) differ per test box,
so these tests assert the platform line and the exit-before-root behaviour,
never the overall pass or fail.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PREP = ROOT / "scripts" / "prep-host.sh"
FIXTURES = ROOT / "tests" / "fixtures" / "os-release"

# fixture -> (family, codename, pkg)
CASES = {
    "pop-24.04": ("ubuntu", "noble", "apt"),
    "mint-22": ("ubuntu", "noble", "apt"),
    "zorin-17": ("ubuntu", "jammy", "apt"),
    "ubuntu-22.04": ("ubuntu", "jammy", "apt"),
    "ubuntu-24.04": ("ubuntu", "noble", "apt"),
    "debian-12": ("debian", "bookworm", "apt"),
    "debian-13": ("debian", "trixie", "apt"),
    "raspbian-bookworm": ("raspbian", "bookworm", "apt"),
    "fedora-40": ("fedora", "unknown", "dnf"),
    "arch": ("arch", "unknown", "pacman"),
    "ubuntu-like-no-codename": ("ubuntu", "unknown", "apt"),
}

PLATFORM_LINE = re.compile(
    r"^prep-check: platform=(\S+) codename=(\S+) pkg=(\S+)$", re.MULTILINE
)


def run_check(os_release: Path, extra_env: dict | None = None):
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PREP_CHECK": "1",
        "OS_RELEASE_FILE": str(os_release),
    }
    env.update(extra_env or {})
    return subprocess.run(
        ["bash", str(PREP)], env=env, capture_output=True, text=True, timeout=120
    )


def platform_of(proc):
    m = PLATFORM_LINE.search(proc.stdout)
    assert m, f"no `prep-check: platform=` line in output:\n{proc.stdout}\n{proc.stderr}"
    return m.groups()


def test_fixtures_exist():
    found = {p.name for p in FIXTURES.iterdir()}
    assert set(CASES) <= found, f"missing fixtures: {set(CASES) - found}"


@pytest.mark.parametrize("name", sorted(CASES))
def test_resolves_fixture(name):
    proc = run_check(FIXTURES / name)
    got = platform_of(proc)  # asserts the line was found first
    assert got == CASES[name], f"{name}: {got}"


def test_ubuntu_like_without_codename_fails_with_remedy():
    proc = run_check(FIXTURES / "ubuntu-like-no-codename")
    assert platform_of(proc)[1] == "unknown"
    fails = [l for l in proc.stdout.splitlines() if l.startswith("prep-check: FAIL")]
    assert fails, f"expected a FAIL line:\n{proc.stdout}"
    assert any("codename" in l and "install Docker by hand" in l for l in fails)
    assert proc.returncode == 1


def test_missing_os_release_is_unknown_not_a_crash(tmp_path):
    proc = run_check(tmp_path / "does-not-exist")
    assert platform_of(proc) == ("unknown", "unknown", "none")


def test_hostile_os_release_is_parsed_not_executed(tmp_path):
    marker = tmp_path / "pwned"
    f = tmp_path / "os-release"
    f.write_text(f'ID=ubuntu\nVERSION_CODENAME=noble\n$(touch {marker})\ntouch {marker}\n')
    proc = run_check(f)
    assert platform_of(proc) == ("ubuntu", "noble", "apt")
    assert not marker.exists(), "os-release content was executed"


def test_script_never_reads_debian_version():
    lines = PREP.read_text().splitlines()
    code = [l for l in lines if not l.lstrip().startswith("#")]
    assert len(code) > 100, "script parse found almost no code lines"
    offenders = [l for l in code if "debian_version" in l]
    assert not offenders, f"prep-host.sh reads /etc/debian_version: {offenders}"


def test_check_mode_exits_before_root_guard():
    if os.geteuid() == 0:
        pytest.skip("needs an unprivileged user to prove the guard is not hit")
    proc = run_check(FIXTURES / "pop-24.04")
    platform_of(proc)  # the check actually ran
    assert "must run as root" not in proc.stdout + proc.stderr
    assert proc.returncode in (0, 1)
