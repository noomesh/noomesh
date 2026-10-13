# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`docker/redis-entrypoint.sh` learns `REDIS_PASSWORD_FILE`.

The script is run for real, with a fake `redis-server` first on PATH that
records what it was exec'd with and copies the config it was handed, so
each case asserts on what redis WOULD have seen: the password from the
file (one trailing newline gone), a refusal when both env and file are
set, a refusal when the file is unreadable, and the pre-existing refusal
on an empty password still standing.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "docker/redis-entrypoint.sh"


def _run(tmp_path: Path, env: dict[str, str]) -> tuple[subprocess.CompletedProcess, Path]:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    seen = tmp_path / "seen.conf"
    fake = bindir / "redis-server"
    fake.write_text(f'#!/bin/sh\ncp "$1" "{seen}"\necho "redis-server argv: $*"\n')
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    full_env = {
        "PATH": f"{bindir}:{os.environ.get('PATH', '')}",
        "REDIS_CONF_PATH": str(tmp_path / "redis-noo.conf"),
        **env,
    }
    proc = subprocess.run(
        ["sh", str(SCRIPT)], env=full_env, capture_output=True, text=True, timeout=30
    )
    return proc, seen


def _requirepass(seen: Path) -> str:
    lines = [ln for ln in seen.read_text().splitlines() if ln.startswith("requirepass ")]
    assert len(lines) == 1, seen.read_text()
    return lines[0][len("requirepass "):]


def test_the_fake_is_what_ran() -> None:
    """Guard the guard: the script must still exec `redis-server <conf>`."""
    assert 'exec redis-server "$CONF"' in SCRIPT.read_text()


def test_env_delivery_still_works(tmp_path: Path) -> None:
    proc, seen = _run(tmp_path, {"REDIS_PASSWORD": "from-env"})
    assert proc.returncode == 0, proc.stderr
    assert _requirepass(seen) == "from-env"


def test_file_delivery_strips_the_trailing_newline(tmp_path: Path) -> None:
    f = tmp_path / "pw"
    f.write_text("from-file\n")
    proc, seen = _run(tmp_path, {"REDIS_PASSWORD_FILE": str(f)})
    assert proc.returncode == 0, proc.stderr
    assert _requirepass(seen) == "from-file"
    assert "from-file" not in proc.stdout.split("argv:")[1], "password reached argv"


def test_both_set_is_refused(tmp_path: Path) -> None:
    f = tmp_path / "pw"
    f.write_text("from-file\n")
    proc, seen = _run(tmp_path, {"REDIS_PASSWORD": "from-env", "REDIS_PASSWORD_FILE": str(f)})
    assert proc.returncode == 1
    assert "both REDIS_PASSWORD and REDIS_PASSWORD_FILE" in proc.stderr
    assert not seen.exists(), "redis-server was exec'd despite the refusal"


def test_unreadable_file_is_refused(tmp_path: Path) -> None:
    proc, seen = _run(tmp_path, {"REDIS_PASSWORD_FILE": str(tmp_path / "missing")})
    assert proc.returncode == 1
    assert "cannot be read" in proc.stderr
    assert not seen.exists()


@pytest.mark.parametrize("env", [{}, {"REDIS_PASSWORD": ""}])
def test_empty_password_is_still_refused(tmp_path: Path, env: dict[str, str]) -> None:
    proc, seen = _run(tmp_path, env)
    assert proc.returncode == 1
    assert "REDIS_PASSWORD is empty" in proc.stderr
    assert not seen.exists()


def test_empty_file_is_refused_as_an_empty_password(tmp_path: Path) -> None:
    f = tmp_path / "pw"
    f.write_text("\n")
    proc, seen = _run(tmp_path, {"REDIS_PASSWORD_FILE": str(f)})
    assert proc.returncode == 1
    assert "REDIS_PASSWORD is empty" in proc.stderr
    assert not seen.exists()


def test_the_standalone_controller_ships_this_script() -> None:
    """`noo-cli/build.rs` embeds the entrypoint for the standalone controller
    (`repo_root()` is `~/.noo` there, so only the STANDALONE_FILES list
    materialises); a `_FILE` branch that only lives in git helps nobody."""
    build = (ROOT / "noo-cli/build.rs").read_text()
    assert '"docker/redis-entrypoint.sh",' in build
