# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The compose lock holds even when the lock file is not writable by us.

rc.1 rehearsal (2026-11-12): root's after-boot unit created
/tmp/noo-compose.lock 0644; the owner's `exec 9>>` was refused, and its
compose ran "continuing UNLOCKED", the interleaving the lock exists to stop.
The library now opens it read-only (flock needs no write access).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "scripts" / "lib-compose-lock.sh"


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes a 0444 file anyway; the case is a non-root owner")
def test_an_unwritable_lock_file_is_still_locked(tmp_path: Path) -> None:
    lock = tmp_path / "noo-compose.lock"
    lock.write_text("")
    lock.chmod(0o444)
    # Take the lock in bash, then (still holding it) ask flock -n from a
    # second process: it must be refused.
    script = f'''
        set -u
        COMPOSE_LOCK_FILE="{lock}" COMPOSE_LOCK_WAIT=1
        . "{LIB}"
        acquire_compose_lock || exit 7
        if flock -n "{lock}" true; then echo NOT-HELD; else echo HELD; fi
    '''
    p = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    assert "UNLOCKED" not in p.stderr, p.stderr
    assert p.stdout.strip() == "HELD", (p.stdout, p.stderr)


def test_hostd_and_the_scripts_still_name_the_same_lock() -> None:
    """Single-flight needs ONE lock: the path is unchanged on both sides."""
    sh = LIB.read_text()
    go = (ROOT / "node-agent-go/internal/hostd/lock_unix.go").read_text()
    assert 'COMPOSE_LOCK_FILE="${COMPOSE_LOCK_FILE:-${TMPDIR:-/tmp}/noo-compose.lock}"' in sh
    assert 'filepath.Join(tmp, "noo-compose.lock")' in go
