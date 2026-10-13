# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Regression tests for scripts/backup-controller.sh retention.

Observed 2026-08-01: the nightly database_backup task reported FAILED on
every run while the backups themselves were fine. The dump was written
(131 MB, encrypted), then the script died in the retention block and never
reached "Backup complete", so the caller saw exit 1.

Cause: `ls -t "$DIR"/pg_*.sql.gz "$DIR"/pg_*.sql.gz.enc` exits NON-ZERO when
EITHER glob matches nothing. Every backup on this host is encrypted, so the
plaintext glob never matched, `ls` exited 2, and `set -euo pipefail` aborted
the script AFTER the work was done.

These tests execute the retention block extracted from the real script rather
than a hand-copied approximation, so they fail if the shell changes back.
"""

import re
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "backup-controller.sh"


def _retention_block() -> str:
    """Pull the `if [ "$PG_OK" = 1 ]; then ... fi` retention block from source."""
    text = SCRIPT.read_text()
    start = text.index('PG_KEEP_MIN="${NOO_BACKUP_KEEP_MIN:-3}"')
    # The block ends at the first line that is exactly "fi" at column 0.
    end = re.search(r"^fi$", text[start:], re.MULTILINE)
    assert end, "could not locate end of retention block"
    return text[start : start + end.end()]


def _run_retention(backup_dir: Path) -> subprocess.CompletedProcess:
    script = "\n".join(
        [
            "set -euo pipefail",
            f'BACKUP_DIR="{backup_dir}"',
            "PG_OK=1",
            "RETAIN_DAYS=7",
            _retention_block(),
            'echo "REACHED_END"',
        ]
    )
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=60
    )


def test_retention_survives_encrypted_only_dir(tmp_path):
    """The exact production shape: only .enc files, plaintext glob unmatched.

    Before the fix this exits 2 and never prints REACHED_END, which is how a
    fully successful backup got reported as a failure.
    """
    for name in ("pg_1.sql.gz.enc", "pg_2.sql.gz.enc", "pg_3.sql.gz.enc"):
        (tmp_path / name).touch()

    res = _run_retention(tmp_path)

    assert res.returncode == 0, f"retention aborted: {res.stderr}"
    assert "REACHED_END" in res.stdout, "script died before completing"


def test_retention_survives_empty_dir(tmp_path):
    """No backups at all (first run) must not fail the script either."""
    res = _run_retention(tmp_path)

    assert res.returncode == 0, f"retention aborted on empty dir: {res.stderr}"
    assert "REACHED_END" in res.stdout


def test_retention_keeps_recent_backups(tmp_path):
    """Guard the fix against over-correction: `|| true` must not disable pruning.

    All files are new, so age-based deletion should remove nothing.
    """
    names = [f"pg_{i}.sql.gz.enc" for i in range(6)]
    for name in names:
        (tmp_path / name).touch()

    res = _run_retention(tmp_path)

    assert res.returncode == 0
    remaining = {p.name for p in tmp_path.iterdir()}
    assert remaining == set(names), "recent backups must never be deleted"
