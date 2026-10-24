# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The off-site setting reaches every backup path, and the run says what happened.

2026-10-24, pop-os: `noo backups setup --set dir:/mnt/fleet/backups/...` wrote
NOO_BACKUP_OFFSITE to the checkout's .env. The scheduled backup ran through
noo-hostd, which loads the secret store and noomesh.yaml but not plain .env
values, so the script saw it unset, printed "offsite: not configured", exited 0,
and the heartbeat recorded success. The target directory was never created.

These run the REAL script text under bash (the resolver prologue and the
`offsite_copy` function, extracted), not a description of it.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "scripts/backup-controller.sh").read_text(encoding="utf-8")


def _prologue() -> str:
    end = SCRIPT.index("# ── Preflight")
    return SCRIPT[:end]


def _offsite_fn() -> str:
    start = SCRIPT.index("offsite_copy() {")
    end = SCRIPT.index("\n}\n", start) + 3
    return SCRIPT[start:end]


def _clean_env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("NOO_")}
    env.update(extra)
    return env


def _run_prologue(tmp: Path, dotenv: str | None, env: dict[str, str]) -> subprocess.CompletedProcess:
    (tmp / "scripts").mkdir(parents=True, exist_ok=True)
    probe = tmp / "scripts" / "probe.sh"
    probe.write_text(_prologue() + '\necho "RESOLVED=${NOO_BACKUP_OFFSITE:-}"\n', encoding="utf-8")
    if dotenv is not None:
        (tmp / ".env").write_text(dotenv, encoding="utf-8")
    return subprocess.run(["bash", str(probe)], capture_output=True, text=True, env=env)


def test_the_setting_in_dot_env_is_resolved_by_the_script_itself(tmp_path: Path) -> None:
    r = _run_prologue(
        tmp_path,
        'A=1\n# NOO_BACKUP_OFFSITE=dir:/old\nNOO_BACKUP_OFFSITE="dir:/mnt/fleet/backups x"\n',
        _clean_env(HOME=str(tmp_path)),
    )
    assert r.returncode == 0, r.stderr
    assert "RESOLVED=dir:/mnt/fleet/backups x" in r.stdout, r.stdout


def test_an_exported_value_wins_and_an_absent_one_stays_unset(tmp_path: Path) -> None:
    r = _run_prologue(tmp_path, "NOO_BACKUP_OFFSITE=dir:/from-env-file\n",
                      _clean_env(HOME=str(tmp_path), NOO_BACKUP_OFFSITE="dir:/exported"))
    assert "RESOLVED=dir:/exported" in r.stdout
    r = _run_prologue(tmp_path / "other", None, _clean_env(HOME=str(tmp_path)))
    assert r.returncode == 0 and "RESOLVED=\n" in r.stdout + "\n"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
def test_a_dot_env_that_cannot_be_read_is_a_failure_not_unset(tmp_path: Path) -> None:
    (tmp_path / "scripts").mkdir()
    (tmp_path / ".env").write_text("NOO_BACKUP_OFFSITE=dir:/x\n", encoding="utf-8")
    (tmp_path / ".env").chmod(0o000)
    probe = tmp_path / "scripts" / "probe.sh"
    probe.write_text(_prologue() + '\necho "RESOLVED=${NOO_BACKUP_OFFSITE:-}"\n', encoding="utf-8")
    r = subprocess.run(["bash", str(probe)], capture_output=True, text=True, env=_clean_env(HOME=str(tmp_path)))
    assert r.returncode != 0, "a configured-but-unreadable destination read as 'not configured'"
    assert "NOO_BACKUP_OFFSITE_RESULT=FAILED" in r.stderr


def _offsite(tmp: Path, dest: str, made: bool = True) -> subprocess.CompletedProcess:
    dump = tmp / "pg_20261024_033000.sql.gz.enc"
    dump.write_text("dump", encoding="utf-8")
    body = f"""set -euo pipefail
BACKUP_DIR={tmp}
PG_FILE={dump if made else ''}
OFFSITE_NOTE=""
{_offsite_fn()}
rc=0
offsite_copy || rc=$?
echo "NOTE=$OFFSITE_NOTE"
exit $rc
"""
    return subprocess.run(["bash", "-c", body], capture_output=True, text=True,
                          env=_clean_env(HOME=str(tmp), NOO_BACKUP_OFFSITE=dest))


def test_a_missing_dir_target_fails_and_nothing_is_created(tmp_path: Path) -> None:
    # The parent exists and is writable (an unmounted share's mount point looks
    # exactly like this): creating the target would put the "off-site" copy on
    # the root disk and report it copied.
    target = tmp_path / "mnt" / "noomesh-pop-os"
    (tmp_path / "mnt").mkdir()
    r = _offsite(tmp_path, f"dir:{target}")
    assert r.returncode != 0, r.stdout
    assert not target.exists(), "the script created the target"
    assert "NOTE=FAILED: target missing" in r.stdout and "mounted" in r.stdout
    assert "NOO_BACKUP_OFFSITE_RESULT" not in r.stdout  # emitted by the caller, from the note
    assert not (tmp_path / ".offsite-last").exists(), "a marker was written for a copy that did not happen"


def test_an_existing_dir_target_is_copied_to_and_marked(tmp_path: Path) -> None:
    target = tmp_path / "mnt"
    target.mkdir()
    r = _offsite(tmp_path, f"dir:{target}")
    assert r.returncode == 0, r.stderr
    assert (target / "pg_20261024_033000.sql.gz.enc").is_file()
    assert f"NOTE=copied 1 artifact(s) to dir:{target}" in r.stdout
    marker = (tmp_path / ".offsite-last").read_text(encoding="utf-8").split()
    assert marker[1] == "pg_20261024_033000.sql.gz.enc", "the newest-dump marker `noo backups status` reads"


def test_the_outcome_line_is_always_named(tmp_path: Path) -> None:
    assert "NOTE=not decided" in _offsite(tmp_path, "").stdout
    assert "NOTE=declined" in _offsite(tmp_path, "none").stdout
    assert "NOTE=portable" in _offsite(tmp_path, "portable").stdout
    # and it is emitted on the captured stream for hostd to put in the result
    assert "NOO_BACKUP_OFFSITE_RESULT=${OFFSITE_NOTE" in SCRIPT
