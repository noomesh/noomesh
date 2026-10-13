# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The controller backup never writes an unencrypted artefact.

Until 2026-09-11 `scripts/backup-controller.sh` copied the age PRIVATE KEY —
the key that decrypts every secret in `secrets/env.sops` — to
`~/noo-backups/age-key_<ts>.txt` in the clear, whenever
`NOO_AGE_BACKUP_PASSPHRASE` happened to be unset. It was unset everywhere: the
fail-closed switch was an opt-in (`NOO_BACKUP_ENCRYPT_REQUIRED=1`) that no
install, script, compose file or doc ever set. The host watcher ran the backup
every six hours. Tracker rows R22/R23/D10.

These run the REAL script (no container, so the pg dump is skipped and the
age-key path is what is under test) and assert on the files it leaves behind.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "backup-controller.sh"

# Assembled rather than written out: a literal of this shape is exactly what
# scripts/leak-check.sh exists to find, and a fixture that trips the repo's own
# secret scanner is a fixture that gets waived, and a waiver is one more place
# a real key could hide.
_SECRET_MARKER = "-".join(["AGE", "SECRET", "KEY"])
AGE_KEY = (
    "# created: 2026-01-01T00:00:00Z\n"
    "# public key: age1" + "test" * 14 + "te\n"
    + _SECRET_MARKER + "-1" + "TEST" * 16 + "TE\n"
)


def _run(tmp_path: Path, **env_extra: str) -> subprocess.CompletedProcess:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    keyfile = tmp_path / "keys.txt"
    keyfile.write_text(AGE_KEY)
    env = {
        **os.environ,
        "HOME": str(home),
        "NOO_BACKUP_DIR": str(tmp_path / "backups"),
        "SOPS_AGE_KEY_FILE": str(keyfile),
    }
    # Start from a clean slate every time: inherited values from the
    # developer's own shell would make this test pass for the wrong reason.
    for k in (
        "NOO_BACKUP_PASSPHRASE",
        "NOO_BACKUP_PASSPHRASE_FILE",
        "NOO_AGE_BACKUP_PASSPHRASE",
        "NOO_AGE_BACKUP_PASSPHRASE_FILE",
        "NOO_BACKUP_ENCRYPT_REQUIRED",
    ):
        env.pop(k, None)
    env.update(env_extra)
    return subprocess.run(
        ["bash", str(SCRIPT)], capture_output=True, text=True, timeout=120, env=env
    )


def _files(tmp_path: Path) -> list[str]:
    d = tmp_path / "backups"
    return sorted(p.name for p in d.iterdir()) if d.is_dir() else []


def test_no_passphrase_at_all_refuses_and_writes_nothing(tmp_path: Path) -> None:
    res = _run(tmp_path)
    assert res.returncode != 0, f"expected a refusal, got 0:\n{res.stdout}"
    assert "REFUSING" in res.stderr
    assert _files(tmp_path) == [], "a refused backup must leave no files behind"


def test_age_key_is_never_copied_in_plaintext(tmp_path: Path) -> None:
    """The exact historical shape: a pg passphrase set, the age one not.

    Before the fix this exited 0 having written `age-key_<ts>.txt` — a
    world's-worth of secrets, unencrypted, in a directory that gets rsync'd
    and tarred around.
    """
    res = _run(tmp_path, NOO_BACKUP_PASSPHRASE="pg-pass-aaaa")
    assert res.returncode != 0, f"expected a refusal, got 0:\n{res.stdout}"
    assert "NOO_AGE_BACKUP_PASSPHRASE" in res.stderr
    assert not [f for f in _files(tmp_path) if f.endswith(".txt")], (
        "the age private key was written in plaintext: " + repr(_files(tmp_path))
    )


def test_identical_passphrases_are_refused(tmp_path: Path) -> None:
    """Recovery must not be circular.

    NOO_BACKUP_PASSPHRASE lives in env.sops. If it also protected the age-key
    backup, opening that backup would require the age key it contains.
    """
    res = _run(
        tmp_path,
        NOO_BACKUP_PASSPHRASE="same-value-xyz",
        NOO_AGE_BACKUP_PASSPHRASE="same-value-xyz",
    )
    assert res.returncode != 0
    assert "INDEPENDENT" in res.stderr


def test_with_both_passphrases_the_age_backup_is_encrypted(tmp_path: Path) -> None:
    res = _run(
        tmp_path,
        NOO_BACKUP_PASSPHRASE="pg-pass-aaaa",
        NOO_AGE_BACKUP_PASSPHRASE="age-pass-bbbb",
    )
    # No container here, so no database dump: the run FAILS (exit 1) after the
    # age-key backup, which is still written.
    assert res.returncode == 1, f"{res.stdout}\n{res.stderr}"
    names = _files(tmp_path)
    enc = [f for f in names if f.startswith("age-key_") and f.endswith(".txt.enc")]
    assert enc, f"no encrypted age-key backup written: {names}"
    assert not [f for f in names if f.startswith("age-key_") and f.endswith(".txt")]
    blob = (tmp_path / "backups" / enc[0]).read_bytes()
    assert _SECRET_MARKER.encode() not in blob, "the private key is readable in the backup"
    assert blob.startswith(b"Salted__"), "not an openssl enc container"


def test_round_trip_restores_the_exact_key(tmp_path: Path) -> None:
    """An untested backup is a hypothesis — decrypt it and compare bytes."""
    res = _run(
        tmp_path,
        NOO_BACKUP_PASSPHRASE="pg-pass-aaaa",
        NOO_AGE_BACKUP_PASSPHRASE="age-pass-bbbb",
    )
    assert res.returncode == 1, res.stderr  # no database dump in this environment
    enc = next(p for p in (tmp_path / "backups").iterdir() if p.name.endswith(".txt.enc"))
    out = subprocess.run(
        [
            "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
            "-pass", "env:BACKUP_PASS", "-in", str(enc),
        ],
        capture_output=True,
        env={**os.environ, "BACKUP_PASS": "age-pass-bbbb"},
        timeout=60,
    )
    assert out.returncode == 0, out.stderr.decode()
    assert out.stdout.decode() == AGE_KEY


def test_the_opt_in_switch_is_not_read_by_anything() -> None:
    """`NOO_BACKUP_ENCRYPT_REQUIRED` must not come back.

    A safety switch whose OFF position is the dangerous one, defaulting to
    OFF, is not a safety switch. Encryption is now unconditional, so any
    shell that READS the variable, or any doc that tells an operator to SET
    it, is a regression. (Prose that records the history is fine — this
    checks for `${NOO_BACKUP_ENCRYPT_REQUIRED...}` and `...=1`.)
    """
    offenders = []
    for path in sorted((REPO / "scripts").glob("*.sh")):
        if "${NOO_BACKUP_ENCRYPT_REQUIRED" in path.read_text():
            offenders.append(str(path))
    for path in sorted((REPO / "docs").rglob("*.md")):
        if "NOO_BACKUP_ENCRYPT_REQUIRED=1" in path.read_text():
            offenders.append(str(path))
    assert not offenders, (
        "NOO_BACKUP_ENCRYPT_REQUIRED is live again in:\n" + "\n".join(offenders)
    )


def test_a_run_that_made_no_database_dump_fails(tmp_path: Path) -> None:
    """No noo-postgres container -> no dump -> the run must FAIL, not exit 0.

    Exiting 0 reported "backup OK" for a backup that never happened (#247's
    silent-success shape). The age-key backup still happens first.
    """
    res = _run(
        tmp_path,
        NOO_BACKUP_PASSPHRASE="pg-pass-aaaa",
        NOO_AGE_BACKUP_PASSPHRASE="age-pass-bbbb",
        PATH=_path_without_docker(tmp_path),
    )
    assert res.returncode != 0, f"a run with no dump succeeded:\n{res.stdout}\n{res.stderr}"
    assert "no database dump" in res.stderr.lower()
    assert "NOO_BACKUP_ARTIFACT=" not in res.stderr


def _path_without_docker(tmp_path: Path) -> str:
    """A PATH where `docker inspect noo-postgres` fails, whatever the host has."""
    shim = tmp_path / "shim"
    shim.mkdir(exist_ok=True)
    d = shim / "docker"
    d.write_text("#!/bin/sh\nexit 1\n")
    d.chmod(0o755)
    return f"{shim}:{os.environ['PATH']}"
