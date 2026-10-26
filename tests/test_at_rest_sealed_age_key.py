# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A sealed age key that did not unseal stops the launch and the backup (i10a PR-B).

`sudo noo-hostd at-rest seal-age-key` seals the SOPS age key to the TPM and
records it in /etc/noo/at-rest.json; noo-unseal.service decrypts it into RAM
at /run/noo/keys/age.txt at boot, and `noo security at-rest finalize` makes
~/.config/sops/age/keys.txt a symlink to it. On such a box a missing key file
means the unit did not unseal. Two readers used to read "missing" as "SOPS is
not in use":

  * `scripts/lib-secrets.sh::_load_secrets_sops` fell through to a decrypt
    that failed with a generic "is the age key available?";
  * `scripts/backup-controller.sh` SKIPPED the age-key backup with a note and
    exited 0 — a backup run that reports success with no way to restore it.

Both now fail closed and name the unit. Each test also runs the unsealed or
unsealed-manifest control, so it fails if the check is reverted or widened.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "scripts" / "lib-secrets.sh"
BACKUP = ROOT / "scripts" / "backup-controller.sh"

SEALED = '{\n  "age_key_sealed": true,\n  "age_key_runtime": "/run/noo/keys/age.txt",\n  "version": 1\n}\n'
NOT_SEALED = '{\n  "volume_encrypted": true,\n  "version": 1\n}\n'

# Assembled, not literal (scripts/leak-check.sh).
AGE_KEY = "# public key: age1" + "test" * 14 + "te\n" + "-".join(["AGE", "SECRET", "KEY"]) + "-1" + "TEST" * 16 + "TE\n"


def _box(tmp: Path, manifest: str | None) -> dict[str, str]:
    (tmp / "secrets").mkdir()
    (tmp / "secrets" / "env.sops").write_text("x")
    (tmp / ".env").write_text("NOO_SECRETS_BACKEND=sops\n")
    b = tmp / "bin"
    b.mkdir()
    sops = b / "sops"
    # Records that it ran; the store it "decrypts" is irrelevant here.
    sops.write_text('#!/bin/sh\necho ran >> "$SOPS_LOG"\necho FOO=bar\n')
    sops.chmod(sops.stat().st_mode | stat.S_IEXEC)
    m = tmp / "at-rest.json"
    if manifest is not None:
        m.write_text(manifest)
    return {
        "PATH": f"{b}:/usr/local/bin:/usr/bin:/bin",
        "HOME": str(tmp / "home"),
        "NOO_AT_REST_MANIFEST": str(m),
        "SOPS_LOG": str(tmp / "sops.log"),
    }


def _load(tmp: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", f"cd {tmp} && . {LIB} && _load_secrets_sops"],
        env=env, capture_output=True, text=True, timeout=60,
    )


def test_sealed_and_not_unsealed_fails_closed_naming_the_unit(tmp_path: Path) -> None:
    env = _box(tmp_path, SEALED)
    r = _load(tmp_path, env)
    assert r.returncode != 0, r.stdout
    assert "sealed to this machine's TPM" in r.stderr and "noo-unseal.service" in r.stderr, r.stderr
    assert not (tmp_path / "sops.log").exists(), "sops ran: the launch reached a decrypt it cannot do"


def test_the_full_load_secrets_returns_non_zero_too(tmp_path: Path) -> None:
    env = _box(tmp_path, SEALED)
    r = subprocess.run(["bash", "-c", f"cd {tmp_path} && . {LIB} && load_secrets"],
                       env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode != 0
    assert "noo-unseal.service" in r.stderr, r.stderr


def test_a_dangling_finalized_symlink_counts_as_missing(tmp_path: Path) -> None:
    env = _box(tmp_path, SEALED)
    d = tmp_path / "home" / ".config" / "sops" / "age"
    d.mkdir(parents=True)
    (d / "keys.txt").symlink_to(tmp_path / "run-noo-keys-age.txt")  # target absent: not unsealed
    r = _load(tmp_path, env)
    assert r.returncode != 0 and "noo-unseal.service" in r.stderr, r.stderr


def test_unsealed_key_present_reaches_sops(tmp_path: Path) -> None:
    env = _box(tmp_path, SEALED)
    runtime = tmp_path / "run-noo-keys-age.txt"
    runtime.write_text(AGE_KEY)
    d = tmp_path / "home" / ".config" / "sops" / "age"
    d.mkdir(parents=True)
    (d / "keys.txt").symlink_to(runtime)
    r = _load(tmp_path, env)
    assert "noo-unseal.service" not in r.stderr, r.stderr
    assert (tmp_path / "sops.log").exists(), "the unsealed key was refused"


def test_sops_age_key_file_is_honoured(tmp_path: Path) -> None:
    env = _box(tmp_path, SEALED)
    runtime = tmp_path / "age.txt"
    runtime.write_text(AGE_KEY)
    r = _load(tmp_path, {**env, "SOPS_AGE_KEY_FILE": str(runtime)})
    assert "noo-unseal.service" not in r.stderr, r.stderr
    assert (tmp_path / "sops.log").exists()


def test_not_sealed_or_no_manifest_keeps_todays_behaviour(tmp_path: Path) -> None:
    for i, manifest in enumerate((NOT_SEALED, None)):
        t = tmp_path / str(i)
        t.mkdir()
        env = _box(t, manifest)
        r = _load(t, env)
        assert "noo-unseal.service" not in r.stderr, r.stderr
        assert (t / "sops.log").exists(), "an unsealed box must still reach sops"


# ── backup-controller.sh ─────────────────────────────────────────────────────


def _backup(tmp: Path, manifest: str | None, key_present: bool) -> subprocess.CompletedProcess:
    home = tmp / "home"
    home.mkdir(exist_ok=True)
    keyfile = tmp / "age.txt"
    if key_present:
        keyfile.write_text(AGE_KEY)
    m = tmp / "at-rest.json"
    if manifest is not None:
        m.write_text(manifest)
    # A docker that is never there: this test must not dump whatever
    # Postgres the machine running it happens to have.
    fake = tmp / "fakebin"
    fake.mkdir(exist_ok=True)
    (fake / "docker").write_text("#!/bin/sh\nexit 1\n")
    (fake / "docker").chmod(0o755)
    env = {**os.environ, "HOME": str(home), "NOO_BACKUP_DIR": str(tmp / "backups"),
           "SOPS_AGE_KEY_FILE": str(keyfile), "NOO_AT_REST_MANIFEST": str(m),
           "NOO_BACKUP_PASSPHRASE": "pg-pass-for-test", "NOO_AGE_BACKUP_PASSPHRASE": "age-pass-for-test",
           # No docker in the test: the pg dump is skipped, the age-key path is under test.
           "PATH": f"{fake}:/usr/local/bin:/usr/bin:/bin"}
    for k in ("NOO_BACKUP_PASSPHRASE_FILE", "NOO_AGE_BACKUP_PASSPHRASE_FILE", "NOO_BACKUP_OFFSITE"):
        env.pop(k, None)
    return subprocess.run(["bash", str(BACKUP)], capture_output=True, text=True, timeout=120, env=env)


def test_backup_refuses_when_sealed_and_the_key_is_missing(tmp_path: Path) -> None:
    r = _backup(tmp_path, SEALED, key_present=False)
    assert r.returncode != 0, r.stdout
    assert "REFUSING" in r.stderr and "noo-unseal.service" in r.stderr, r.stderr
    d = tmp_path / "backups"
    assert not d.exists() or not any(d.iterdir()), "a refused backup must leave no files behind"


def test_backup_still_skips_quietly_when_not_sealed(tmp_path: Path) -> None:
    r = _backup(tmp_path, NOT_SEALED, key_present=False)
    assert "noo-unseal.service" not in r.stderr, r.stderr
    assert "skipping age-key backup" in r.stdout, r.stdout


def test_backup_with_the_unsealed_key_writes_the_encrypted_copy(tmp_path: Path) -> None:
    r = _backup(tmp_path, SEALED, key_present=True)
    assert "noo-unseal.service" not in r.stderr, r.stderr
    assert any(p.name.endswith(".txt.enc") for p in (tmp_path / "backups").iterdir()), r.stdout + r.stderr
