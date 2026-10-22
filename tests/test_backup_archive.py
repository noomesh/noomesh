# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The cold-storage archive is in the backup, and goes off the machine with it.

Retention archives expired audit partitions and agent mail to
/data/audit-archive and THEN deletes them from Postgres, so the pg dump does
not contain them. Before this, nothing backed that directory up: the only copy
of those rows sat on the same volume as the database. These run the real
backup script against a fake `docker` whose `cp` streams a tar, and assert the
bytes that land in the encrypted artifact and in the offsite copy.
"""

from __future__ import annotations

import io
import os
import stat
import subprocess
import tarfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BACKUP = REPO / "scripts" / "backup-controller.sh"
EXPORT = REPO / "scripts" / "noo-backup-export.sh"
PASS = "unit-test-passphrase-one"
MARK = b"sealed-ciphertext-marker"

FAKE_DOCKER = r"""#!/bin/bash
echo "docker $*" >> "${FAKE_LOG:?}"
case "$1" in
  inspect) [ "${FAKE_NO_GATEWAY:-}" = 1 ] && [ "$2" = noo-gateway ] && exit 1; exit 0 ;;
  cp)
    if [ -n "${FAKE_CP_ERR:-}" ]; then echo "$FAKE_CP_ERR" >&2; exit 1; fi
    cat "$FAKE_TAR"; exit 0 ;;
  exec)
    shift; [ "$1" = "-i" ] && shift; shift
    case "$1" in
      pg_dump) echo "CREATE TABLE t();"; exit 0 ;;
      psql) [[ " $* " == *" -c "* ]] && printf '%s\n' "SELECT 1;" ; exit 0 ;;
    esac ;;
esac
exit 0
"""


def _tar() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in {
            "audit-archive/noo_agent_messages_2026_03.jsonl.gz": MARK,
            "audit-archive/noo_security_audit_2025_09.jsonl": b'{"id":1}\n',
        }.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def _run(tmp: Path, script: Path = BACKUP, **extra: str):
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    d = bindir / "docker"
    d.write_text(FAKE_DOCKER)
    d.chmod(d.stat().st_mode | stat.S_IEXEC)
    (tmp / "home").mkdir(exist_ok=True)
    (tmp / "a.tar").write_bytes(_tar())
    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "HOME": str(tmp / "home"),
        "NOO_BACKUP_DIR": str(tmp / "backups"),
        "NOO_BACKUP_PASSPHRASE": PASS,
        "NOO_BACKUP_OFFSITE": f"dir:{tmp / 'offsite'}",
        "NOO_SOPS_FILE": str(tmp / "absent.sops"),
        "FAKE_LOG": str(tmp / "docker.log"),
        "FAKE_TAR": str(tmp / "a.tar"),
    }
    for k in ("NOO_AGE_BACKUP_PASSPHRASE", "NOO_AGE_BACKUP_PASSPHRASE_FILE",
              "NOO_BACKUP_PASSPHRASE_FILE", "SOPS_AGE_KEY_FILE"):
        env.pop(k, None)
    env.update(extra)
    (tmp / "offsite").mkdir(exist_ok=True)
    return subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env, cwd=tmp)


def _dec(path: Path) -> bytes:
    return subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-pass", "env:P", "-in", str(path)],
        capture_output=True, check=True, env={**os.environ, "P": PASS},
    ).stdout


def test_the_archive_is_backed_up_encrypted_and_copied_offsite(tmp_path):
    r = _run(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    made = list((tmp_path / "backups").glob("archive_*.tar.enc"))
    assert len(made) == 1, r.stdout
    raw = made[0].read_bytes()
    assert MARK not in raw and b"audit-archive" not in raw, "the artifact must be ciphertext"
    names = tarfile.open(fileobj=io.BytesIO(_dec(made[0]))).getnames()
    assert "audit-archive/noo_agent_messages_2026_03.jsonl.gz" in names, names
    assert "audit-archive/noo_security_audit_2025_09.jsonl" in names, names
    # and it left the machine with the dump
    off = {p.name for p in (tmp_path / "offsite").iterdir()}
    assert made[0].name in off, off
    assert any(n.startswith("pg_") for n in off)
    assert "docker cp noo-gateway:/data/audit-archive -" in (tmp_path / "docker.log").read_text()


def test_a_missing_archive_dir_is_a_note_not_a_failure(tmp_path):
    r = _run(tmp_path, FAKE_CP_ERR="Error: No such container:path: noo-gateway:/data/audit-archive (Could not find the file /data/audit-archive in container noo-gateway)")
    assert r.returncode == 0, r.stdout + r.stderr
    assert not list((tmp_path / "backups").glob("archive_*.tar.enc"))
    assert "nothing has been archived" in r.stdout


def test_a_failed_archive_backup_fails_the_run(tmp_path):
    r = _run(tmp_path, FAKE_CP_ERR="permission denied reading volume")
    assert r.returncode != 0
    assert "archive" in (r.stdout + r.stderr).lower()
    assert not list((tmp_path / "backups").glob("archive_*.tar.enc")), "no half-written artifact may stay"


def test_the_portable_export_carries_the_archive(tmp_path):
    assert _run(tmp_path).returncode == 0
    out = tmp_path / "out"
    out.mkdir()
    env = {**os.environ, "NOO_BACKUP_DIR": str(tmp_path / "backups")}
    r = subprocess.run(["bash", str(EXPORT), "--out", str(out)], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    bundle = next(out.glob("noo-backup-export_*.tar.gz"))
    names = tarfile.open(bundle).getnames()
    assert any("archive_" in n and n.endswith(".tar.enc") for n in names), names
