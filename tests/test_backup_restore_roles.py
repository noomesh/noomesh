# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A pg dump is not restorable without the cluster roles it references.

Found by the operator's restore drill (2026-10-12): `pg_dump noomesh` carries
`ALTER SCHEMA evolve OWNER TO noo_evolve_ddl`, `GRANT ... TO noo_app` and
`ALTER DEFAULT PRIVILEGES FOR ROLE noo_trellion_ddl ...`, but roles are
cluster-global and the dump does not include them. On a clean server ~150
statements failed, psql exited 0 anyway, and the drill's checks (which looked
only in `public`, with no search_path) reported zero tables.

These run the REAL scripts against a fake `docker` on PATH that records what
is piped into psql.
"""

from __future__ import annotations

import gzip
import os
import stat
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BACKUP = REPO / "scripts" / "backup-controller.sh"
DRILL = REPO / "scripts" / "restore-drill.sh"
PASS = "unit-test-passphrase-one"
ROLES = ["noo_app", "noo_evolve", "noo_evolve_ddl", "noo_trellion", "noo_trellion_ddl"]

FAKE_DOCKER = r"""#!/bin/bash
LOG="${FAKE_LOG:?}"
echo "docker $*" >> "$LOG"
case "$1" in
  inspect|rm|run) exit 0 ;;
esac
# docker exec [-i] NAME CMD...
shift; [ "$1" = "-i" ] && shift; shift
case "$1" in
  pg_isready) exit 0 ;;
  pg_dump) echo "CREATE TABLE t();"; exit 0 ;;
  psql)
    if [[ " $* " == *" -c "* ]]; then
      sql="${*: -1}"
      case "$sql" in
        *pg_roles*LIKE*) printf '%s\n' "$FAKE_ROLE_ROWS"; exit 0 ;;
        *to_regclass*) echo "${FAKE_REGCLASS:-t}"; exit 0 ;;
        *"FROM information_schema.tables"*) echo "${FAKE_TABLES:-5}"; exit 0 ;;
        *"count(*)"*) echo "${FAKE_ROWS:-3}"; exit 0 ;;
      esac
      exit 0
    fi
    # stdin SQL being applied
    sql="$(cat)"
    { echo "--- psql $* ---"; printf '%s\n' "$sql"; } >> "$LOG"
    if [ -n "${FAKE_FAIL_ON:-}" ] && [[ "$sql" == *"$FAKE_FAIL_ON"* ]]; then
      echo 'psql:stdin:1: ERROR:  role "noo_evolve_ddl" does not exist' >&2
      exit 3
    fi
    exit 0 ;;
esac
exit 0
"""


def _env(tmp: Path, **extra: str) -> dict:
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    d = bindir / "docker"
    d.write_text(FAKE_DOCKER)
    d.chmod(d.stat().st_mode | stat.S_IEXEC)
    home = tmp / "home"
    home.mkdir(exist_ok=True)
    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "HOME": str(home),
        "NOO_BACKUP_DIR": str(tmp / "backups"),
        "NOO_BACKUP_PASSPHRASE": PASS,
        "NOO_BACKUP_OFFSITE": "none",
        "NOO_DRILL_PG_IMAGE": "fake/image:1",
        "NOO_SOPS_FILE": str(tmp / "absent.sops"),
        "FAKE_LOG": str(tmp / "docker.log"),
        "FAKE_ROLE_ROWS": "\n".join(
            f"DO $r$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{r}') "
            f"THEN CREATE ROLE {r} LOGIN NOSUPERUSER; END IF; END $r$;"
            for r in ROLES
        ),
    }
    for k in ("NOO_AGE_BACKUP_PASSPHRASE", "NOO_AGE_BACKUP_PASSPHRASE_FILE",
              "NOO_BACKUP_PASSPHRASE_FILE", "SOPS_AGE_KEY_FILE"):
        env.pop(k, None)
    env.update(extra)
    return env


def _enc(data: bytes, out: Path) -> None:
    subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt", "-pass", f"env:P", "-out", str(out)],
        input=data, check=True, env={**os.environ, "P": PASS},
    )


def _dec(path: Path) -> bytes:
    return subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-pass", "env:P", "-in", str(path)],
        capture_output=True, check=True, env={**os.environ, "P": PASS},
    ).stdout


def _make_backup(tmp: Path, ts: str = "20261012_010101", roles: bool = True) -> Path:
    d = tmp / "backups"
    d.mkdir(exist_ok=True)
    dump = d / f"pg_{ts}.sql.gz.enc"
    _enc(gzip.compress(b"CREATE TABLE t();\n"), dump)
    if roles:
        _enc(b"CREATE ROLE noo_app;\n", d / f"pgroles_{ts}.sql.enc")
    return dump


def _drill(tmp: Path, **extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(DRILL)], capture_output=True, text=True,
                          timeout=120, env=_env(tmp, **extra))


# ── backup-controller ────────────────────────────────────────────────────────

def test_backup_writes_encrypted_roles_file_beside_the_dump(tmp_path):
    r = subprocess.run(["bash", str(BACKUP)], capture_output=True, text=True,
                       timeout=120, env=_env(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    names = sorted(p.name for p in (tmp_path / "backups").iterdir())
    dump = [n for n in names if n.startswith("pg_")]
    roles = [n for n in names if n.startswith("pgroles_")]
    assert len(dump) == 1 and len(roles) == 1, names
    # Same timestamp, so a restore can pair them.
    assert dump[0].removeprefix("pg_").removesuffix(".sql.gz.enc") == \
        roles[0].removeprefix("pgroles_").removesuffix(".sql.enc")
    sql = _dec(tmp_path / "backups" / roles[0]).decode()
    for role in ROLES:
        assert f"CREATE ROLE {role}" in sql
    # Never a credential, never a privileged attribute.
    assert "PASSWORD" not in "\n".join(l for l in sql.splitlines() if not l.startswith("--")).upper()
    # Encrypted at rest: ciphertext must not contain the SQL.
    assert b"CREATE ROLE" not in (tmp_path / "backups" / roles[0]).read_bytes()


def test_backup_fails_loudly_when_roles_cannot_be_read(tmp_path):
    r = subprocess.run(["bash", str(BACKUP)], capture_output=True, text=True,
                       timeout=120, env=_env(tmp_path, FAKE_ROLE_ROWS=""))
    assert r.returncode != 0
    assert "roles" in r.stderr.lower()
    names = [p.name for p in (tmp_path / "backups").iterdir()]
    assert not any(n.startswith("pgroles_") for n in names)


def test_retention_removes_the_roles_file_with_its_dump(tmp_path):
    d = tmp_path / "backups"
    d.mkdir()
    old = 20 * 86400
    for ts in ("20200101_000001", "20200101_000002", "20200101_000003", "20200101_000004"):
        for name in (f"pg_{ts}.sql.gz.enc", f"pgroles_{ts}.sql.enc"):
            p = d / name
            p.touch()
            os.utime(p, (p.stat().st_atime - old, p.stat().st_mtime - old))
    r = subprocess.run(["bash", str(BACKUP)], capture_output=True, text=True,
                       timeout=120, env=_env(tmp_path))
    assert r.returncode == 0, r.stdout + r.stderr
    names = {p.name for p in d.iterdir()}
    # The oldest dump aged out and took its roles file with it.
    assert "pg_20200101_000001.sql.gz.enc" not in names
    assert "pgroles_20200101_000001.sql.enc" not in names


# ── restore-drill ────────────────────────────────────────────────────────────

def test_drill_applies_roles_before_the_dump_with_on_error_stop(tmp_path):
    _make_backup(tmp_path)
    r = _drill(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    log = (tmp_path / "docker.log").read_text()
    roles_at = log.index("CREATE ROLE noo_app;")
    dump_at = log.index("CREATE TABLE t();")
    assert roles_at < dump_at, "roles must be applied before the data"
    applies = [l for l in log.splitlines() if l.startswith("--- psql")]
    assert len(applies) == 2
    assert all("ON_ERROR_STOP=1" in l for l in applies), applies


def test_drill_old_backup_without_roles_file_precreates_known_roles(tmp_path):
    _make_backup(tmp_path, roles=False)
    r = _drill(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "pre-creating the known noo_* roles" in r.stdout
    log = (tmp_path / "docker.log").read_text()
    for role in ROLES:
        assert f"CREATE ROLE {role} NOLOGIN" in log
    applied = log.split("--- psql", 1)[1]
    assert "PASSWORD" not in applied.upper()
    assert log.index("CREATE ROLE noo_app NOLOGIN") < log.index("CREATE TABLE t();")


def test_drill_stops_at_first_error_and_names_it(tmp_path):
    _make_backup(tmp_path)
    r = _drill(tmp_path, FAKE_FAIL_ON="CREATE TABLE t();")
    assert r.returncode != 0
    assert "RESTORE FAILED" in r.stdout
    assert 'role "noo_evolve_ddl" does not exist' in r.stdout
    # A failed restore is not followed by sanity checks that would say "0 tables".
    assert "Sanity checks" not in r.stdout


def test_drill_distinguishes_missing_from_empty(tmp_path):
    _make_backup(tmp_path)
    empty = _drill(tmp_path, FAKE_ROWS="0")
    assert empty.returncode != 0
    assert "restored but EMPTY" in empty.stdout
    assert "MISSING" not in empty.stdout

    missing = _drill(tmp_path, FAKE_REGCLASS="f")
    assert missing.returncode != 0
    assert "MISSING from the restore" in missing.stdout


def test_drill_checks_the_mesh_schema_not_just_public():
    text = DRILL.read_text()
    assert "search_path = mesh, public, trellion, evolve" in text
    assert "table_schema='public'" not in text
