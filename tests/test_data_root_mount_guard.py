# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The stack refuses to start when the data root is not on its recorded filesystem.

2026-10-24, the production controller: the data NVMe dropped off the bus.
Postgres device-binds ${NOO_DATA_ROOT}/postgres; on a reboot with the drive
absent docker would have made the missing bind source on the ROOT disk and
postgres would have run initdb into it: an empty database, the gateway up on
it, silent data loss. scripts/lib-data-root-mount.sh records the identity of
the filesystem under the data root and compares it at every launch.

These tests run the REAL library against a fake `findmnt` (a mount table in
env vars), a fake `ls` that can raise an I/O error, and a fake `docker`.
Revert the library and each of them fails.
"""

from __future__ import annotations

import re
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
LIB = SCRIPTS / "lib-data-root-mount.sh"
LAUNCHERS = ("noomesh-start.sh", "noomesh-restart.sh", "noomesh-rebuild.sh")

UUID_A = "aaaa-1111"
UUID_B = "bbbb-2222"
CALL_LINE = re.compile(r"^\s*check_data_root_mount\s*\|\|\s*exit 1\s*$")
SOURCE_LINE = re.compile(r"^\s*(source|\.)\s+\S*lib-data-root-mount\.sh\"?\s*$")
STATE_LINE = re.compile(r"^\s*check_state_volume_open\s*\|\|\s*exit 1\s*$")
COMPOSE_LINE = re.compile(r"\bdocker compose\b")


def _exe(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture
def rig(tmp_path):
    """An install root (cwd) with a data root, plus fakes on PATH."""
    install = tmp_path / "install"
    install.mkdir()
    data = tmp_path / "mnt" / "extradrive1" / "noo"
    (data / "postgres").mkdir(parents=True)
    (data / "postgres" / "PG_VERSION").write_text("16\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    dlog = tmp_path / "docker.log"
    # The fake mount table: findmnt -n -o FIELD -T path -> $FAKE_<FIELD>.
    _exe(bindir / "findmnt", """\
        #!/bin/sh
        [ -n "$FAKE_FINDMNT_FAIL" ] && exit 1
        field=""
        while [ $# -gt 0 ]; do [ "$1" = "-o" ] && field="$2"; shift; done
        eval "printf '%s\\n' \\"\\$FAKE_$field\\""
        """)
    _exe(bindir / "ls", """\
        #!/bin/sh
        if [ -n "$FAKE_LS_EIO" ]; then
          echo "ls: cannot open directory '$2': Input/output error" >&2
          exit 2
        fi
        exec /bin/ls "$@"
        """)
    _exe(bindir / "docker", f"""\
        #!/bin/sh
        echo "$@" >> "{dlog}"
        case "$1" in
          ps) printf '%s\\n' $FAKE_PS ;;
        esac
        exit 0
        """)
    env = {
        "PATH": f"{bindir}:/usr/bin:/bin",
        "HOME": str(tmp_path / "home"),
        "TERM": "dumb",
        "NOO_DATA_ROOT": str(data),
        "FAKE_UUID": UUID_A,
        "FAKE_SOURCE": "/dev/nvme1n1p1",
        "FAKE_TARGET": str(tmp_path / "mnt" / "extradrive1"),
        "FAKE_FSTYPE": "ext4",
    }
    return {"install": install, "data": data, "env": env, "dlog": dlog, "tmp": tmp_path}


def run(rig, fn="check_data_root_mount", **extra):
    env = dict(rig["env"])
    env.update({k: v for k, v in extra.items() if v is not None})
    script = f'source {LIB}\nrc=0; {fn} || rc=$?\necho "RC=$rc"\n'
    return subprocess.run(["bash", "-c", script], cwd=rig["install"], env=env, capture_output=True, text=True, timeout=60)


def record(rig) -> str:
    return (rig["install"] / ".noo-data-root-id").read_text()


# ── first run: record ─────────────────────────────────────────────────────


def test_first_run_on_a_healthy_root_records_and_passes(rig):
    r = run(rig)
    assert "RC=0" in r.stdout, r.stderr
    assert "recorded the filesystem" in r.stderr
    rec = record(rig)
    assert f"uuid={UUID_A}" in rec and "id_kind=uuid" in rec and "source=/dev/nvme1n1p1" in rec
    assert f"data_root={rig['data']}" in rec
    # postgres has a cluster here: the "initialised" marker is written with it.
    assert "postgres_initialised=" in rec


def test_a_filesystem_without_a_uuid_records_source_and_target_and_says_so(rig):
    r = run(rig, FAKE_UUID="")
    assert "RC=0" in r.stdout, r.stderr
    rec = record(rig)
    assert "id_kind=mount" in rec and "source=/dev/nvme1n1p1" in rec
    assert "no UUID" in r.stderr
    # ...and the same mount passes, a different source refuses.
    assert "RC=0" in run(rig, FAKE_UUID="").stdout
    bad = run(rig, FAKE_UUID="", FAKE_SOURCE="/dev/sdb1")
    assert "RC=1" in bad.stdout and "no UUID" in bad.stderr


# ── later runs ────────────────────────────────────────────────────────────


def test_matching_uuid_passes(rig):
    assert "RC=0" in run(rig).stdout
    again = run(rig)
    assert "RC=0" in again.stdout, again.stderr
    assert "REFUSED" not in again.stderr


def test_a_different_uuid_refuses_and_names_both(rig):
    run(rig)
    r = run(rig, FAKE_UUID=UUID_B)
    assert "RC=1" in r.stdout
    assert "REFUSED" in r.stderr and UUID_A in r.stderr and UUID_B in r.stderr
    assert "/dev/nvme1n1p1" in r.stderr
    for pointer in ("findmnt", "lsblk -f", "data-root-recovery.md", "NEW EMPTY database"):
        assert pointer in r.stderr, pointer


def test_the_data_root_on_the_root_filesystem_refuses_and_says_so(rig):
    run(rig)  # separate data disk recorded
    r = run(rig, FAKE_UUID="rootfs-9999", FAKE_SOURCE="/dev/sda2", FAKE_TARGET="/")
    assert "RC=1" in r.stdout
    assert "ROOT filesystem" in r.stderr and "not mounted" in r.stderr


def test_an_unreadable_root_refuses(rig):
    run(rig)
    r = run(rig, FAKE_LS_EIO="1")
    assert "RC=1" in r.stdout
    assert "Input/output error" in r.stderr and "cannot be read" in r.stderr


def test_a_missing_root_refuses_and_is_not_created(rig):
    run(rig)
    gone = rig["tmp"] / "elsewhere" / "noo"
    r = run(rig, NOO_DATA_ROOT=str(gone))
    assert "RC=1" in r.stdout and "does not exist" in r.stderr
    assert not gone.exists(), "the check created the data root"
    assert not gone.parent.exists()
    # also with nothing recorded at all
    (rig["install"] / ".noo-data-root-id").unlink()
    r = run(rig, NOO_DATA_ROOT=str(gone))
    assert "RC=1" in r.stdout and not gone.exists()


def test_a_changed_data_root_refuses_until_rerecorded_deliberately(rig):
    run(rig)
    other = rig["tmp"] / "mnt" / "extradrive1" / "noo2"
    other.mkdir()
    r = run(rig, NOO_DATA_ROOT=str(other))
    assert "RC=1" in r.stdout and "recorded data root" in r.stderr
    ok = run(rig, NOO_DATA_ROOT=str(other), NOO_DATA_ROOT_RERECORD="1")
    assert "RC=0" in ok.stdout, ok.stderr
    assert f"data_root={other}" in record(rig)


def test_a_replaced_disk_is_rerecorded_only_when_asked(rig):
    run(rig)
    assert "RC=1" in run(rig, FAKE_UUID=UUID_B).stdout
    ok = run(rig, FAKE_UUID=UUID_B, NOO_DATA_ROOT_RERECORD="1")
    assert "RC=0" in ok.stdout, ok.stderr
    assert f"uuid={UUID_B}" in record(rig)


# ── postgres belt and braces ──────────────────────────────────────────────


def test_an_empty_postgres_dir_on_an_initialised_install_refuses(rig):
    run(rig)  # records "initialised" (PG_VERSION present)
    (rig["data"] / "postgres" / "PG_VERSION").unlink()
    r = run(rig)
    assert "RC=1" in r.stdout
    assert "NEW EMPTY database" in r.stderr and "was initialised" in r.stderr


def test_a_missing_postgres_dir_on_an_initialised_install_refuses(rig):
    run(rig)
    (rig["data"] / "postgres" / "PG_VERSION").unlink()
    (rig["data"] / "postgres").rmdir()
    assert "RC=1" in run(rig).stdout


def test_rerecord_does_not_bypass_the_postgres_belt(rig):
    run(rig)
    (rig["data"] / "postgres" / "PG_VERSION").unlink()
    r = run(rig, NOO_DATA_ROOT_RERECORD="1")
    assert "RC=1" in r.stdout


def test_a_fresh_install_with_an_empty_postgres_dir_is_not_refused(rig):
    (rig["data"] / "postgres" / "PG_VERSION").unlink()
    r = run(rig)
    assert "RC=0" in r.stdout, r.stderr
    assert "postgres_initialised" not in record(rig)
    assert "RC=0" in run(rig).stdout  # still fine on the next launch


# ── edges ─────────────────────────────────────────────────────────────────


def test_no_data_root_is_not_this_checks_business(rig):
    env = dict(rig["env"], NOO_DATA_ROOT="")
    r = subprocess.run(["bash", "-c", f'source {LIB}; check_data_root_mount; echo RC=$?'], cwd=rig["install"], env=env, capture_output=True, text=True)
    assert "RC=0" in r.stdout and not (rig["install"] / ".noo-data-root-id").exists()


def test_data_root_comes_from_dot_env_like_the_launchers_read_it(rig):
    (rig["install"] / ".env").write_text(f"NOO_DATA_ROOT={rig['data']}\n")
    env = dict(rig["env"])
    env.pop("NOO_DATA_ROOT")
    r = subprocess.run(["bash", "-c", f'source {LIB}; check_data_root_mount; echo RC=$?'], cwd=rig["install"], env=env, capture_output=True, text=True)
    assert "RC=0" in r.stdout and f"data_root={rig['data']}" in record(rig)


def test_report_is_read_only_and_carries_the_evidence(rig):
    r = run(rig, fn="data_root_mount_report")
    assert "RC=4" in r.stdout and "no filesystem recorded" in r.stdout
    assert not (rig["install"] / ".noo-data-root-id").exists(), "report recorded"
    run(rig)
    ok = run(rig, fn="data_root_mount_report")
    assert "RC=0" in ok.stdout and UUID_A in ok.stdout
    bad = run(rig, fn="data_root_mount_report", FAKE_UUID=UUID_B)
    assert "RC=3" in bad.stdout and UUID_A in bad.stdout and UUID_B in bad.stdout


# ── no findmnt: refuse on Linux, skip on macOS ────────────────────────────


def _path_without_findmnt(rig, uname: str | None = None) -> str:
    """A PATH holding every tool the host has EXCEPT findmnt (the 0.6.11
    rehearsal's alpine dind without util-linux), plus the rig's fakes
    other than findmnt, and optionally a fake `uname -s`."""
    nofm = rig["tmp"] / "nofindmnt-bin"
    nofm.mkdir(exist_ok=True)
    for d in ("/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        if not Path(d).is_dir():
            continue
        for tool in Path(d).iterdir():
            dest = nofm / tool.name
            if tool.name == "findmnt" or dest.exists() or dest.is_symlink():
                continue
            dest.symlink_to(tool)
    for fake in ("ls", "docker"):
        dest = nofm / fake
        if dest.exists() or dest.is_symlink():
            dest.unlink()
        dest.symlink_to(rig["tmp"] / "bin" / fake)
    if uname:
        u = nofm / "uname"
        if u.exists() or u.is_symlink():
            u.unlink()
        _exe(u, f"#!/bin/sh\necho {uname}\n")
    path = str(nofm)
    probe = subprocess.run(["bash", "-c", "command -v findmnt"], env={"PATH": path}, capture_output=True, text=True)
    assert probe.returncode != 0, f"findmnt still on the test PATH: {probe.stdout}"
    return path


def test_no_findmnt_on_linux_refuses_names_util_linux_and_records_nothing(rig):
    r = run(rig, PATH=_path_without_findmnt(rig, uname="Linux"))
    assert "RC=1" in r.stdout, r.stderr
    assert "REFUSED" in r.stderr and "findmnt is not installed" in r.stderr
    assert "apt install util-linux" in r.stderr and "apk add util-linux" in r.stderr
    assert "Retrying will not help" in r.stderr
    assert not (rig["install"] / ".noo-data-root-id").exists()


def test_no_findmnt_on_linux_is_not_bypassed_by_rerecord(rig):
    run(rig)  # recorded on a host that had findmnt
    before = record(rig)
    r = run(rig, PATH=_path_without_findmnt(rig, uname="Linux"), NOO_DATA_ROOT_RERECORD="1")
    assert "RC=1" in r.stdout, r.stderr
    assert "util-linux" in r.stderr and "re-recorded" not in r.stderr
    assert record(rig) == before, "the record changed without findmnt"


def test_no_findmnt_on_darwin_skips_with_a_warning(rig):
    r = run(rig, PATH=_path_without_findmnt(rig, uname="Darwin"))
    assert "RC=0" in r.stdout, r.stderr
    assert "WARNING: no findmnt" in r.stderr and "REFUSED" not in r.stderr
    assert not (rig["install"] / ".noo-data-root-id").exists()
    rep = run(rig, fn="data_root_mount_report", PATH=_path_without_findmnt(rig, uname="Darwin"))
    assert "RC=4" in rep.stdout


def test_no_findmnt_on_linux_reports_5_for_verify(rig):
    r = run(rig, fn="data_root_mount_report", PATH=_path_without_findmnt(rig, uname="Linux"))
    assert "RC=5" in r.stdout and "findmnt is not installed" in r.stdout


def test_no_findmnt_on_linux_boot_guard_stops_the_stack_and_records_why(rig):
    r = run(rig, fn="data_root_mount_boot_guard", PATH=_path_without_findmnt(rig, uname="Linux"), FAKE_PS="noo-redis noo-postgres")
    assert "RC=1" in r.stdout, r.stderr
    stops = [c for c in rig["dlog"].read_text().splitlines() if c.startswith("stop ")]
    assert stops == ["stop noo-postgres", "stop noo-redis"], stops
    why = (rig["install"] / ".noo-data-root-refused").read_text()
    assert "findmnt is not installed" in why and "util-linux" in why and "Retrying will not help" in why


# ── the boot path: stop, never start ──────────────────────────────────────


def test_boot_guard_stops_postgres_first_then_the_rest_and_records_why(rig):
    run(rig)
    r = run(rig, fn="data_root_mount_boot_guard", FAKE_UUID=UUID_B, FAKE_PS="noo-redis noo-postgres noo-gateway")
    assert "RC=1" in r.stdout
    calls = rig["dlog"].read_text().splitlines()
    stops = [c for c in calls if c.startswith("stop ")]
    assert stops[0] == "stop noo-postgres", calls
    assert set(stops) == {"stop noo-postgres", "stop noo-redis", "stop noo-gateway"}
    assert not any(c.startswith(("start", "up", "run", "compose")) for c in calls), calls
    why = (rig["install"] / ".noo-data-root-refused").read_text()
    assert "REFUSED" in why and UUID_B in why and "noo-postgres" in why


def test_boot_guard_on_a_good_mount_touches_no_container_and_clears_the_reason(rig):
    run(rig)
    (rig["install"] / ".noo-data-root-refused").write_text("stale")
    r = run(rig, fn="data_root_mount_boot_guard", FAKE_PS="noo-postgres")
    assert "RC=0" in r.stdout, r.stderr
    assert not rig["dlog"].exists(), "docker was called on a healthy mount"
    assert not (rig["install"] / ".noo-data-root-refused").exists()


def test_boot_guard_follows_the_instance_prefix(rig):
    run(rig)
    run(rig, fn="data_root_mount_boot_guard", FAKE_UUID=UUID_B, FAKE_PS="noo-galaxy-postgres", NOO_INSTANCE="galaxy")
    assert "name=^noo-galaxy-" in rig["dlog"].read_text()


# ── launcher wiring ───────────────────────────────────────────────────────


def _statements(path: Path) -> list[str]:
    return [l for l in path.read_text().splitlines() if l.strip() and not l.strip().startswith("#")]


@pytest.mark.parametrize("name", LAUNCHERS)
def test_every_launcher_checks_the_data_root_before_compose(name):
    stmts = _statements(SCRIPTS / name)
    calls = [i for i, s in enumerate(stmts) if CALL_LINE.match(s)]
    assert calls, f"{name} never calls `check_data_root_mount || exit 1`"
    sources = [i for i, s in enumerate(stmts) if SOURCE_LINE.match(s)]
    assert sources and sources[0] < calls[0], f"{name}: lib-data-root-mount.sh is not sourced before the call"
    state = [i for i, s in enumerate(stmts) if STATE_LINE.match(s)]
    assert state and state[0] < calls[0], f"{name}: the check rides beside check_state_volume_open"
    composes = [i for i, s in enumerate(stmts) if COMPOSE_LINE.search(s)]
    assert composes and calls[0] < composes[0], f"{name}: a `docker compose` runs before the data-root check"


def test_the_cli_embeds_the_lib():
    build = (REPO_ROOT / "noo-cli" / "build.rs").read_text()
    assert '"scripts/lib-data-root-mount.sh",' in build


def test_hostd_boot_restore_runs_the_guard_before_anything_else():
    go = (REPO_ROOT / "node-agent-go" / "internal" / "hostd" / "boot.go").read_text()
    m = re.search(r"const bootRestoreScript = `(.*?)`\n", go, re.S)
    assert m
    script = m.group(1)
    guard = script.index("data_root_mount_boot_guard")
    for later in ("secret_rundir)", "check_state_volume_open", "load_secrets", "docker start"):
        assert guard < script.index(later), later
