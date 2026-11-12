# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The launchers make the gateway's own dirs on the noo-data volume and hand
them to uid 65532 before the gateway starts.

The gateway runs nonroot (65532); the noo-data root stays owned by the
operator (onboard's `subdir_owner` leaves it alone on purpose), so a NEW
top-level dir the gateway creates itself fails EACCES:

  - /data/ingest/{working,archive}: Drive/folder ingest staging (2026-08-08);
  - /data/audit-archive: the agent-mail archive
    (gateway-rust/src/agent_mail_archive.rs create_dir_all). 0.6.10-rc.3
    rehearsal: "cannot create /data/audit-archive: Permission denied".

`noo_prepare_gateway_data_dirs` (scripts/lib-instance.sh) is the one place
the list lives; noomesh-start.sh (onboard's first up, `noo upgrade --stack`,
`noo mesh start`) and noomesh-restart.sh (whenever it recreates the gateway)
call it. Run here with a fake `docker` that captures the throwaway
container's script, which is then executed against a scratch dir with a fake
`chown` recording what it was asked to hand over.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
LIB_INSTANCE = SCRIPTS / "lib-instance.sh"

GATEWAY_DIRS = ("ingest/working", "ingest/archive", "audit-archive")


def _fake_bin(tmp_path: Path) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    docker = bindir / "docker"
    # Record argv one per line; the last arg is the in-container script.
    docker.write_text('#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a"; done > "$FAKE_DOCKER_LOG"\n')
    chown = bindir / "chown"
    chown.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$FAKE_CHOWN_LOG"\n')
    for f in (docker, chown):
        f.chmod(0o755)
    return bindir


def _captured_script(tmp_path: Path) -> tuple[list[str], str]:
    bindir = _fake_bin(tmp_path)
    log = tmp_path / "docker.log"
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "FAKE_DOCKER_LOG": str(log), "COMPOSE_PROJECT_NAME": "proj"}
    # lib-instance.sh runs noo_instance_env on source; harmless here.
    r = subprocess.run(
        ["bash", "-c", f'. "{LIB_INSTANCE}" >/dev/null 2>&1; noo_prepare_gateway_data_dirs'],
        env=env, capture_output=True, text=True, cwd=tmp_path,
    )
    assert r.returncode == 0, r.stderr
    assert log.exists(), "noo_prepare_gateway_data_dirs never ran docker"
    argv = log.read_text().splitlines()
    i = argv.index("-c")
    return argv, "\n".join(argv[i + 1:])


def test_prep_mounts_the_noo_data_volume_in_a_throwaway_root_container(tmp_path: Path) -> None:
    argv, _ = _captured_script(tmp_path)
    assert argv[:2] == ["run", "--rm"], argv
    assert "proj_noo-data:/d" in argv, argv
    assert "alpine" in argv, argv
    assert "--user" not in argv and "-u" not in argv, "the chown needs root in the throwaway container"


def test_prep_creates_every_gateway_dir_and_hands_it_to_65532(tmp_path: Path) -> None:
    _, script = _captured_script(tmp_path)
    vol = tmp_path / "vol"
    vol.mkdir()
    chown_log = tmp_path / "chown.log"
    env = {**os.environ, "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}", "FAKE_CHOWN_LOG": str(chown_log)}
    r = subprocess.run(["sh", "-c", script.replace("/d/", f"{vol}/")], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    for d in GATEWAY_DIRS:
        assert (vol / d).is_dir(), f"/data/{d} is not created"
    calls = chown_log.read_text().splitlines()
    owned: set[str] = set()
    for c in calls:
        words = c.split()
        assert "65532:65532" in words, c
        owned |= {w[len(str(vol)) + 1:] for w in words if w.startswith(f"{vol}/")}
    # Every gateway dir is covered by a chown of it or of its parent, with -R
    # for a parent.
    for d in GATEWAY_DIRS:
        top = d.split("/")[0]
        assert d in owned or (top in owned and any("-R" in c.split() for c in calls)), f"/data/{d} is not handed to 65532: {calls}"
    assert "audit-archive" in owned, calls


def _uncommented(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def test_start_calls_the_prep_and_keeps_no_inline_copy() -> None:
    body = _uncommented((SCRIPTS / "noomesh-start.sh").read_text())
    assert re.search(r"^\s*noo_prepare_gateway_data_dirs \|\| \{ .*exit 1; \}\s*$", body, re.M), "noomesh-start.sh no longer prepares the gateway's dirs, or no longer stops when the volume cannot be made"
    assert "/d/ingest" not in body, "an inline copy of the list in noomesh-start.sh would drift from lib-instance.sh"


def test_restart_prepares_when_it_recreates_the_gateway() -> None:
    body = _uncommented((SCRIPTS / "noomesh-restart.sh").read_text())
    calls = re.findall(r"^\s*noo_prepare_gateway_data_dirs \|\| \{ .*exit 1; \}\s*$", body, re.M)
    assert len(calls) == 2, "noomesh-restart.sh must prepare on the whole-stack path and when `gateway` is named"
    named = body.index('SERVICES=("${RESOLVED_SERVICES[@]}")')
    assert re.search(r"grep -qx gateway;\s*then\s*noo_prepare_gateway_data_dirs \|\|", body[named:]), (
        "the named-services path must prepare after resolving names (an alias resolves to `gateway` only then)"
    )


def test_prep_volume_is_the_compose_project_not_the_cwd(tmp_path: Path) -> None:
    """A dist install runs from the install root (~/.noo); basename-of-$PWD
    made ".noo_noo-data", invalid, and `|| true` hid docker's exit 125."""
    bindir = _fake_bin(tmp_path)
    log = tmp_path / "docker.log"
    cwd = tmp_path / ".noo"
    cwd.mkdir()
    env = {k: v for k, v in os.environ.items() if k != "COMPOSE_PROJECT_NAME"}
    env.update(PATH=f"{bindir}:{os.environ['PATH']}", FAKE_DOCKER_LOG=str(log))
    r = subprocess.run(
        ["bash", "-c", f'. "{LIB_INSTANCE}" >/dev/null 2>&1; noo_prepare_gateway_data_dirs'],
        env=env, capture_output=True, text=True, cwd=cwd,
    )
    assert r.returncode == 0, r.stderr
    argv = log.read_text().splitlines()
    assert "noomesh_noo-data:/d" in argv, argv
    assert not any(a.startswith(".noo") for a in argv), argv


def test_prep_failure_is_reported_not_swallowed(tmp_path: Path) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    docker = bindir / "docker"
    # The volume exists and is bound (so noo_ensure_data_volume is quiet);
    # only the throwaway chown container fails: that stays non-fatal.
    docker.write_text(
        '#!/bin/sh\n'
        'case "$1 $2" in "volume inspect") case "$*" in *device*) echo "/r/noo-data";; esac; exit 0;; esac\n'
        'echo "invalid volume name" >&2\nexit 125\n'
    )
    docker.chmod(0o755)
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "COMPOSE_PROJECT_NAME": "proj", "NOO_DATA_ROOT": "/r"}
    env.pop("NOO_STATE_ROOT", None)
    r = subprocess.run(
        ["bash", "-c", f'. "{LIB_INSTANCE}" >/dev/null 2>&1; noo_prepare_gateway_data_dirs'],
        env=env, capture_output=True, text=True, cwd=tmp_path,
    )
    assert r.returncode == 0, "a failed prep stays non-fatal (the start continues)"
    assert "WARNING" in r.stderr and "invalid volume name" in r.stderr, r.stderr


# ── i677: noo-data is created as compose declares it, never by the mount ──

def _vol_fake(tmp_path: Path, exists: bool, device: str = "") -> tuple[Path, Path]:
    bindir = tmp_path / "vbin"
    bindir.mkdir()
    log = tmp_path / "calls.log"
    docker = bindir / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> "{log}"\n'
        'case "$1 $2" in\n'
        f'  "volume inspect") {"" if exists else "exit 1;"} case "$*" in *device*) printf "%s\\n" "{device}";; *Mountpoint*) echo /var/lib/docker/volumes/x/_data;; esac; exit 0;;\n'
        "esac\nexit 0\n"
    )
    docker.chmod(0o755)
    return bindir, log


def _ensure(tmp_path: Path, exists: bool, device: str = "", **envs: str):
    bindir, log = _vol_fake(tmp_path, exists, device)
    env = {k: v for k, v in os.environ.items() if k not in ("NOO_DATA_ROOT", "NOO_STATE_ROOT", "COMPOSE_PROJECT_NAME")}
    env.update(PATH=f"{bindir}:{os.environ['PATH']}", COMPOSE_PROJECT_NAME="proj", **envs)
    r = subprocess.run(["bash", "-c", f'. "{LIB_INSTANCE}" >/dev/null 2>&1; noo_prepare_gateway_data_dirs'],
                       env=env, capture_output=True, text=True, cwd=tmp_path)
    calls = log.read_text().splitlines() if log.exists() else []
    return r, calls


def test_an_absent_noo_data_is_created_bound_and_labelled_before_anything_mounts_it(tmp_path: Path) -> None:
    root = tmp_path / "data"
    (root / "noo-data").mkdir(parents=True)
    r, calls = _ensure(tmp_path, exists=False, NOO_DATA_ROOT=str(root))
    assert r.returncode == 0, r.stderr
    create = [c for c in calls if c.startswith("volume create")]
    assert create == [
        f"volume create --driver local --opt type=none --opt o=bind --opt device={root}/noo-data "
        "--label com.docker.compose.project=proj --label com.docker.compose.volume=noo-data proj_noo-data"
    ], calls
    run = [i for i, c in enumerate(calls) if c.startswith("run ")]
    assert run and calls.index(create[0]) < run[0], "created before the throwaway container mounts it"


def test_the_state_root_wins_as_in_the_compose_declaration(tmp_path: Path) -> None:
    (tmp_path / "state" / "noo-data").mkdir(parents=True)
    r, calls = _ensure(tmp_path, exists=False, NOO_DATA_ROOT=str(tmp_path / "data"), NOO_STATE_ROOT=str(tmp_path / "state"))
    assert r.returncode == 0, r.stderr
    assert any(f"device={tmp_path}/state/noo-data " in c for c in calls if c.startswith("volume create")), calls


def test_no_data_root_refuses_and_nothing_creates_the_volume(tmp_path: Path) -> None:
    r, calls = _ensure(tmp_path, exists=False)
    assert r.returncode == 1
    assert "NOO_DATA_ROOT is not set" in r.stderr, r.stderr
    assert not any(c.startswith(("volume create", "run ")) for c in calls), "never a plain volume, never a mount that would make one"


def test_a_missing_bind_directory_refuses_and_nothing_creates_the_volume(tmp_path: Path) -> None:
    r, calls = _ensure(tmp_path, exists=False, NOO_DATA_ROOT=str(tmp_path / "nowhere"))
    assert r.returncode == 1
    assert f"{tmp_path}/nowhere/noo-data does not exist" in r.stderr, r.stderr
    assert not any(c.startswith(("volume create", "run ")) for c in calls), calls


def test_an_existing_unbound_noo_data_is_named_loudly_and_left_alone(tmp_path: Path) -> None:
    (tmp_path / "data" / "noo-data").mkdir(parents=True)
    r, calls = _ensure(tmp_path, exists=True, device="", NOO_DATA_ROOT=str(tmp_path / "data"))
    assert r.returncode == 0, "an existing install keeps starting"
    assert "is NOT bound to the data root" in r.stderr and "/var/lib/docker/volumes/x/_data" in r.stderr, r.stderr
    assert not any(c.startswith(("volume create", "volume rm")) for c in calls), "never recreated or moved silently"


def test_an_existing_bound_noo_data_is_quiet(tmp_path: Path) -> None:
    (tmp_path / "data" / "noo-data").mkdir(parents=True)
    r, calls = _ensure(tmp_path, exists=True, device=f"{tmp_path}/data/noo-data", NOO_DATA_ROOT=str(tmp_path / "data"))
    assert r.returncode == 0 and "WARNING" not in r.stderr, r.stderr
    assert not any(c.startswith("volume create") for c in calls), calls
