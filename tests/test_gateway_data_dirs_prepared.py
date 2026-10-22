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
    assert re.search(r"^\s*noo_prepare_gateway_data_dirs\s*$", body, re.M), "noomesh-start.sh no longer prepares the gateway's dirs"
    assert "/d/ingest" not in body, "an inline copy of the list in noomesh-start.sh would drift from lib-instance.sh"


def test_restart_prepares_when_it_recreates_the_gateway() -> None:
    body = _uncommented((SCRIPTS / "noomesh-restart.sh").read_text())
    calls = re.findall(r"^\s*noo_prepare_gateway_data_dirs\s*$", body, re.M)
    assert len(calls) == 2, "noomesh-restart.sh must prepare on the whole-stack path and when `gateway` is named"
    named = body.index('SERVICES=("${RESOLVED_SERVICES[@]}")')
    assert re.search(r"grep -qx gateway;\s*then\s*noo_prepare_gateway_data_dirs", body[named:]), (
        "the named-services path must prepare after resolving names (an alias resolves to `gateway` only then)"
    )
