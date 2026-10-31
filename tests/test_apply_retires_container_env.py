# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The applier removes the retired ~/pai-assistant/.env, and nothing else (i95).

`noo cluster push-secrets` once wrote the fleet credentials into the old
container era's compose env. Nothing reads it any more, so a node that still
has one is carrying stale fleet secrets at 0644. Every bundle that carries the
CLI names the node's user (`cli-user`), and the `retire_container_env` block
of scripts/noo-apply.sh removes the file as that user.

The block is lifted out between its BEGIN/END markers and run with
`runuser` and `getent` stubbed (the real ones want root and a real account).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
APPLIER = (REPO / "scripts" / "noo-apply.sh").read_text()

STALE = "NODE_ID=robopi\nNOO_CLUSTER_SECRET=old\nNOO_NODE_AGENT_TOKEN=old\nNATS_USER=u\nNATS_PASSWORD=p\n"


def block() -> str:
    m = re.search(r"# BEGIN retire_container_env\n(.*?)# END retire_container_env", APPLIER, re.S)
    assert m, "retire_container_env is not delimited in noo-apply.sh"
    return m.group(1)


def run(tmp: Path, cli_user: str | None, env: str | None, symlink_to: Path | None = None) -> tuple[str, str, Path]:
    work = tmp / "work"
    (work / "files").mkdir(parents=True)
    if cli_user is not None:
        (work / "files" / "cli-user").write_text(cli_user + "\n")
    home = tmp / "home"
    (home / "pai-assistant").mkdir(parents=True)
    f = home / "pai-assistant" / ".env"
    if symlink_to is not None:
        f.symlink_to(symlink_to)
    elif env is not None:
        f.write_text(env)
    script = f"""set -eu
WORK="{work}"; applied=""
getent() {{ [ "$2" = node ] && echo "node:x:1000:1000::{home}:/bin/sh"; }}
runuser() {{ [ "$1" = -u ] && [ "$3" = -- ] || exit 99; shift 3; "$@"; }}
{block()}
echo "applied=$applied"
"""
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    applied = r.stdout.strip().split("applied=", 1)[1]
    return applied, r.stderr, f


def test_a_stale_env_with_fleet_credentials_is_removed(tmp_path: Path) -> None:
    applied, _, f = run(tmp_path, "node", STALE)
    assert not f.exists() and not f.is_symlink()
    assert applied.split() == ["container-env-retired"]


def test_a_file_without_fleet_credentials_is_left_and_said(tmp_path: Path) -> None:
    applied, err, f = run(tmp_path, "node", "NOO_DATA_ROOT=/data\n")
    assert f.read_text() == "NOO_DATA_ROOT=/data\n"
    assert applied == ""
    assert "holds no fleet credential — left in place" in err


def test_a_symlink_is_never_followed_or_removed(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.env"
    target.write_text(STALE)
    applied, _, f = run(tmp_path, "node", None, symlink_to=target)
    assert f.is_symlink() and target.read_text() == STALE
    assert applied == ""


def test_no_file_is_a_quiet_no_op(tmp_path: Path) -> None:
    applied, err, _ = run(tmp_path, "node", None)
    assert applied == "" and err == ""


def test_without_a_named_ordinary_user_nothing_is_touched(tmp_path: Path) -> None:
    for i, user in enumerate([None, "root", "", "a b", "../x", "nobody-known"]):
        applied, _, f = run(tmp_path / str(i), user, STALE)
        assert f.read_text() == STALE, user
        assert applied == "", user


def test_the_removal_runs_as_the_user_not_as_root() -> None:
    # Root following a symlink planted in a user's tree is the hazard the CLI
    # install already avoids; the removal takes the same road.
    b = block()
    rm = b.index('rm -f "$f"')
    assert b.rfind('runuser -u "$_rce_user" --', 0, rm) != -1, "rm must run inside runuser"
    assert "rm " not in b[:b.index("runuser -u")], "nothing is removed as root"
