# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A node enrolled by root gets its CLI, and its stale container env retired.

`scripts/noo-apply.sh` refused `cli-user` root with exit 65 ("not an ordinary
account name") since 0.6.0, which failed the WHOLE bundle for every node
enrolled as root: a VPS, a root shell, the rehearsal's node2 (0.6.24-rc.3,
A-pull.key: "noo-apply: REFUSED — cli-user 'root' …", "the applier refused
the bundle (exit 65)"). The as-the-user rule protects a tree another account
controls; root's own home is not one. install.sh as root installs to
/root/.local/bin, which is where the applier writes.

The cli-binary block and the retire_container_env block are lifted from the
real script and run with `getent` and `runuser` stubbed (the real runuser
wants root): `getent passwd <u>` answers a home under the test's tmp dir, and
`runuser -u <u> -- cmd…` runs cmd as the test user, recording <u>.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
APPLIER = (REPO / "scripts" / "noo-apply.sh").read_text()
ELF = b"\x7fELF" + b"\x02\x01\x01\x00" * 4 + b"payload"


def cli_block() -> str:
    m = re.search(r'(if \[ -f "\$WORK/files/cli-binary" \] && \[ -s "\$WORK/files/cli-user" \]; then\n.*?\n)fi\n', APPLIER, re.S)
    assert m, "cli-binary block not found in noo-apply.sh"
    return m.group(1) + "fi\n"


def retire_block() -> str:
    m = re.search(r"# BEGIN retire_container_env\n(.*?)# END retire_container_env", APPLIER, re.S)
    assert m, "retire_container_env is not delimited in noo-apply.sh"
    return m.group(1)


def stubs(tmp: Path) -> tuple[Path, Path]:
    bindir = tmp / "stub"
    bindir.mkdir(exist_ok=True)
    homes = tmp / "homes"
    homes.mkdir(exist_ok=True)
    (bindir / "getent").write_text(
        f'#!/bin/sh\n[ "$1" = passwd ] || exit 2\n'
        f'case "$2" in nohome) exit 2 ;; esac\n'
        f'mkdir -p "{homes}/$2"; echo "$2:x:0:0::{homes}/$2:/bin/sh"\n'
    )
    (bindir / "runuser").write_text(
        f'#!/bin/sh\n[ "$1" = -u ] || exit 2\necho "$2" >> "{tmp}/runuser.log"\nshift 3\nexec "$@"\n'
    )
    for f in ("getent", "runuser"):
        (bindir / f).chmod(0o755)
    return bindir, homes


def run_cli(tmp: Path, user: str) -> tuple[subprocess.CompletedProcess, Path]:
    work = tmp / "work"
    (work / "files").mkdir(parents=True, exist_ok=True)
    (work / "files" / "cli-binary").write_bytes(ELF)
    (work / "files" / "cli-user").write_text(user + "\n")
    bindir, homes = stubs(tmp)
    script = (
        'set -u\nWORK="$1"\napplied=""\n'
        'note_binary_sha() { :; }\n'
        + cli_block()
        + 'echo "applied=[$applied]"\n'
    )
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}
    p = subprocess.run(["bash", "-c", script, "applier", str(work)], capture_output=True, text=True, env=env, timeout=60)
    return p, homes


def test_a_root_enrolled_node_gets_its_cli_in_roots_own_home(tmp_path):
    p, homes = run_cli(tmp_path, "root")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "REFUSED" not in p.stderr, p.stderr
    assert (homes / "root" / ".local" / "bin" / "noo").read_bytes() == ELF
    assert "applied=[ cli-binary]" in p.stdout, p.stdout
    # Written through runuser as root (the same path as any user).
    assert "root" in (tmp_path / "runuser.log").read_text().split()


def test_an_ordinary_user_still_gets_it_in_their_home(tmp_path):
    p, homes = run_cli(tmp_path, "alex")
    assert p.returncode == 0, p.stdout + p.stderr
    assert (homes / "alex" / ".local" / "bin" / "noo").read_bytes() == ELF


@pytest.mark.parametrize("bad", ["a|b", "../etc", "Alex", "x;rm"])
def test_a_name_that_is_not_an_account_is_still_refused(tmp_path, bad):
    p, homes = run_cli(tmp_path, bad)
    assert p.returncode == 65, p.stdout + p.stderr
    assert "is not a valid account name" in p.stderr, p.stderr
    assert not any(homes.rglob("noo"))


def test_root_s_stale_container_env_is_retired_too(tmp_path):
    work = tmp_path / "work"
    (work / "files").mkdir(parents=True)
    (work / "files" / "cli-user").write_text("root\n")
    bindir, homes = stubs(tmp_path)
    env_file = homes / "root" / "pai-assistant" / ".env"
    env_file.parent.mkdir(parents=True)
    env_file.write_text("NOO_CLUSTER_SECRET=x\n")
    script = 'set -u\nWORK="$1"\napplied=""\n' + retire_block() + 'echo "applied=[$applied]"\n'
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}
    p = subprocess.run(["bash", "-c", script, "applier", str(work)], capture_output=True, text=True, env=env, timeout=60)
    assert p.returncode == 0, p.stdout + p.stderr
    assert not env_file.exists(), "root's stale credential env was left in place"
    assert "container-env-retired" in p.stdout, p.stdout
