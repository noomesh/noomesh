# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The applier makes every declared root reachable by the agent's user.

On host8 (2026-09-13 → 09-18) the data root lived under /media/<user>/, a
udisks mount parent that is 750 root:root plus an ACL for that one person.
The agent's system user could not traverse it, saw the drive as absent and
logged `mkdir /media/<user>/<drive>: permission denied` on every reconcile
while the drive was mounted the whole time. `grant_traverse` in
scripts/noo-apply.sh grants an execute-only ACL on exactly the ancestors
that refuse traverse, and says so.

The function is exercised with a fake `runuser` (refuses traverse on one
directory) and a fake `setfacl` (records what it was asked), since a test
runs as one user and cannot switch.
"""
from __future__ import annotations

import os
import shutil
import re
import stat
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
APPLIER = REPO / "scripts" / "noo-apply.sh"


def _function_block() -> str:
    src = APPLIER.read_text()
    m = re.search(r"# BEGIN grant_traverse\n(.*?)# END grant_traverse", src, re.S)
    assert m, "grant_traverse is not delimited in noo-apply.sh"
    return m.group(1)


def _run(blocked: str, target: str, with_setfacl: bool = True) -> tuple[int, str, str, list[str]]:
    with tempfile.TemporaryDirectory() as tmp:
        fake = Path(tmp) / "bin"
        fake.mkdir()
        log = Path(tmp) / "setfacl.log"
        asked = Path(tmp) / "asked.log"
        (fake / "runuser").write_text(
            "#!/bin/sh\n# runuser -u USER -- test -x DIR: DIR is the last argument\neval d=\\\"\\${$#}\\\"\n"
            f"echo \"$d\" >> {asked}\n"
            # A closed directory closes everything below it, as on a real
            # host — until it is granted, which the fake setfacl records.
            f"grep -qF -- \"--x {blocked}\" {log} 2>/dev/null && exit 0\n"
            f"case \"$d\" in {blocked}|{blocked}/*) exit 1;; esac\nexit 0\n"
        )
        if with_setfacl:
            (fake / "setfacl").write_text(f"#!/bin/sh\necho \"$*\" >> {log}\nexit 0\n")
        for f in fake.iterdir():
            f.chmod(f.stat().st_mode | stat.S_IEXEC)
        # A HERMETIC PATH: the fakes, plus the only two host tools involved —
        # `dirname` (grant_traverse) and `grep` (the fake runuser). The PATH
        # used to end in /usr/bin:/bin, so "without setfacl" still found the
        # host's own /usr/bin/setfacl wherever the acl package is installed.
        # On a fleet node that also has the noo-agent user (host1, a CI
        # runner that is also the host2 node) the real grant then SUCCEEDED
        # and the warning under test never printed.
        for tool in ("dirname", "grep"):
            real = shutil.which(tool)
            assert real, f"{tool} is needed to run grant_traverse"
            (fake / tool).symlink_to(real)
        script = (
            f"set -e\n{_function_block()}\n"
            f'grant_traverse noo-agent "{target}"\n'
            "grant_traverse_flush_missing\n"
        )
        env = {**os.environ, "PATH": str(fake)}
        if not with_setfacl:
            assert shutil.which("setfacl", path=env["PATH"]) is None, "setfacl must be ABSENT for this case"
        p = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, env=env)
        grants = log.read_text().splitlines() if log.exists() else []
        _run.asked = asked.read_text().splitlines() if asked.exists() else []
        return p.returncode, p.stdout, p.stderr, grants


def test_only_the_ancestor_that_refuses_traverse_is_granted(tmp_path: Path) -> None:
    media = tmp_path / "media" / "someone"
    drive = media / "drive1" / "noo" / "ollama"
    drive.mkdir(parents=True)
    rc, out, err, grants = _run(str(media), str(drive))
    assert rc == 0, err
    assert grants == [f"-m u:noo-agent:--x {media}"], grants
    assert "granted noo-agent traverse (execute-only)" in out
    assert str(media) in out


def test_nothing_is_granted_when_every_ancestor_is_traversable(tmp_path: Path) -> None:
    root = tmp_path / "data" / "noo"
    root.mkdir(parents=True)
    rc, out, err, grants = _run("/nowhere", str(root))
    assert rc == 0, err
    assert grants == []
    assert out == ""


def test_a_root_that_does_not_exist_yet_still_gets_its_ancestors_checked(tmp_path: Path) -> None:
    media = tmp_path / "media" / "someone"
    media.mkdir(parents=True)
    rc, _out, err, grants = _run(str(media), str(media / "drive1" / "noo"))
    assert rc == 0, err
    assert grants == [f"-m u:noo-agent:--x {media}"]


def test_without_setfacl_the_applier_names_the_fix_and_continues(tmp_path: Path) -> None:
    media = tmp_path / "media" / "someone"
    (media / "drive1").mkdir(parents=True)
    rc, _out, err, grants = _run(str(media), str(media / "drive1"), with_setfacl=False)
    assert rc == 0, "a missing ACL tool must not fail the whole apply"
    assert grants == []
    # One line naming the missing package and the fix — not the whole
    # per-path sentence repeated for every ancestor (2026-09-29: a worker
    # without the acl package got that paragraph seven times, and the fix
    # it named needs the very binary that is missing).
    assert "WARNING" in err
    assert err.count("acl package is not installed") == 1, "named once, not once per path"
    assert "apt-get install -y acl" in err
    assert str(media) in err
    assert "could not be granted" not in err, "the old full-sentence-per-path wording must be gone"


def test_the_agent_env_step_checks_every_declared_root() -> None:
    src = APPLIER.read_text()
    step = src.split("if [ -f \"$WORK/files/agent-env\" ]; then", 1)[1].split("\nfi\n", 1)[0]
    for key in ("NOO_DATA_ROOT", "MODELS_DIR", "HF_CACHE_DIR"):
        assert key in step, f"{key} is a declared root and must be made reachable"
    assert "grant_traverse noo-agent" in step


def test_the_walk_is_top_down_so_a_closed_parent_is_granted_once(tmp_path: Path) -> None:
    """Bottom-up, `test -x` fails for every directory below a closed one and
    each got its own ACL (three grants for one closed /media/<user> on
    host8). Top-down, the shallowest refusal is granted and the deeper
    directories are judged on their own."""
    media = tmp_path / "media" / "someone"
    leaf = media / "drive1" / "noo" / "ollama"
    leaf.mkdir(parents=True)
    rc, _out, err, grants = _run(str(media), str(leaf))
    assert rc == 0, err
    asked = _run.asked
    assert asked[0] == str(tmp_path.parents[-2]) or asked[0].count("/") == 1, asked[:2]
    assert asked.index(str(media)) < asked.index(str(leaf)), "shallowest first"
    # The fake keeps refusing everything under `media` (it cannot see the
    # grant), so a bottom-up walk would have granted all four directories.
    assert grants == [f"-m u:noo-agent:--x {media}"], grants
