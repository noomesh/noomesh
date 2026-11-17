# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The self-node's root applier re-owns a root-owned hf-cache/hub, safely.

On a fresh controller onboard runs "storage" before "services": the storage
step made hf-cache/hub while noo-agent did not exist yet (owner 0:0), then
prep-host created noo-agent and re-owned hf-cache but not hub. The node agent
could not write hub, where HF weights land. pop-os has carried that since
2026-09-07, with content (snapshots/ are relative symlinks into ../../blobs).

`hf_hub_reown` (scripts/noo-apply.sh, between its BEGIN/END markers) runs in
the agent-env block as root. Each rule is security-critical and pinned here:

  a. the target is exactly "$HF_CACHE_DIR/hub" (a sibling such as hf-cache's
     `token` is never touched);
  b. HF_CACHE_DIR resolves inside NOO_DATA_ROOT (a `..` escape is refused)
     and no component below the root is a symlink;
  c. a symlinked hub, or a hub that is not a directory, is refused;
  d. only a hub owned by uid 0 under an hf-cache owned by noo-agent;
  e. `chown -R -P -h`: a symlink inside hub pointing OUTSIDE the data root
     is re-owned itself, its target never visited; modes unchanged;
  f. one line saying what was done, or why not.

The test runs unprivileged: the block is sourced and its fixed seams are
overridden after it. HF_HUB_AGENT_USER is this test's own user (so "owned by
noo-agent" means owned by us), HF_HUB_ROOT_UID is our uid (so our tree reads
as "root-owned"), and HF_HUB_CHOWN is a shim that logs its argv and then runs
the REAL `chown -v` with the same arguments: chowning to our own uid:gid is
allowed, and GNU chown -v names every path it visits ("ownership of 'P'
retained ..."), which is the exact set a root run would re-own.
"""
from __future__ import annotations

import os
import pwd
import re
import stat
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
APPLIER = REPO / "scripts" / "noo-apply.sh"
ME = os.getuid()
ME_NAME = pwd.getpwuid(ME).pw_name


def _block() -> str:
    m = re.search(r"# BEGIN hf_hub_reown\n(.*?)# END hf_hub_reown", APPLIER.read_text(), re.S)
    assert m, "hf_hub_reown is not delimited in noo-apply.sh"
    return m.group(1)


def _tree(tmp: Path) -> dict[str, Path]:
    """A data root whose hub is shaped like pop-os's: blobs/ with a file,
    snapshots/<rev>/ with a relative symlink into ../../blobs, plus a symlink
    pointing OUTSIDE the data root at a directory with a file in it."""
    root = tmp / "noo"
    cache = root / "hf-cache"
    hub = cache / "hub"
    blobs = hub / "models--x--y" / "blobs"
    snap = hub / "models--x--y" / "snapshots" / "rev1"
    blobs.mkdir(parents=True)
    snap.mkdir(parents=True)
    blob = blobs / "abc123"
    blob.write_text("weights")
    blob.chmod(0o640)
    (snap / "model.safetensors").symlink_to("../../blobs/abc123")
    outside = tmp / "outside"
    outside.mkdir()
    (outside / "secret").write_text("not ours")
    (outside / "secret").chmod(0o600)
    (snap / "escape").symlink_to(outside)
    (cache / "token").write_text("hf_token")
    return {"root": root, "cache": cache, "hub": hub, "blob": blob, "outside": outside, "snap": snap}


def _run(tmp: Path, root: str, cache: str, root_uid: int = ME, agent: str = ME_NAME) -> tuple[subprocess.CompletedProcess, list[str], list[str]]:
    """Returns (process, chown argv lines, paths chown -v visited)."""
    shim = tmp / "chown-shim"
    log = tmp / "chown.argv"
    vis = tmp / "chown.visited"
    shim.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{log}"\nexec chown -v "$@" >> "{vis}"\n')
    shim.chmod(0o755)
    script = (
        _block()
        + f'\nHF_HUB_CHOWN="{shim}"\nHF_HUB_ROOT_UID={root_uid}\nHF_HUB_AGENT_USER="{agent}"\n'
        + 'hf_hub_reown "$1" "$2"\n'
    )
    r = subprocess.run(["sh", "-c", "set -eu\n" + script, "_", root, cache], capture_output=True, text=True)
    argv = log.read_text().splitlines() if log.exists() else []
    visited = re.findall(r"ownership of '([^']*)'", vis.read_text()) if vis.exists() else []
    return r, argv, visited


def _modes(paths: list[Path]) -> dict[Path, int]:
    return {p: os.lstat(p).st_mode for p in paths}


def test_a_root_owned_hub_is_reowned_physically_and_only_hub(tmp_path: Path) -> None:
    t = _tree(tmp_path)
    watch = [t["blob"], t["outside"], t["outside"] / "secret", t["cache"] / "token", t["hub"]]
    before = _modes(watch)
    r, argv, visited = _run(tmp_path, str(t["root"]), str(t["cache"]))
    assert r.returncode == 0, r.stderr
    # a + e: every visited path is hub or inside it, reached physically.
    expected = {str(t["hub"])} | {str(Path(d) / n) for d, ds, fs in os.walk(t["hub"]) for n in ds + fs}
    assert set(visited) == expected, sorted(set(visited) ^ expected)
    assert not any(v.startswith(str(t["outside"])) or "/escape/" in v for v in visited), visited
    assert str(t["cache"] / "token") not in visited
    # The outside symlink is re-owned itself (lchown), its target never.
    assert str(t["snap"] / "escape") in visited
    # e: the exact flags, owner only, hf-cache's uid:gid, hub as the one target.
    st = os.stat(t["cache"])
    assert argv == [f"-R -P -h {st.st_uid}:{st.st_gid} -- {t['hub']}"], argv
    # modes unchanged (never a chmod), the outside tree included.
    assert _modes(watch) == before
    assert stat.S_IMODE(os.lstat(t["blob"]).st_mode) == 0o640
    # f: one line, the count is hub's entries.
    n = len(expected) - 1
    assert r.stdout.strip() == f"noo-apply: re-owned {t['hub']} ({n} entries) to {ME_NAME}", r.stdout
    assert r.stderr == ""


def test_hf_cache_outside_the_data_root_is_refused(tmp_path: Path) -> None:
    t = _tree(tmp_path)
    other = tmp_path / "noo2"
    other.mkdir()
    # A `..` escape that a lexical walk alone would accept, and a plain path elsewhere.
    for cache in (f"{t['root']}/../outside-cache/hf-cache", str(t["cache"])):
        if cache.endswith("outside-cache/hf-cache"):
            (tmp_path / "outside-cache" / "hf-cache" / "hub").mkdir(parents=True)
            root = str(t["root"])
        else:
            root = str(other)
        r, argv, _ = _run(tmp_path, root, cache)
        assert argv == [], f"{cache}: {argv}"
        assert "not re-owned" in r.stderr and "not inside NOO_DATA_ROOT" in r.stderr, r.stderr


def test_a_symlinked_component_of_hf_cache_is_refused(tmp_path: Path) -> None:
    t = _tree(tmp_path)
    real = t["root"] / "real"
    real.mkdir()
    t["cache"].rename(real / "hf-cache")
    (t["root"] / "link").symlink_to(real)
    r, argv, _ = _run(tmp_path, str(t["root"]), str(t["root"] / "link" / "hf-cache"))
    assert argv == [], argv
    assert f"{t['root']}/link is a symlink" in r.stderr, r.stderr


def test_a_symlinked_hub_is_refused(tmp_path: Path) -> None:
    t = _tree(tmp_path)
    t["hub"].rename(t["root"] / "hub-real")
    t["hub"].symlink_to(t["root"] / "hub-real")
    r, argv, _ = _run(tmp_path, str(t["root"]), str(t["cache"]))
    assert argv == [], argv
    assert f"{t['hub']} is a symlink" in r.stderr, r.stderr


def test_a_hub_that_is_not_a_directory_is_refused(tmp_path: Path) -> None:
    t = _tree(tmp_path)
    import shutil

    shutil.rmtree(t["hub"])
    t["hub"].write_text("not a dir")
    r, argv, _ = _run(tmp_path, str(t["root"]), str(t["cache"]))
    assert argv == [], argv
    assert f"{t['hub']} is not a directory" in r.stderr, r.stderr


def test_no_action_when_hub_is_not_root_owned(tmp_path: Path) -> None:
    t = _tree(tmp_path)
    # Our tree, but "root" is some other uid: hub is already the agent's.
    r, argv, _ = _run(tmp_path, str(t["root"]), str(t["cache"]), root_uid=ME + 1)
    assert argv == [] and r.stdout == "" and r.stderr == "", (argv, r.stdout, r.stderr)


def test_no_action_when_hf_cache_is_not_the_agents(tmp_path: Path) -> None:
    t = _tree(tmp_path)
    # The agent is root (uid 0), which does not own our hf-cache.
    r, argv, _ = _run(tmp_path, str(t["root"]), str(t["cache"]), agent="root")
    assert argv == [] and r.stdout == "" and r.stderr == "", (argv, r.stdout, r.stderr)


def test_nothing_when_hub_is_missing_or_the_agent_account_is_absent(tmp_path: Path) -> None:
    t = _tree(tmp_path)
    r, argv, _ = _run(tmp_path, str(t["root"]), str(t["cache"]), agent="noo-no-such-user-rh")
    assert argv == [] and r.stdout == "" and r.stderr == ""
    import shutil

    shutil.rmtree(t["hub"])
    r, argv, _ = _run(tmp_path, str(t["root"]), str(t["cache"]))
    assert argv == [] and r.stdout == "" and r.stderr == ""


def test_the_applier_runs_it_in_the_agent_env_block_from_the_staged_env() -> None:
    src = APPLIER.read_text()
    block = src.index('if [ -f "$WORK/files/agent-env" ]; then\n    grep -qE \'^NODE_ID=.+\'')
    end = src.index('applied="$applied $ae_state"', block)
    body = src[block:end]
    call = body.index("hf_hub_reown ")
    assert body.index("grant_traverse_flush_missing") < call
    tail = body[call:]
    assert "grep -E '^NOO_DATA_ROOT=' \"$WORK/files/agent-env\"" in tail
    assert "grep -E '^HF_CACHE_DIR=' \"$WORK/files/agent-env\"" in tail
    # The seams are fixed in the script, never read from the environment.
    blk = _block()
    for line in ("HF_HUB_CHOWN=chown\n", "HF_HUB_ROOT_UID=0\n", "HF_HUB_AGENT_USER=noo-agent\n"):
        assert line in blk, line
