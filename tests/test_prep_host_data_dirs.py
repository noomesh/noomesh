# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""prep-host creates the data directories and never re-owns an existing one.

0.6.17-rc.2 rehearsal: prep-host step 7 ran
`install -d -o noo-agent -g noo-agent <root> <root>/hf-cache <root>/models
<root>/ollama`. GNU `install -d -o` RE-OWNS a directory that already exists,
so the ollama store that scripts/lib-reown.sh had given to 65532 (the
hardened ollama image's uid) became noo-agent's. ollama-embed could then not
create /home/nonroot/.ollama/convert, harrier was never created, and RAG
stayed down. Re-owning the root also changed what the CLI wants for every
directory it does not list (it reads the root's owner), so the CLI reported
`noo-data is owned by 0:0, wants 122:122`.

The rule now (one rule with noo-cli onboard/steps.rs intended_owner):

  * the root and ollama are created with their owner when missing, and an
    existing one keeps its owner;
  * models and hf-cache are the node agent's write targets and stay
    noo-agent's (the one re-own prep-host still does);
  * ollama's owner is the same in prep-host, the CLI's table, lib-reown.sh
    and the image's USER.

The block between `# >>> data-dirs` and `# <<< data-dirs` runs for real
against a temp root, with `install` shimmed: the shim logs every call and,
as root, runs the real `install` (with noo-agent mapped to a free uid), so
real owners are checked; as non-root it creates the directories and the log
is the evidence.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREP = ROOT / "scripts" / "prep-host.sh"
STEPS = ROOT / "noo-cli" / "src" / "onboard" / "steps.rs"
REOWN = ROOT / "scripts" / "lib-reown.sh"
OLLAMA_DOCKERFILE = ROOT / "docker" / "Dockerfile.ollama"

AGENT = (4242, 4243)  # what the shim maps noo-agent to
OTHER = (5151, 5152)  # an existing directory's foreign owner
IS_ROOT = os.geteuid() == 0
REAL_INSTALL = shutil.which("install")

SHIM = r"""#!/bin/bash
printf '%s\n' "$*" >> "$SHIM_LOG"
args=()
for a in "$@"; do
  case "$a" in noo-agent) args+=("$SHIM_AGENT_ID") ;; *) args+=("$a") ;; esac
done
if [ "$(id -u)" = 0 ]; then
  # -o/-g of noo-agent arrive as the uid and gid in turn.
  out=(); prev=""
  for a in "${args[@]}"; do
    if [ "$prev" = "-o" ] && [ "$a" = "$SHIM_AGENT_ID" ]; then a="${SHIM_AGENT_ID%%:*}"; fi
    if [ "$prev" = "-g" ] && [ "$a" = "$SHIM_AGENT_ID" ]; then a="${SHIM_AGENT_ID#*:}"; fi
    out+=("$a"); prev="$a"
  done
  exec "$SHIM_REAL_INSTALL" "${out[@]}"
fi
skip=""
for a in "${args[@]}"; do
  if [ -n "$skip" ]; then skip=""; continue; fi
  case "$a" in -o|-g|-m) skip=1 ;; -d) ;; *) mkdir -p "$a" ;; esac
done
"""


def _block() -> str:
    src = PREP.read_text()
    m = re.search(r"^# >>> data-dirs[^\n]*\n(.*?)^# <<< data-dirs$", src, re.S | re.M)
    assert m, "prep-host.sh has no '# >>> data-dirs' ... '# <<< data-dirs' block"
    return m.group(1)


def _run(tmp: Path, data_root: Path) -> list[str]:
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    shim = bindir / "install"
    shim.write_text(SHIM)
    shim.chmod(0o755)
    log = tmp / "install.log"
    log.write_text("")
    script = "set -eu\n" + _block()
    env = dict(os.environ)
    env.update(
        PATH=f"{bindir}:{env.get('PATH', '/usr/bin:/bin')}",
        NOO_DATA_ROOT=str(data_root),
        SHIM_LOG=str(log),
        SHIM_AGENT_ID=f"{AGENT[0]}:{AGENT[1]}",
        SHIM_REAL_INSTALL=REAL_INSTALL or "/usr/bin/install",
    )
    r = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    assert r.returncode == 0, f"the data-dirs block failed: {r.stderr}"
    return [line for line in log.read_text().splitlines() if line]


def _owner(p: Path) -> tuple[int, int]:
    st = p.stat()
    return (st.st_uid, st.st_gid)


def _named(calls: list[str], path: Path) -> list[str]:
    return [c for c in calls if str(path) in c.split()]


def test_an_existing_root_and_ollama_store_keep_their_owners():
    import tempfile

    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        root = tmp / "noo"
        for d in (root, root / "ollama", root / "models", root / "hf-cache"):
            d.mkdir(parents=True)
            if IS_ROOT:
                os.chown(d, *OTHER)
        calls = _run(tmp, root)

        assert not _named(calls, root), f"an existing data root was passed to install (re-owned): {calls}"
        assert not _named(calls, root / "ollama"), f"an existing ollama store was passed to install (re-owned): {calls}"
        # The agent's write targets stay its own (the one re-own kept).
        for d in ("models", "hf-cache"):
            assert any("-o noo-agent -g noo-agent" in c for c in _named(calls, root / d)), f"{d}: {calls}"
        if IS_ROOT:
            assert _owner(root) == OTHER and _owner(root / "ollama") == OTHER, "an existing directory changed owner"
            assert _owner(root / "models") == AGENT and _owner(root / "hf-cache") == AGENT


def test_a_missing_root_and_ollama_store_are_created_with_their_owners():
    import tempfile

    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        root = tmp / "noo"
        calls = _run(tmp, root)

        assert [c for c in _named(calls, root) if "-o noo-agent -g noo-agent" in c], f"the root: {calls}"
        assert [c for c in _named(calls, root / "ollama") if "-o 65532 -g 65532" in c], f"ollama: {calls}"
        for d in ("", "ollama", "models", "hf-cache"):
            assert (root / d).is_dir(), f"{root / d} was not created"
        if IS_ROOT:
            assert _owner(root) == AGENT
            assert _owner(root / "ollama") == (65532, 65532)
            assert _owner(root / "models") == AGENT and _owner(root / "hf-cache") == AGENT


def test_the_ollama_store_has_one_owner_everywhere():
    prep = re.search(r"^OLLAMA_STORE_OWNER=(\d+:\d+)$", PREP.read_text(), re.M)
    assert prep, "prep-host.sh no longer sets OLLAMA_STORE_OWNER"
    steps = STEPS.read_text()
    fn = steps.split("pub(crate) fn subdir_owner(", 1)[1].split("\n}\n", 1)[0]
    arm = next((line for line in fn.splitlines() if '"ollama"' in line), None)
    assert arm, "the CLI's subdir_owner no longer lists ollama: the CLI and prep-host disagree on its owner"
    cli = re.search(r'Some\("(\d+:\d+)"\)', arm)
    assert cli, arm
    reown = re.search(r"^NOO_REOWN_UID=(\d+)$", REOWN.read_text(), re.M)
    user = re.search(r"^USER (\d+):(\d+)$", OLLAMA_DOCKERFILE.read_text(), re.M)
    assert reown and user
    owners = {
        "prep-host": prep.group(1),
        "noo-cli subdir_owner": cli.group(1),
        "lib-reown.sh": f"{reown.group(1)}:{reown.group(1)}",
        "Dockerfile.ollama USER": f"{user.group(1)}:{user.group(2)}",
    }
    assert len(set(owners.values())) == 1, f"the ollama store's owner disagrees: {owners}"


def test_install_d_o_only_creates_or_names_the_agents_targets():
    """Every `install -d -o` in the block is data_dir's (it only creates) or
    the line for the agent's two write targets: none names the root or ollama."""
    lines = [ln.strip() for ln in _block().splitlines() if re.match(r"\s*install -d .*-o ", ln)]
    assert lines, "the block has no install -d -o at all: this guard is reading the wrong text"
    for ln in lines:
        if '"$1"' in ln:
            continue  # data_dir's body, behind its [ -d ] test
        assert ln in (
            'install -d -o noo-agent -g noo-agent "$NOO_DATA_ROOT/hf-cache" "$NOO_DATA_ROOT/models"',
            'install -d -o noo-agent -g noo-agent "$NOO_DATA_ROOT/hf-cache/hub"',
        ), ln


def test_hub_gets_hf_caches_owner_when_missing_or_empty():
    """The onboard storage step makes hf-cache/hub before prep-host creates
    noo-agent (onboard runs storage, then services), so on a fresh controller
    hub was 0:0 under a noo-agent hf-cache and the node agent could not write
    the HF weights. prep-host gives a missing or EMPTY hub hf-cache's owner,
    after hf-cache itself."""
    import tempfile

    for pre in ("missing", "empty"):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            root = tmp / "noo"
            (root / "hf-cache").mkdir(parents=True)
            if pre == "empty":
                (root / "hf-cache" / "hub").mkdir()
                if IS_ROOT:
                    os.chown(root / "hf-cache" / "hub", 0, 0)
            calls = _run(tmp, root)
            hub = root / "hf-cache" / "hub"
            named = _named(calls, hub)
            assert named == [f"-d -o noo-agent -g noo-agent {hub}"], f"{pre}: {calls}"
            parent = _named(calls, root / "hf-cache")
            assert parent and calls.index(parent[0]) < calls.index(named[0]), f"hub before hf-cache: {calls}"
            assert hub.is_dir()
            if IS_ROOT:
                assert _owner(hub) == AGENT == _owner(root / "hf-cache")


def test_a_hub_with_content_or_a_symlink_hub_is_left_to_the_applier():
    """A hub with content is re-owned recursively by the self-node applier
    (noo-apply.sh hf_hub_reown), which acts only on a 0-owned hub: re-owning
    its top here would hide the content from it. A symlinked hub is never
    passed to install (install -d follows the link and re-owns its target)."""
    import tempfile

    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        root = tmp / "noo"
        hub = root / "hf-cache" / "hub"
        (hub / "blobs").mkdir(parents=True)
        (hub / "blobs" / "x").write_text("w")
        calls = _run(tmp, root)
        assert not _named(calls, hub), f"a hub with content was passed to install: {calls}"
        if IS_ROOT:
            assert _owner(hub) == (0, 0)

    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        root = tmp / "noo"
        (root / "hf-cache").mkdir(parents=True)
        elsewhere = tmp / "elsewhere"
        elsewhere.mkdir()
        (root / "hf-cache" / "hub").symlink_to(elsewhere)
        calls = _run(tmp, root)
        assert not _named(calls, root / "hf-cache" / "hub"), f"a symlinked hub was passed to install: {calls}"
