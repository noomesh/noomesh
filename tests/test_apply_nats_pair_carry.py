# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""agent-env replaces the node's env whole; the node's NATS pair must survive it.

The pair is not an agent-env key: it rides the `nats-creds` bundle kind. A
bundle that carries agent-env WITHOUT nats-creds dropped the pair the node
already held, and the agent came back with no bus credential while still
registering over HTTP. `agent_env_carry_nats_pair` (lifted from
scripts/noo-apply.sh between its markers) carries this node's own pair into
the staged env; a bundle WITH nats-creds still replaces it (the merge block
that follows in the applier, checked here by the order of the two blocks).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
APPLIER = REPO / "scripts" / "noo-apply.sh"

NEW_ENV = "NODE_ID=host3\nCONTROLLER_URL=https://noo-controller:8080\nNOO_NODE_AGENT_TOKEN=tok\n"


def block() -> str:
    m = re.search(r"# BEGIN agent_env_nats_carry\n(.*?)# END agent_env_nats_carry", APPLIER.read_text(), re.S)
    assert m, "agent_env_carry_nats_pair is not delimited in noo-apply.sh"
    return m.group(1)


def carry(tmp: Path, old: str | None, node: str = "host3") -> tuple[str, subprocess.CompletedProcess]:
    new = tmp / "staged.env"
    new.write_text(NEW_ENV)
    old_p = tmp / "installed.env"
    if old is not None:
        old_p.write_text(old)
    r = subprocess.run(
        ["bash", "-c", block() + '\nagent_env_carry_nats_pair "$1" "$2" "$3"', "_", str(new), str(old_p), node],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return new.read_text(), r


def test_the_pair_is_preserved_when_the_bundle_has_no_nats_creds(tmp_path: Path) -> None:
    out, r = carry(tmp_path, "NODE_ID=host3\nNATS_NODE_USER=node-host3\nNATS_NODE_PASSWORD=pw-1\n")
    assert out.startswith(NEW_ENV), "the bundle's env is installed as rendered"
    assert "NATS_NODE_USER=node-host3\n" in out and "NATS_NODE_PASSWORD=pw-1\n" in out
    assert "kept this node's existing NATS pair (node-host3)" in r.stdout


def test_a_password_held_as_a_file_pointer_is_carried_as_the_pointer(tmp_path: Path) -> None:
    out, _ = carry(tmp_path, "NODE_ID=host3\nNATS_NODE_USER=node-host3\n"
                             "NATS_NODE_PASSWORD_FILE=/etc/noo/agent-secrets/NATS_NODE_PASSWORD\n")
    assert "NATS_NODE_PASSWORD_FILE=/etc/noo/agent-secrets/NATS_NODE_PASSWORD\n" in out
    assert "NATS_NODE_PASSWORD=" not in out.replace("NATS_NODE_PASSWORD_FILE=", "")


def test_another_nodes_pair_is_never_carried(tmp_path: Path) -> None:
    out, r = carry(tmp_path, "NODE_ID=old\nNATS_NODE_USER=node-old\nNATS_NODE_PASSWORD=pw\n")
    assert "NATS_NODE" not in out
    assert "belongs to 'node-old', not node-host3" in r.stderr


def test_no_pair_to_carry_says_so(tmp_path: Path) -> None:
    out, r = carry(tmp_path, "NODE_ID=host3\n")
    assert out == NEW_ENV
    assert "holds no NATS pair" in r.stderr and "nats-creds rotate host3" in r.stderr


def test_no_installed_env_is_a_quiet_noop(tmp_path: Path) -> None:
    out, r = carry(tmp_path, None)
    assert out == NEW_ENV and r.stderr == ""


def test_the_applier_carries_only_without_nats_creds_and_merges_after() -> None:
    src = APPLIER.read_text()
    call = src.index('agent_env_carry_nats_pair "$STAGED_ENV"')
    guard = src.rindex('if [ ! -f "$WORK/files/nats-creds" ]; then', 0, call)
    assert call - guard < 200, "the carry must be guarded on the bundle carrying no nats-creds"
    # With nats-creds, the merge that REPLACES the pair runs after agent-env.
    merge = src.index('if [ -f "$WORK/files/nats-creds" ]; then')
    assert merge > call
    assert "grep -vE '^(NATS_NODE_USER|NATS_NODE_PASSWORD)=' \"$AGENT_ENV\"" in src[merge:]


def test_the_merge_replaces_a_carried_pair(tmp_path: Path) -> None:
    # The applier's nats-creds merge, as written: drop the old pair, append the new.
    env = tmp_path / "env"
    env.write_text(NEW_ENV + "NATS_NODE_USER=node-host3\nNATS_NODE_PASSWORD=old\n")
    creds = tmp_path / "creds"
    creds.write_text("NODE=host3\nNATS_NODE_USER=node-host3\nNATS_NODE_PASSWORD=new\n")
    m = re.search(r"grep -vE '\^\(NATS_NODE_USER\|NATS_NODE_PASSWORD\)=' \"\$AGENT_ENV\" > \"\$TMPENV\" \|\| true\n"
                  r"\s*grep -E '\^\(NATS_NODE_USER\|NATS_NODE_PASSWORD\)=' \"\$WORK/files/nats-creds\" >> \"\$TMPENV\"",
                  APPLIER.read_text())
    assert m, "the nats-creds merge changed shape"
    script = m.group(0).replace('"$AGENT_ENV"', f'"{env}"').replace(
        '"$WORK/files/nats-creds"', f'"{creds}"').replace('"$TMPENV"', f'"{tmp_path / "out"}"')
    subprocess.run(["bash", "-c", script], check=True)
    out = (tmp_path / "out").read_text()
    assert "NATS_NODE_PASSWORD=new\n" in out and "NATS_NODE_PASSWORD=old" not in out
