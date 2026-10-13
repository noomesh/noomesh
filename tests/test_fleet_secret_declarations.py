# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The fleet-wide secret keys, declared in three languages, plus the
applier block that consumes them.

`FLEET_KEYS` (Rust), `FS_KEYS` (shell) and `FLEET_SECRET_KEYS` (Go) are the
same fact in three files that cannot import each other. The applier's list is
not cosmetic: `/etc/noo-node-agent.env` is read by systemd as an
`EnvironmentFile` for a ROOT unit, so a fragment able to name any key is a
fragment able to set `PATH`.

These checks began life as Rust `#[test]`s next to the code. They could not
stay there: the `noo-cli` CI job builds the crate in isolation, so
`scripts/noo-apply.sh` and `node-agent-go/deploy/*` are simply absent and
every one of them failed on a missing file. Same shape as the `include_str!`
that reached outside its crate — a test that reads across the repo belongs at
the repo level.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
PUSH_RS = REPO / "noo-cli/src/commands/cluster_push_secrets.rs"
FETCH_RS = REPO / "noo-cli/src/commands/node_fetch.rs"
APPLY_SH = REPO / "scripts/noo-apply.sh"
SIGN_SH = REPO / "scripts/sign-bundle.sh"
ENV_TMPL = REPO / "node-agent-go/deploy/noo-node-agent.env.tmpl"

CONTROLLER_ONLY = ["POSTGRES_PASSWORD", "REDIS_PASSWORD", "NOO_JWT_SECRET", "ANTHROPIC_API_KEY"]


def fleet_keys() -> list[str]:
    src = PUSH_RS.read_text()
    m = re.search(r"pub\(crate\) const FLEET_KEYS: &\[FleetKey\] = &\[(.*?)\n\];", src, re.S)
    assert m, "FLEET_KEYS not found — this test is reading the wrong thing"
    keys = re.findall(r'key: "([A-Z0-9_]+)"', m.group(1))
    assert keys, "FLEET_KEYS parsed empty"
    return keys


def test_every_applier_knows_exactly_these_keys() -> None:
    mine = fleet_keys()

    line = next(
        (l for l in APPLY_SH.read_text().splitlines() if l.strip().startswith("FS_KEYS=")),
        None,
    )
    assert line, "noo-apply.sh no longer defines FS_KEYS — this test is checking a dead string"
    listed = line.split("=", 1)[1].strip().strip("'").split("|")
    assert listed == mine, f"noo-apply.sh FS_KEYS {listed} vs FLEET_KEYS {mine}"

    go = FETCH_RS.read_text()
    m = re.search(r"FLEET_SECRET_KEYS: &\[&str\] =\s*&\[(.*?)\];", go, re.S)
    assert m, "FLEET_SECRET_KEYS not found in node_fetch.rs"
    assert re.findall(r'"([A-Z0-9_]+)"', m.group(1)) == mine


def test_the_bundle_kind_is_in_both_allowlists() -> None:
    # A correctly-built bundle whose kind the applier does not know is
    # refused on arrival with exit 76.
    for path, needle in ((APPLY_SH, "KNOWN_KINDS="), (SIGN_SH, "KNOWN=")):
        line = next((l for l in path.read_text().splitlines() if l.startswith(needle)), None)
        assert line, f"{path.name} no longer defines {needle}"
        assert "fleet-secrets" in line, f"{path.name} {needle} lacks fleet-secrets"


def test_registry_covers_what_the_agent_env_writes() -> None:
    tmpl = ENV_TMPL.read_text().splitlines()
    for key in fleet_keys():
        assert any(l.startswith(f"{key}=") for l in tmpl), (
            f"{key} is in FLEET_KEYS but the agent env template never writes it"
        )
    # Controller-only secrets must NOT be deliverable: pushing a Postgres or
    # Redis password to a worker spreads a credential the node has no use for.
    for key in CONTROLLER_ONLY:
        assert key not in fleet_keys(), f"{key} is controller-only"


# ── the applier block, actually EXECUTED ──────────────────────────────────
#
# The block is LIFTED out of noo-apply.sh rather than re-typed: a test with
# its own copy of the logic passes while the script is broken.

ENV_BEFORE = (
    "NODE_ID=host3\nNODE_TIER=2\nNOO_CLUSTER_SECRET=OLD\n"
    "NOO_NODE_AGENT_TOKEN=KEEPME\nNATS_USER=oldu\nNATS_PASSWORD=oldp\nPATH=/usr/bin\n"
)
# (NATS_USER/NATS_PASSWORD above are the STALE retired lines an existing node
# still carries — The merge must leave them alone; they are no
# longer fleet keys, so a payload naming them is refused.)


def applier_merge(payload: str, env_before: str, node: str) -> tuple[int, str]:
    src = APPLY_SH.read_text()
    start = src.index('if [ -f "$WORK/files/fleet-secrets" ]; then')
    end = src.index('\n    applied="$applied fleet-secrets"', start)
    block = src[start:end]
    with tempfile.TemporaryDirectory() as d:
        work = pathlib.Path(d)
        (work / "files").mkdir()
        (work / "files/fleet-secrets").write_text(payload)
        envp = work / "agent.env"
        envp.write_text(env_before)
        block = block.replace("AGENT_ENV=/etc/noo-node-agent.env", f"AGENT_ENV={envp}")
        # install -o root -g root needs privileges a test does not have.
        block = block.replace("install -m 600 -o root -g root", "install -m 600")
        script = f"set -e\nWORK={work}\nNODE_ID={node}\n{block}\nfi\n"
        p = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
        return p.returncode, p.stderr + envp.read_text()


def test_the_applier_replaces_carried_keys_and_touches_nothing_else() -> None:
    rc, out = applier_merge("NODE=host3\nNOO_CLUSTER_SECRET=NEW\n", ENV_BEFORE, "host3")
    assert rc == 0, out
    assert "NOO_CLUSTER_SECRET=NEW" in out
    assert "NOO_CLUSTER_SECRET=OLD" not in out
    # A payload naming one key must not blank the other.
    assert "NOO_NODE_AGENT_TOKEN=KEEPME" in out, out
    # ...nor touch the stale retired lines (inert; re-provision drops them).
    assert "NATS_USER=oldu" in out and "NATS_PASSWORD=oldp" in out, out
    # …nor re-decide anything the controller has no business re-deciding.
    assert "NODE_TIER=2" in out, out
    assert "PATH=/usr/bin" in out, out
    assert "NODE_ID=host3" in out


def test_the_applier_refuses_a_key_that_is_not_a_fleet_key() -> None:
    rc, out = applier_merge(
        "NODE=host3\nNOO_CLUSTER_SECRET=NEW\nPATH=/evil\n", ENV_BEFORE, "host3"
    )
    assert rc != 0, f"a PATH= line must be refused: {out}"
    assert "PATH=/usr/bin" in out, f"the env must be untouched: {out}"
    assert "/evil" not in out, out


def test_the_applier_refuses_a_payload_addressed_to_another_node() -> None:
    rc, out = applier_merge("NODE=host9\nNOO_CLUSTER_SECRET=NEW\n", ENV_BEFORE, "host3")
    assert rc != 0, out
    assert "NOO_CLUSTER_SECRET=OLD" in out, out


def test_the_applier_refuses_an_unbound_or_empty_payload() -> None:
    for bad in (
        "NOO_CLUSTER_SECRET=NEW\n",  # no NODE=
        "NODE=host3\n",  # names no key
        "NODE=host3\nNOO_NODE_AGENT_TOKEN=\n",  # a key with no value
    ):
        rc, out = applier_merge(bad, ENV_BEFORE, "host3")
        assert rc != 0, f"{bad!r} must be refused: {out}"
        assert "NOO_NODE_AGENT_TOKEN=KEEPME" in out, f"{bad!r} must not write: {out}"


def test_the_retired_shared_bus_pair_is_no_longer_a_fleet_key() -> None:
    """an earlier change: NATS_USER/NATS_PASSWORD were fleet keys; the shared bus
    user is retired, so a payload carrying either is refused whole — a node's
    bus credential rides the `nats-creds` kind, never fleet-secrets."""
    assert "NATS_USER" not in fleet_keys() and "NATS_PASSWORD" not in fleet_keys()
    for bad in ("NODE=host3\nNATS_PASSWORD=p\n", "NODE=host3\nNOO_CLUSTER_SECRET=N\nNATS_USER=u\n"):
        rc, out = applier_merge(bad, ENV_BEFORE, "host3")
        assert rc != 0, f"{bad!r} must be refused: {out}"
        assert "NOO_CLUSTER_SECRET=OLD" in out, f"{bad!r} must not write: {out}"


def test_the_applier_never_leaves_the_agent_without_its_identity() -> None:
    # NODE_ID resolves the cert path. A merge that lost it produces an agent
    # that crash-loops cert-not-found.
    rc, out = applier_merge(
        "NODE=host3\nNOO_CLUSTER_SECRET=u\n", "NODE_TIER=2\nNOO_CLUSTER_SECRET=old\n", "host3"
    )
    assert rc != 0, f"a merge without NODE_ID must abort: {out}"
