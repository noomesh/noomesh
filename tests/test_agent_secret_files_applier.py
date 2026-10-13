# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The applier delivers the node agent's secrets as FILES.

`agent_secret_files` in scripts/noo-apply.sh runs at the end of every apply:
when the installed agent binary carries the capability marker it moves each
plain secret in /etc/noo-node-agent.env into its own 0600 file owned by the
agent's user and leaves only a `NAME_FILE` pointer; when it does not, it
inlines any pointer back so an older agent never boots pointed at a file it
cannot read. The block is lifted out of the applier between its markers and
run against a temp directory as the current user (the owner argument), the
same way test_applier_grants_traverse_to_the_declared_roots.py drives
grant_traverse.
"""

from __future__ import annotations

import os
import pwd
import re
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
APPLIER = REPO / "scripts" / "noo-apply.sh"
GO_READER = REPO / "node-agent-go/internal/config/secretenv.go"

ME = pwd.getpwuid(os.getuid()).pw_name

# What provision renders into the agent-env member (the secret lines of
# node-agent-go/deploy/noo-node-agent.env.tmpl) plus the nats-creds merge.
RENDERED = (
    "NODE_ID=host3\n"
    "CONTROLLER_URL=https://noo-controller:8080\n"
    "NOO_NODE_AGENT_TOKEN=tok-123\n"
    "NOO_CLUSTER_SECRET=\"cluster-abc\"\n"
    "NATS_USER=\n"
    "NATS_PASSWORD=\n"
    "NOO_TLS_KEY=/etc/noo/pki/nodes/host3/node.key\n"
    "NATS_NODE_USER=node-host3\n"
    "NATS_NODE_PASSWORD=nats-pw\r\n"
)
SECRETS = {"NOO_NODE_AGENT_TOKEN": "tok-123", "NOO_CLUSTER_SECRET": "cluster-abc", "NATS_NODE_PASSWORD": "nats-pw"}


def block() -> str:
    m = re.search(r"# BEGIN agent_secret_files\n(.*?)# END agent_secret_files", APPLIER.read_text(), re.S)
    assert m, "agent_secret_files is not delimited in noo-apply.sh"
    return m.group(1)


def applier_keys() -> list[str]:
    m = re.search(r'^AGENT_SECRET_KEYS="([^"]+)"', block(), re.M)
    assert m, "AGENT_SECRET_KEYS not found in the block"
    return m.group(1).split()


def capability() -> str:
    m = re.search(r'const SecretFilesCapability = "([^"]+)"', GO_READER.read_text())
    assert m, "SecretFilesCapability not found in secretenv.go"
    return m.group(1)


class Node:
    def __init__(self, tmp: Path, capable: bool) -> None:
        self.env = tmp / "noo-node-agent.env"
        self.dir = tmp / "agent-secrets"
        self.bin = tmp / "noo-node-agent"
        self.bak = tmp / "noo-node-agent.env.container-backup"
        self.install_agent(capable)

    def install_agent(self, capable: bool) -> None:
        # An ELF-ish blob: the marker sits in rodata among other bytes.
        marker = capability().encode() if capable else b"noo-agent-reads-plain-env"
        self.bin.write_bytes(b"\x7fELF\x02\x01" + os.urandom(64) + marker + os.urandom(64))

    def run(self, extra: str = "") -> subprocess.CompletedProcess:
        script = (
            f"set -eu\n{block()}\n"
            f'agent_secret_files "{self.env}" "{self.dir}" "{self.bin}" "{ME}" "{self.bak}" || exit $?\n'
            'echo "CHANGED=$ASF_CHANGED"\n' + extra
        )
        return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True)

    def lines(self) -> list[str]:
        return self.env.read_text().splitlines()


def test_a_capable_agent_gets_files_and_the_env_holds_pointers_only(tmp_path: Path) -> None:
    n = Node(tmp_path, capable=True)
    n.env.write_text(RENDERED)
    n.env.chmod(0o600)
    p = n.run()
    assert p.returncode == 0, p.stderr
    assert "CHANGED=1" in p.stdout

    env = n.env.read_text()
    for name, value in SECRETS.items():
        f = n.dir / name
        assert f.read_text() == value, (name, f.read_text())
        st = f.stat()
        assert stat.S_IMODE(st.st_mode) == 0o600, oct(st.st_mode)
        assert st.st_uid == os.getuid()
        assert f"{name}_FILE={f}\n" in env
        assert f"{name}=" not in [line.split("=", 1)[0] + "=" for line in n.lines()], f"{name} is still a plain line"
        assert value not in env, f"{name}'s value is still in the env"
    assert stat.S_IMODE(n.dir.stat().st_mode) == 0o750
    assert stat.S_IMODE(n.env.stat().st_mode) == 0o600
    # non-secrets untouched; the empty shared pair stays an empty line, no file
    assert "NODE_ID=host3" in n.lines() and "NATS_NODE_USER=node-host3" in n.lines()
    assert "NATS_PASSWORD=" in n.lines() and not (n.dir / "NATS_PASSWORD").exists()
    # every secret-carrying line in the env is a pointer now
    for line in n.lines():
        k = line.split("=", 1)[0]
        if k in applier_keys():
            assert line == f"{k}=", line


def test_it_is_idempotent(tmp_path: Path) -> None:
    n = Node(tmp_path, capable=True)
    n.env.write_text(RENDERED)
    assert n.run().returncode == 0
    before = n.env.read_text()
    p = n.run()
    assert p.returncode == 0 and "CHANGED=0" in p.stdout, p.stdout + p.stderr
    assert n.env.read_text() == before


def test_a_merge_after_the_flip_replaces_the_file_and_leaves_one_pointer(tmp_path: Path) -> None:
    """nats-creds / fleet-secrets append PLAIN lines to a converted env; the
    same apply must fold them into the files before the agent restarts, or
    the agent would refuse NAME beside NAME_FILE."""
    n = Node(tmp_path, capable=True)
    n.env.write_text(RENDERED)
    assert n.run().returncode == 0
    with n.env.open("a") as f:
        f.write("NATS_NODE_PASSWORD=rotated\n")
    p = n.run()
    assert p.returncode == 0, p.stderr
    assert (n.dir / "NATS_NODE_PASSWORD").read_text() == "rotated"
    keys = [line.split("=", 1)[0] for line in n.lines()]
    assert keys.count("NATS_NODE_PASSWORD_FILE") == 1 and "NATS_NODE_PASSWORD" not in keys


def test_an_old_agent_keeps_plain_values(tmp_path: Path) -> None:
    n = Node(tmp_path, capable=False)
    n.env.write_text(RENDERED)
    p = n.run()
    assert p.returncode == 0 and "CHANGED=0" in p.stdout, p.stdout + p.stderr
    assert n.env.read_bytes() == RENDERED.encode()
    assert not n.dir.exists()


def test_a_rollback_to_an_old_agent_inlines_the_files_back_and_removes_them(tmp_path: Path) -> None:
    n = Node(tmp_path, capable=True)
    n.env.write_text(RENDERED)
    assert n.run().returncode == 0
    n.install_agent(capable=False)
    p = n.run()
    assert p.returncode == 0, p.stderr
    assert "CHANGED=1" in p.stdout
    for name, value in SECRETS.items():
        assert f"{name}={value}" in n.lines(), name
        assert not any(line.startswith(f"{name}_FILE=") for line in n.lines())
    assert not n.dir.exists(), "the secret files must not outlive the pointers"


def test_the_container_era_backup_loses_its_secret_values(tmp_path: Path) -> None:
    n = Node(tmp_path, capable=True)
    n.env.write_text(RENDERED)
    n.bak.write_text("NODE_ID=host3\nNOO_CLUSTER_SECRET=old-plain\nNATS_PASSWORD=shared\nLOG_LEVEL=info\n")
    assert n.run().returncode == 0
    assert n.bak.read_text() == "NODE_ID=host3\nLOG_LEVEL=info\n"


def test_the_root_side_readers_follow_the_pointer(tmp_path: Path) -> None:
    """The harness fallback in the applier reads NATS_NODE_PASSWORD through
    agent_env_secret; after the flip it must still find the value."""
    n = Node(tmp_path, capable=True)
    n.env.write_text(RENDERED)
    p = n.run(f'agent_env_secret "{n.env}" NATS_NODE_PASSWORD; echo; agent_env_secret "{n.env}" NATS_NODE_USER\n')
    assert p.returncode == 0, p.stderr
    assert p.stdout.splitlines()[-2:] == ["nats-pw", "node-host3"], p.stdout


def test_the_fetch_report_bearer_follows_the_pointer(tmp_path: Path) -> None:
    src = (REPO / "scripts/noo-fetch.sh").read_text()
    m = re.search(r"^node_bearer\(\) \{\n(.*?)^\}", src, re.S | re.M)
    assert m, "node_bearer not found in noo-fetch.sh"
    body = m.group(0).replace("_env=/etc/noo-node-agent.env", f"_env={tmp_path}/env")
    (tmp_path / "s").write_text("cluster-abc")
    (tmp_path / "env").write_text(f"NODE_ID=host3\nNOO_CLUSTER_SECRET_FILE={tmp_path}/s\n")
    p = subprocess.run(["/bin/sh", "-c", f"NODE=host3\n{body}\nnode_bearer"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert p.stdout.startswith("host3:"), p.stdout


@pytest.mark.parametrize("capable", [True, False])
def test_the_block_refuses_to_lose_node_id(tmp_path: Path, capable: bool) -> None:
    n = Node(tmp_path, capable=capable)
    n.env.write_text("NOO_CLUSTER_SECRET=x\n")
    p = n.run()
    if capable:
        assert p.returncode == 70 and "lost NODE_ID" in p.stderr, (p.returncode, p.stderr)
    else:
        assert p.returncode == 0


def test_the_applier_calls_the_block_after_every_merge() -> None:
    """The conversion is the LAST env write of an apply: it must follow the
    agent-env install, both merges, and the agent-binary install it judges."""
    src = APPLIER.read_text()
    call = src.index("agent_secret_files /etc/noo-node-agent.env /etc/noo/agent-secrets /usr/local/bin/noo-node-agent")
    for earlier in ('if [ -f "$WORK/files/agent-env" ]', 'if [ -f "$WORK/files/nats-creds" ]',
                    'if [ -f "$WORK/files/fleet-secrets" ]', 'if [ -f "$WORK/files/agent-binary" ]'):
        assert src.index(earlier) < call, earlier
    assert call < src.index("# ── 4. Orchestrate")


# ── the harness env ───────────────────────────────────────
#
# The same block converts /etc/noo-harness.env, called with the harness's
# own key list and marker (the gateway binary's HARNESS_SECRET_FILES_CAPABILITY)
# and owned by noo-harness under /etc/noo/harness-secrets.

HARNESS_RS = REPO / "gateway-rust/src/harness_main.rs"

# What the harness-env template renders, after the nats-creds merge.
HARNESS_RENDERED = (
    "NODE_ID=host3\n"
    "NOO_GATEWAY_URL=https://noo-controller:8080\n"
    "NATS_URL=tls://noo-controller:4222\n"
    "NOO_TLS_KEY=/etc/noo/pki/nodes/host3/node.key\n"
    "NOO_NODE_AGENT_TOKEN=tok-123\n"
    "NOO_CLUSTER_SECRET=cluster-abc\n"
    "NOO_HARNESS_MODEL=auto\n"
    "NATS_NODE_USER=node-host3\n"
    "NATS_NODE_PASSWORD=nats-pw\n"
)


def harness_capability() -> str:
    m = re.search(r'pub const HARNESS_SECRET_FILES_CAPABILITY: &str = "([^"]+)";', HARNESS_RS.read_text())
    assert m, "HARNESS_SECRET_FILES_CAPABILITY not found in harness_main.rs"
    return m.group(1)


class Harness:
    def __init__(self, tmp: Path) -> None:
        self.env = tmp / "noo-harness.env"
        self.dir = tmp / "harness-secrets"
        self.bin = tmp / "noo-gateway"

    def install(self, marker: bytes) -> None:
        self.bin.write_bytes(b"\x7fELF\x02\x01" + os.urandom(64) + marker + os.urandom(64))

    def run(self) -> subprocess.CompletedProcess:
        script = (
            f"set -eu\n{block()}\n"
            f'agent_secret_files "{self.env}" "{self.dir}" "{self.bin}" "{ME}" "" '
            '"$HARNESS_SECRET_KEYS" "$HARNESS_SECRET_CAPABILITY" || exit $?\n'
            'echo "CHANGED=$ASF_CHANGED"\n'
        )
        return subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True)


def test_a_capable_harness_gets_files_and_its_env_holds_pointers_only(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    h.install(harness_capability().encode())
    h.env.write_text(HARNESS_RENDERED)
    p = h.run()
    assert p.returncode == 0 and "CHANGED=1" in p.stdout, p.stdout + p.stderr
    env = h.env.read_text()
    for name, value in SECRETS.items():
        f = h.dir / name
        assert f.read_text() == value, name
        assert stat.S_IMODE(f.stat().st_mode) == 0o600
        assert f"{name}_FILE={f}\n" in env, env
        assert value not in env, f"{name}'s value is still in the harness env"
    assert "NOO_TLS_KEY=/etc/noo/pki/nodes/host3/node.key" in env and "NATS_NODE_USER=node-host3" in env
    # idempotent
    p = h.run()
    assert p.returncode == 0 and "CHANGED=0" in p.stdout, p.stdout + p.stderr


def test_the_harness_env_is_judged_by_the_harness_marker_not_the_agents(tmp_path: Path) -> None:
    """A gateway binary that happens to carry the AGENT's marker string is
    not a harness that reads files: its env stays plain. And a rollback to a
    harness without the marker inlines the files back and removes them."""
    h = Harness(tmp_path)
    h.install(capability().encode())
    h.env.write_text(HARNESS_RENDERED)
    p = h.run()
    assert p.returncode == 0 and "CHANGED=0" in p.stdout, p.stdout + p.stderr
    assert h.env.read_text() == HARNESS_RENDERED and not h.dir.exists()

    h.install(harness_capability().encode())
    assert h.run().returncode == 0
    h.install(b"noo-gateway-before-1271")
    p = h.run()
    assert p.returncode == 0 and "CHANGED=1" in p.stdout, p.stdout + p.stderr
    for name, value in SECRETS.items():
        assert f"{name}={value}\n" in h.env.read_text(), name
    assert "_FILE=" not in h.env.read_text()
    assert not h.dir.exists()


def test_the_applier_converts_the_harness_env_after_every_harness_write() -> None:
    src = APPLIER.read_text()
    call = src.index("agent_secret_files /etc/noo-harness.env /etc/noo/harness-secrets /usr/local/bin/noo-gateway")
    for earlier in ('if [ -f "$WORK/files/nats-creds" ]', 'if [ -f "$WORK/files/harness-env" ]',
                    'if [ -f "$WORK/files/harness-binary" ]', 'if [ -f "$WORK/files/harness-unit" ]'):
        assert src.index(earlier) < call, earlier
    assert call < src.index("# ── 4. Orchestrate")
    tail = src[call:src.index("# ── 4. Orchestrate")]
    assert '"$HARNESS_SECRET_KEYS" "$HARNESS_SECRET_CAPABILITY"' in tail and "noo-harness" in tail
    assert "need_harness_restart=1" in tail


def test_a_config_refresh_keeps_the_harness_pair_through_its_pointer() -> None:
    """The harness-env block's second fallback (the existing harness env)
    must follow a NATS_NODE_PASSWORD_FILE pointer, or a converted node's
    config refresh would log the harness out."""
    src = APPLIER.read_text()
    blk = src[src.index('if [ -f "$WORK/files/harness-env" ]'):src.index('if [ -f "$WORK/files/harness-binary" ]')]
    assert 'agent_env_secret "$HARNESS_ENV" NATS_NODE_PASSWORD' in blk
    assert "grep -qE '^NATS_NODE_PASSWORD=.+' \"$HARNESS_ENV\"" not in blk
