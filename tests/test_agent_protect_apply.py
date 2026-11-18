# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The root applier holds the node agent's unit to the paths it writes.

scripts/noo-apply.sh renders noo-node-agent.service.d/50-noomesh-protect.conf
(ProtectSystem=strict, PrivateTmp=yes, ProtectHome=read-only, one
ReadWritePaths= per path) from the STAGED agent-env. That env is signed by
signing.key, not by the release, so what is rendered from it must stay
config: fixed directive names, every path validated, one bad value refuses
the whole drop-in and leaves the installed one exactly as it was.

The `agent_protect` block (with `config_unchanged`) is lifted out between its
markers and run unprivileged against a temp dir, with a fake systemctl first
on PATH, the way tests/test_harness_egress_apply.py runs harness_egress. The
call sites are pinned by source guards at the end. One test per rule, so a
mutant can be cut against each.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
APPLY = (REPO / "scripts/noo-apply.sh").read_text()


def _block(name: str) -> str:
    m = re.search(rf"# BEGIN {name}\n(.*?)# END {name}\n", APPLY, re.S)
    assert m, f"{name} is not delimited in noo-apply.sh"
    return m.group(1)


LIB = _block("config_unchanged") + _block("agent_protect")
HEADER = (
    "# Rendered by noo-apply from the agent env: the node agent writes only where it must.\n"
    "[Service]\n"
    "ProtectSystem=strict\n"
    "PrivateTmp=yes\n"
    "ProtectHome=read-only\n"
)
# The fixed state dir is a real host path: bare where this host has it.
STATE = ("" if os.path.exists("/var/lib/noo-node-agent") else "-") + "/var/lib/noo-node-agent"
INJECTION = "ExecStartPre=/bin/sh -c id"


class Node:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.log = tmp / "calls.log"
        self.log.write_text("")
        self.dropin_dir = tmp / "noo-node-agent.service.d"
        self.dropin = self.dropin_dir / "50-noomesh-protect.conf"
        self.envf = tmp / "agent-env"
        self.data = tmp / "data"
        (self.data / "models").mkdir(parents=True)
        (tmp / "state").mkdir()
        (tmp / "extra1").mkdir()
        fake = self.bin / "systemctl"
        fake.write_text('#!/bin/sh\necho "systemctl $*" >> "$CALLS"\nexit 0\n')
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)

    def write_env(self, **kv: str) -> None:
        body = "NODE_ID=n1\n" + "".join(f"{k}={v}\n" for k, v in kv.items())
        self.envf.write_bytes(body.encode())

    def normal_env(self) -> None:
        t = self.tmp
        self.write_env(
            NOO_DATA_ROOT=f"{t}/data",
            MODELS_DIR=f"{t}/data/models",
            HF_CACHE_DIR=f"{t}/data/hf-cache",          # missing: `-`
            OLLAMA_DATA_DIR=f"{t}/data",                # a duplicate: listed once
            NOO_AGENT_STATE=f"{t}/state",
            NOO_HOST_ROOTS=f"{t}/extra1::{t}/extra2",   # empty element skipped; extra2 missing
        )

    def run(self, fn: str = 'agent_protect_apply "$ENVF"', pre: str = "") -> subprocess.CompletedProcess:
        script = (
            "set -eu\n" + LIB + pre +
            'applied=""; need_restart=0\n'
            f"{fn}\n"
            'echo "APPLIED=$applied"; echo "RESTART=$need_restart"\n'
        )
        owner = subprocess.check_output(["sh", "-c", "echo $(id -un):$(id -gn)"], text=True).strip()
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "CALLS": str(self.log), "ENVF": str(self.envf), "TMPDIR": str(self.tmp),
            "AGENT_DROPIN_DIR": str(self.dropin_dir), "AP_OWNER_ARGS": "", "AP_STAT_OWNER": owner,
        }
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines()


@pytest.fixture
def node(tmp_path: Path) -> Node:
    return Node(tmp_path)


def out(r: subprocess.CompletedProcess, key: str) -> str:
    assert r.returncode == 0, (r.stdout, r.stderr)
    return re.search(rf"^{key}=(.*)$", r.stdout, re.M).group(1)


def rw_paths(node: Node) -> list[str]:
    return [l.split("=", 1)[1] for l in node.dropin.read_text().splitlines() if l.startswith("ReadWritePaths=")]


def installed(node: Node) -> bytes:
    """A good drop-in, installed; the call log cleared after it."""
    node.normal_env()
    r = node.run()
    assert out(r, "RESTART") == "1"
    node.log.write_text("")
    return node.dropin.read_bytes()


def assert_refused(node: Node, before: bytes | None, key: str) -> None:
    r = node.run()
    assert out(r, "RESTART") == "0"
    assert f"agent-protect=REFUSED:{key}" in out(r, "APPLIED")
    lines = r.stderr.splitlines()
    assert len(lines) == 1 and key in lines[0], r.stderr
    assert INJECTION not in r.stderr and "%h" not in r.stderr
    assert node.calls() == []
    if before is None:
        assert not node.dropin.exists()
    else:
        assert node.dropin.read_bytes() == before


# ── the rendered file, exactly ──────────────────────────────────────────────

def test_a_normal_agent_env_renders_the_golden_drop_in(node: Node) -> None:
    node.normal_env()
    r = node.run()
    t = node.tmp
    assert node.dropin.read_text() == HEADER + (
        f"ReadWritePaths={STATE}\n"
        f"ReadWritePaths={t}/state\n"
        f"ReadWritePaths={t}/data\n"
        f"ReadWritePaths={t}/data/models\n"
        f"ReadWritePaths=-{t}/data/hf-cache\n"
        f"ReadWritePaths={t}/extra1\n"
        f"ReadWritePaths=-{t}/extra2\n"
        "ReadWritePaths=-/var/lib/docker/containers\n"
    )
    assert stat.S_IMODE(node.dropin.stat().st_mode) == 0o644
    assert node.calls() == ["systemctl daemon-reload"]
    assert out(r, "RESTART") == "1" and out(r, "APPLIED").split() == ["agent-protect"]


def test_unchanged_on_a_second_apply_no_rewrite_no_reload_no_restart(node: Node) -> None:
    before = installed(node)
    st = node.dropin.stat()
    r = node.run()
    assert out(r, "RESTART") == "0" and out(r, "APPLIED") == ""
    assert node.calls() == []
    assert node.dropin.read_bytes() == before
    st2 = node.dropin.stat()
    assert (st2.st_ino, st2.st_mtime_ns) == (st.st_ino, st.st_mtime_ns)


def test_paths_are_deduplicated_in_a_fixed_order_whatever_the_env_order(node: Node) -> None:
    before = installed(node)
    lines = node.envf.read_text().splitlines()
    node.envf.write_text("\n".join(reversed(lines)) + "\n")
    r = node.run()
    assert node.dropin.read_bytes() == before and out(r, "RESTART") == "0"
    paths = [p.lstrip("-") for p in rw_paths(node)]
    assert len(paths) == len(set(paths))


# ── rule 2: shape ───────────────────────────────────────────────────────────

def test_a_newline_injection_in_the_data_root_refuses_the_whole_drop_in(node: Node) -> None:
    before = installed(node)
    # The reader is a seam: hand the block a value carrying a real newline.
    pre = (
        'ap_env_value() { if [ "$2" = NOO_DATA_ROOT ]; then '
        f"printf '%s\\n{INJECTION}' \"$INJ_BASE\"; "
        'else grep -E "^$2=" "$1" | tail -1 | cut -d= -f2- || true; fi; }\n'
        f'INJ_BASE="{node.tmp}/data"\n'
    )
    r = node.run(pre=pre)
    assert out(r, "RESTART") == "0"
    lines = r.stderr.splitlines()
    assert len(lines) == 1 and "NOO_DATA_ROOT" in lines[0] and INJECTION not in r.stderr
    assert node.calls() == [] and node.dropin.read_bytes() == before
    assert b"ExecStartPre" not in node.dropin.read_bytes()


def test_a_carriage_return_injection_in_the_env_file_is_refused(node: Node) -> None:
    # systemd ends a line at a lone CR; grep does not.
    before = installed(node)
    node.write_env(NOO_DATA_ROOT=f"{node.tmp}/data\r{INJECTION}")
    assert_refused(node, before, "NOO_DATA_ROOT")


def test_a_systemd_specifier_is_refused(node: Node) -> None:
    before = installed(node)
    node.write_env(MODELS_DIR="%h/models")
    assert_refused(node, before, "MODELS_DIR")


def test_a_quote_is_refused(node: Node) -> None:
    before = installed(node)
    node.write_env(HF_CACHE_DIR=f'"{node.tmp}/data"')
    assert_refused(node, before, "HF_CACHE_DIR")


def test_a_dotdot_component_is_refused(node: Node) -> None:
    before = installed(node)
    node.write_env(NOO_DATA_ROOT=f"{node.tmp}/data/../../etc")
    assert_refused(node, before, "NOO_DATA_ROOT")


def test_a_relative_path_is_refused(node: Node) -> None:
    before = installed(node)
    node.write_env(OLLAMA_DATA_DIR="data/ollama")
    assert_refused(node, before, "OLLAMA_DATA_DIR")


def test_a_refusal_with_nothing_installed_installs_nothing(node: Node) -> None:
    node.write_env(NOO_DATA_ROOT="/srv/noo data")
    assert_refused(node, None, "NOO_DATA_ROOT")


# ── rule 3: the deny list ───────────────────────────────────────────────────

def test_a_data_root_of_slash_is_refused(node: Node) -> None:
    before = installed(node)
    node.write_env(NOO_DATA_ROOT="/")
    assert_refused(node, before, "NOO_DATA_ROOT")


def test_a_symlink_that_resolves_to_slash_is_refused(node: Node) -> None:
    # The literal path passes the shape rule; only the resolved check sees `/`.
    before = installed(node)
    (node.tmp / "rootlink").symlink_to("/")
    node.write_env(NOO_DATA_ROOT=f"{node.tmp}/rootlink")
    assert_refused(node, before, "NOO_DATA_ROOT")


def test_etc_is_refused(node: Node) -> None:
    before = installed(node)
    node.write_env(NOO_DATA_ROOT="/etc")
    assert_refused(node, before, "NOO_DATA_ROOT")


def test_below_etc_is_refused(node: Node) -> None:
    before = installed(node)
    node.write_env(NOO_DATA_ROOT="/etc/systemd/system")
    assert_refused(node, before, "NOO_DATA_ROOT")


@pytest.mark.parametrize("value", ["/var", "/var/lib"])
def test_a_prefix_of_a_denied_path_is_refused(node: Node, value: str) -> None:
    before = installed(node)
    node.write_env(MODELS_DIR=value)
    assert_refused(node, before, "MODELS_DIR")


def test_var_lib_docker_is_refused(node: Node) -> None:
    before = installed(node)
    node.write_env(NOO_DATA_ROOT="/var/lib/docker")
    assert_refused(node, before, "NOO_DATA_ROOT")


def test_var_lib_docker_containers_is_allowed_and_listed_once(node: Node) -> None:
    node.write_env(NOO_DATA_ROOT="/var/lib/docker/containers")
    r = node.run()
    assert out(r, "RESTART") == "1"
    assert rw_paths(node) == [STATE, "-/var/lib/docker/containers"]


def test_a_symlink_that_resolves_into_a_denied_path_is_refused(node: Node) -> None:
    before = installed(node)
    (node.tmp / "sneaky").symlink_to("/etc")
    node.write_env(NOO_DATA_ROOT=f"{node.tmp}/sneaky")
    assert_refused(node, before, "NOO_DATA_ROOT")


# ── rule 4: NOO_HOST_ROOTS ──────────────────────────────────────────────────

def test_host_roots_over_the_cap_are_refused(node: Node) -> None:
    before = installed(node)
    node.write_env(NOO_HOST_ROOTS=":".join(f"{node.tmp}/h{i}" for i in range(17)))
    assert_refused(node, before, "NOO_HOST_ROOTS")


def test_host_roots_at_the_cap_are_listed(node: Node) -> None:
    roots = [f"{node.tmp}/h{i}" for i in range(16)]
    node.write_env(NOO_HOST_ROOTS=":".join(roots))
    out(node.run(), "RESTART")
    assert rw_paths(node)[1:-1] == ["-" + p for p in roots]


def test_one_bad_host_root_element_refuses_the_drop_in(node: Node) -> None:
    before = installed(node)
    node.write_env(NOO_HOST_ROOTS=f"{node.tmp}/extra1:/etc")
    assert_refused(node, before, "NOO_HOST_ROOTS")


# ── rule 5: a data root under /home ─────────────────────────────────────────

def test_an_existing_data_root_under_home_is_listed_bare(node: Node) -> None:
    home = Path.home().resolve()
    if not str(home).startswith("/home/") or not home.is_dir():
        pytest.skip("this runner's home is not an existing directory below /home")
    node.write_env(NOO_DATA_ROOT=str(home))
    out(node.run(), "RESTART")
    assert str(home) in rw_paths(node) and f"-{home}" not in rw_paths(node)


def test_home_itself_is_refused(node: Node) -> None:
    before = installed(node)
    node.write_env(NOO_DATA_ROOT="/home")
    assert_refused(node, before, "NOO_DATA_ROOT")


# ── teardown ────────────────────────────────────────────────────────────────

def test_teardown_removes_the_drop_in_and_reloads(node: Node) -> None:
    installed(node)
    r = node.run(fn="agent_protect_remove")
    assert r.returncode == 0, r.stderr
    assert not node.dropin.exists() and not node.dropin_dir.exists()
    assert node.calls() == ["systemctl daemon-reload"]


# ── source guards: the call sites ───────────────────────────────────────────

def test_the_render_rides_the_agent_env_block_and_its_one_restart() -> None:
    call = 'agent_protect_apply "$WORK/files/agent-env"\n'
    assert APPLY.count(call) == 1
    i = APPLY.index(call)
    assert APPLY.index("    hf_hub_reown \"$(grep -E '^NOO_DATA_ROOT='") < i
    assert i < APPLY.index('if [ -f "$WORK/files/nats-creds" ]; then')
    # Inside the agent-env block, not after it.
    block_start = APPLY.rindex('if [ -f "$WORK/files/agent-env" ]; then', 0, i)
    assert "\nfi\n" not in APPLY[block_start:i]
    body = _block("agent_protect")
    assert "need_restart=1" in body
    assert "systemctl restart" not in body and "systemctl daemon-reload" in body


def test_teardown_calls_the_removal_before_it_hands_off() -> None:
    i = APPLY.index("    agent_protect_remove\n    harness_egress_remove\n")
    assert i < APPLY.index('echo "applied: teardown')


def test_the_directive_names_are_fixed_in_the_template() -> None:
    body = _block("agent_protect")
    render = body[body.index("ap_render() {"):]
    render = render[:render.index("\n}\n")]
    assert re.findall(r"\b([A-Z][a-z][A-Za-z]+)=", render) == [
        "ProtectSystem", "PrivateTmp", "ProtectHome", "ReadWritePaths", "ReadWritePaths"]


# ── the real kernel-side proof (root + systemd only) ────────────────────────

@pytest.mark.skipif(os.geteuid() != 0 or shutil.which("systemd-run") is None,
                    reason="needs root and systemd-run: the EROFS proof runs on a systemd host only")
def test_protect_system_strict_really_blocks_etc_and_allows_the_listed_dir(tmp_path: Path) -> None:
    probe = Path("/etc/noo-protect-probe")
    assert not probe.exists()
    r = subprocess.run(
        ["systemd-run", "--wait", "--pipe", "--quiet", "--collect",
         "-p", "ProtectSystem=strict", "-p", f"ReadWritePaths={tmp_path}",
         "sh", "-c", f"touch {tmp_path}/ok && ! touch {probe}"],
        capture_output=True, text=True, timeout=60)
    try:
        assert r.returncode == 0, (r.stdout, r.stderr)
        assert (tmp_path / "ok").exists()
        assert not probe.exists()
    finally:
        if probe.exists():
            probe.unlink()


# The CHARACTER rule on its own: each value below is absolute, normalised and
# not denied, so only the allowed-character class can refuse it (the two
# tests above are also refused by the absolute-path rule, which masks it).
@pytest.mark.parametrize("bad", ["/data/%h", '/data/da"ta', "/data/a b", "/data/a\\b", "/data/a$b", "/data/a;b"])
def test_a_bad_character_inside_an_absolute_path_is_refused(node: Node, bad: str) -> None:
    before = installed(node)
    node.write_env(MODELS_DIR=f"{node.tmp}{bad}")
    assert_refused(node, before, "MODELS_DIR")
