# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The root applier installs noo-netns-restore.service (i907 step 1b).

The controller used to write the unit with `sudo tee` on every roll that
found it missing or stale (the rehearsal's B-nosudo `netns` row). Now the
controller's self-node applier renders it from a template in
scripts/noo-apply.sh (release-listed as `applier`, i908) and the `netns-unit`
kind carries only `user=` and `root=`, which signing.key alone vouches for.
So every value is judged, a bad one refuses the kind with one line and leaves
the installed unit exactly as it was, and the unit never runs as root.

The `netns_unit` block (with `config_unchanged`) is lifted out between its
markers and run unprivileged against a temp dir, with a fake systemctl and a
fake `id` first on PATH, the way tests/test_agent_protect_apply.py runs
agent_protect. Source guards at the end pin the call sites and the CLI side.
One test per rule, so a mutant can be cut against each.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
APPLY = (REPO / "scripts/noo-apply.sh").read_text()
NETNS_RS = (REPO / "noo-cli/src/netns_unit.rs").read_text()
UPGRADE_RS = (REPO / "noo-cli/src/commands/upgrade.rs").read_text()


def _block(name: str) -> str:
    m = re.search(rf"# BEGIN {name}\n(.*?)# END {name}\n", APPLY, re.S)
    assert m, f"{name} is not delimited in noo-apply.sh"
    return m.group(1)


LIB = _block("config_unchanged") + _block("netns_unit")
INJECTION = "ExecStartPre=/bin/sh -c id"
# The account the tests install for. Real files carry the real uid; a root
# test runner hands them to an unprivileged uid first (uid 0 is refused).
UID = os.getuid() or 4242


def expected_unit(user: str, root: str) -> str:
    return (
        "[Unit]\n"
        "Description=noomesh: start the containers that join another's network after dockerd starts\n"
        "After=docker.service\n"
        "PartOf=docker.service\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        f"User={user}\n"
        f'ExecStart=/bin/bash "{root}/scripts/noo-netns-restore.sh"\n'
        "\n"
        "[Install]\n"
        "WantedBy=docker.service\n"
    )


class Node:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.log = tmp / "calls.log"
        self.log.write_text("")
        self.units = tmp / "units"
        self.units.mkdir()
        self.unit = self.units / "noo-netns-restore.service"
        self.enabled = tmp / "enabled"
        (tmp / "systemd").mkdir()  # this host "runs systemd" unless a test says otherwise
        self.install = tmp / "home" / "alex" / ".noo"
        (self.install / "scripts").mkdir(parents=True)
        self.script = self.install / "scripts" / "noo-netns-restore.sh"
        self.script.write_text("#!/usr/bin/env bash\nexit 0\n")
        if os.getuid() == 0:
            for p in (self.install, self.install / "scripts", self.script):
                os.chown(p, UID, UID)
        self.payload = tmp / "netns-unit"
        self._exe("systemctl",
                  '#!/bin/sh\necho "systemctl $*" >> "$CALLS"\n'
                  'case "$1" in\n'
                  '  is-enabled) [ -e "$ENABLED" ] && exit 0; exit 1 ;;\n'
                  '  enable) [ -n "${ENABLE_FAILS:-}" ] && exit 1; touch "$ENABLED" ;;\n'
                  '  disable) rm -f "$ENABLED" ;;\n'
                  'esac\nexit 0\n')
        # id -u NAME: alex is the install owner; toor is a second uid 0.
        self._exe("id",
                  '#!/bin/sh\n[ "$1" = -u ] || exit 2\n'
                  f'case "$2" in alex) echo {UID} ;; toor|root) echo 0 ;; *) exit 1 ;; esac\n')

    def _exe(self, name: str, body: str) -> None:
        f = self.bin / name
        f.write_text(body)
        f.chmod(f.stat().st_mode | stat.S_IXUSR)

    def good(self) -> str:
        return f"user=alex\nroot={self.install}\n"

    def write(self, body: str) -> None:
        self.payload.write_bytes(body.encode())

    def run(self, fn: str = 'netns_unit_apply "$PAYLOAD"', **extra: str) -> subprocess.CompletedProcess:
        script = "set -eu\n" + LIB + 'applied=""\n' + f"{fn}\n" + 'echo "APPLIED=$applied"\n'
        owner = subprocess.check_output(["sh", "-c", "echo $(id -un):$(id -gn)"], text=True).strip()
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "CALLS": str(self.log), "ENABLED": str(self.enabled), "PAYLOAD": str(self.payload),
            "TMPDIR": str(self.tmp), "NETNS_UNIT_DIR": str(self.units), "NU_OWNER_ARGS": "",
            "NU_STAT_OWNER": owner, "NU_SYSTEMD_DIR": str(self.tmp / "systemd"),
        }
        env.update(extra)
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines()


@pytest.fixture
def node(tmp_path: Path) -> Node:
    return Node(tmp_path)


def applied(r: subprocess.CompletedProcess) -> str:
    assert r.returncode == 0, (r.stdout, r.stderr)
    return re.search(r"^APPLIED=(.*)$", r.stdout, re.M).group(1).strip()


def installed(node: Node) -> bytes:
    """A good unit, installed and enabled; the call log cleared after it."""
    node.write(node.good())
    assert applied(node.run()) == "netns-unit"
    node.log.write_text("")
    return node.unit.read_bytes()


def assert_refused(node: Node, before: bytes | None, field: str) -> None:
    r = node.run()
    assert applied(r) == f"netns-unit=REFUSED:{field}"
    lines = r.stderr.splitlines()
    assert len(lines) == 1 and field in lines[0] and "left as it was" in lines[0], r.stderr
    assert INJECTION not in r.stderr
    if before is None:
        assert not node.unit.exists()
    else:
        assert node.unit.read_bytes() == before
    assert not [c for c in node.calls() if not c.startswith("systemctl is-enabled")], node.calls()


# ── render + install ──────────────────────────────────────────────────────

def test_renders_the_exact_unit_installs_reloads_and_enables(node: Node) -> None:
    node.write(node.good())
    r = node.run()
    assert applied(r) == "netns-unit"
    assert node.unit.read_text() == expected_unit("alex", str(node.install))
    assert stat.S_IMODE(node.unit.stat().st_mode) == 0o644
    assert "systemctl daemon-reload" in node.calls()
    assert "systemctl enable noo-netns-restore.service" in node.calls()
    assert node.calls().index("systemctl daemon-reload") < node.calls().index("systemctl enable noo-netns-restore.service")


def test_a_second_apply_is_unchanged_and_runs_nothing(node: Node) -> None:
    before = installed(node)
    r = node.run()
    assert applied(r) == "netns-unit=unchanged"
    assert node.unit.read_bytes() == before
    assert node.calls() == ["systemctl is-enabled --quiet noo-netns-restore.service"]


def test_a_stale_unit_is_replaced(node: Node) -> None:
    installed(node)
    node.unit.write_text("[Unit]\nold\n")
    assert applied(node.run()) == "netns-unit"
    assert node.unit.read_text() == expected_unit("alex", str(node.install))
    assert "systemctl daemon-reload" in node.calls()


def test_a_current_but_disabled_unit_is_enabled_without_a_rewrite(node: Node) -> None:
    installed(node)
    node.enabled.unlink()
    assert applied(node.run()) == "netns-unit"
    assert "systemctl daemon-reload" not in node.calls()
    assert "systemctl enable noo-netns-restore.service" in node.calls()


def test_a_failed_enable_is_said(node: Node) -> None:
    node.write(node.good())
    r = node.run(ENABLE_FAILS="1")
    assert applied(r) == "netns-unit=NOT-ENABLED"
    assert "enable failed" in r.stderr


def test_no_systemd_installs_nothing(node: Node) -> None:
    (node.tmp / "systemd").rmdir()
    node.write(node.good())
    assert applied(node.run()) == "netns-unit=no-systemd"
    assert not node.unit.exists() and node.calls() == []


# ── refusals: the installed unit stays exactly as it was ──────────────────

def test_root_is_refused(node: Node) -> None:
    before = installed(node)
    node.write(f"user=root\nroot={node.install}\n")
    assert_refused(node, before, "user")


def test_another_uid_zero_is_refused(node: Node) -> None:
    before = installed(node)
    node.write(f"user=toor\nroot={node.install}\n")
    assert_refused(node, before, "user")


def test_an_unknown_account_is_refused(node: Node) -> None:
    node.write(f"user=nobody-here\nroot={node.install}\n")
    assert_refused(node, None, "user")


@pytest.mark.parametrize("user", ["", "-alex", ".alex", "al ex", "al%ex", 'al"ex', "a" * 33])
def test_a_badly_shaped_user_is_refused(node: Node, user: str) -> None:
    before = installed(node)
    node.write(f"user={user}\nroot={node.install}\n")
    assert_refused(node, before, "user")


@pytest.mark.parametrize("root", ["relative/.noo", "/a//b", "/a/./b", "/a/../b", "/a/b/", "/a/b%h", '/a/"b', "/a/b\\c", "/a b"])
def test_a_badly_shaped_root_is_refused(node: Node, root: str) -> None:
    before = installed(node)
    node.write(f"user=alex\nroot={root}\n")
    assert_refused(node, before, "root")


@pytest.mark.parametrize("name", ["in%h", 'in"q', "in\\b", "in b", "in\tt"])
def test_a_root_outside_the_charset_is_refused_even_when_it_is_a_real_install(node: Node, name: str) -> None:
    """The charset rule alone: the directory exists and the user owns it and
    its script, so only the shape can refuse a systemd specifier or a quote."""
    before = installed(node)
    odd = node.tmp / name
    (odd / "scripts").mkdir(parents=True)
    (odd / "scripts" / "noo-netns-restore.sh").write_text("#!/bin/sh\n")
    if os.getuid() == 0:
        for p in (odd, odd / "scripts", odd / "scripts" / "noo-netns-restore.sh"):
            os.chown(p, UID, UID)
    node.write(f"user=alex\nroot={odd}\n")
    assert_refused(node, before, "root")


@pytest.mark.parametrize("user", ["-alex", ".alex", "al%ex", 'al"ex', "al\\ex", "a" * 33])
def test_a_user_the_host_knows_is_still_held_to_its_shape(node: Node, user: str) -> None:
    """The shape rule alone: this host's `id` answers for any name."""
    before = installed(node)
    node._exe("id", f'#!/bin/sh\n[ "$1" = -u ] || exit 2\necho {UID}\n')
    node.write(f"user={user}\nroot={node.install}\n")
    assert_refused(node, before, "user")


def test_a_root_the_user_does_not_own_is_refused(node: Node) -> None:
    before = installed(node)
    other = node.tmp / "elsewhere"
    (other / "scripts").mkdir(parents=True)
    (other / "scripts" / "noo-netns-restore.sh").write_text("#!/bin/sh\n")
    if os.getuid() == 0:
        os.chown(other / "scripts" / "noo-netns-restore.sh", UID, UID)
    else:
        # The fake id hands alex another uid than the one owning the files.
        node._exe("id", '#!/bin/sh\ncase "$2" in alex) echo 4243 ;; *) exit 1 ;; esac\n')
    node.write(f"user=alex\nroot={other}\n")
    assert_refused(node, before, "root-owner")


def test_a_missing_script_is_refused(node: Node) -> None:
    before = installed(node)
    node.script.unlink()
    assert_refused(node, before, "script")


def test_a_linked_script_is_refused(node: Node) -> None:
    before = installed(node)
    node.script.unlink()
    node.script.symlink_to("/bin/true")
    assert_refused(node, before, "script")


def test_a_linked_root_is_refused(node: Node) -> None:
    before = installed(node)
    link = node.tmp / "link"
    link.symlink_to(node.install)
    node.write(f"user=alex\nroot={link}\n")
    assert_refused(node, before, "root")


@pytest.mark.parametrize("body", [
    "user=alex\n",                      # root missing
    "root=/x\n",                        # user missing
    "user=alex\nuser=alex\nroot=/x\n",  # a key twice
    "",                                 # nothing
])
def test_the_payload_is_exactly_two_keys(node: Node, body: str) -> None:
    before = installed(node)
    node.write(body.replace("/x", str(node.install)))
    assert_refused(node, before, "shape")


@pytest.mark.parametrize("body", [
    "user=alex\n" + INJECTION + "\nroot={root}\n",
    "user=alex\nroot={root}\n" + INJECTION + "\n",
    "user=alex\nroot={root}\n[Service]\n" + INJECTION + "\n",
])
def test_an_injected_directive_is_refused(node: Node, body: str) -> None:
    before = installed(node)
    node.write(body.format(root=node.install))
    assert_refused(node, before, "shape")
    assert INJECTION not in node.unit.read_text()


# ── teardown ──────────────────────────────────────────────────────────────

def test_teardown_removes_it(node: Node) -> None:
    installed(node)
    r = node.run("netns_unit_remove")
    assert r.returncode == 0, r.stderr
    assert not node.unit.exists()
    assert node.calls() == ["systemctl disable noo-netns-restore.service", "systemctl daemon-reload"]


def test_teardown_without_the_unit_runs_nothing(node: Node) -> None:
    r = node.run("netns_unit_remove")
    assert r.returncode == 0 and node.calls() == []


# ── parity + source guards ────────────────────────────────────────────────

def _rust_render_template() -> str:
    """netns_unit.rs `render`'s format string, as text."""
    m = re.search(r'pub\(crate\) fn render\(.*?Ok\(format!\(\n(.*?)\n\s*\)\)', NETNS_RS, re.S)
    assert m, "netns_unit::render is not where this guard reads it"
    out = []
    for line in m.group(1).splitlines():
        line = line.strip()
        line = line[1:] if line.startswith('"') else line
        line = re.sub(r'\\n(\\|")$', "", line)
        out.append(line.replace('\\"', '"'))
    return "\n".join(out) + "\n"


def test_the_applier_renders_what_the_cli_compares_against() -> None:
    """The CLI decides "current" from netns_unit::render; the applier writes
    the unit. One byte apart and every roll would re-stage it."""
    rust = _rust_render_template().replace("{owner}", "alex").replace("{install_root}", "/home/alex/.noo")
    assert rust == expected_unit("alex", "/home/alex/.noo"), rust


def test_the_kind_is_known_text_and_parameters_only() -> None:
    known = re.search(r'^KNOWN_KINDS="([^"]*)"', APPLY, re.M).group(1).split()
    text = re.search(r'^TEXT_KINDS="([^"]*)"', APPLY, re.M).group(1).split()
    listed = re.search(r'^RELEASE_LISTED_KINDS="([^"]*)"', APPLY, re.M).group(1).split()
    assert "netns-unit" in known and "netns-unit" in text
    # i908: parameters, not root code, so no release row.
    assert "netns-unit" not in listed
    sign = (REPO / "scripts/sign-bundle.sh").read_text()
    assert "netns-unit" in re.search(r'^KNOWN="([^"]*)"', sign, re.M).group(1).split()


def test_the_apply_and_the_teardown_call_the_block() -> None:
    assert 'if [ -f "$WORK/files/netns-unit" ]; then\n    netns_unit_apply "$WORK/files/netns-unit"\nfi' in APPLY
    td = APPLY[APPLY.index('if [ -f "$WORK/files/teardown" ]; then'):]
    td = td[:td.index("dismantling in 5s")]
    assert "    netns_unit_remove\n" in td


def _fn_body(code: str, marker: str) -> str:
    """test_src::fn_body, for the guard below: from MARKER to its matching
    brace, skipping strings, char literals and comments."""
    start = code.index(marker)
    i, depth, opened = start, 0, False
    while i < len(code):
        c = code[i]
        if code.startswith("//", i):
            i = code.index("\n", i)
            continue
        if c == '"':
            i += 1
            while code[i] != '"':
                i += 2 if code[i] == "\\" else 1
        elif c == "'" and re.match(r"'(\\.|[^\\'])'", code[i:i + 4]):
            i = code.index("'", i + 2)
        elif c == "{":
            depth, opened = depth + 1, True
        elif c == "}":
            depth -= 1
            if opened and depth == 0:
                return code[start:i + 1]
        i += 1
    raise AssertionError(f"{marker} never closes")


def test_the_roll_sudos_for_the_unit_only_where_there_is_no_applier() -> None:
    """i907 step 1b: no `sudo tee /etc/systemd/system/noo-netns-restore.service`
    from the roll on a controller with a self-node applier. The roll reaches
    netns_unit::install (sudo_write_root_file's `sudo tee`) only from its
    no-applier arm, and nothing else in noo-cli does besides onboard."""
    body = _fn_body(UPGRADE_RS, "fn reconcile_netns_unit(")
    assert "sudo_write_root_file" not in body and "sudo_cmd" not in body, body
    assert body.count("nu::install(") == 1, body
    stage = body.index("nu::Route::Stage =>")
    old = body.index("nu::Route::OldApplier(")
    sudo = body.index("nu::Route::Sudo =>")
    stated = body.index("nu::Route::Stated(")
    assert stage < old < sudo < body.index("nu::install(") < stated, body
    assert "nu::stage_to_self_node(" in body[stage:old]
    callers = {}
    for f in (REPO / "noo-cli/src").rglob("*.rs"):
        n = len(re.findall(r"\b(?:nu|netns_unit)::install\(", f.read_text()))
        if n:
            callers[str(f.relative_to(REPO / "noo-cli/src"))] = n
    assert callers == {"commands/upgrade.rs": 1, "onboard/steps.rs": 1}, callers
