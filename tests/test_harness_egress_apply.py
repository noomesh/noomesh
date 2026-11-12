# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Enforcement step 1: the applier holds the noo-harness unit off the internet.

scripts/noo-apply.sh renders /etc/noo/harness-net/{resolv.conf,hosts,
nsswitch.conf} and the unit's 50-noomesh-egress.conf drop-in, probes whether
this systemd enforces IPAddressDeny, and tags the `applied:` line. Its
`harness_egress` block (with `config_unchanged`) is lifted out between its
markers and run unprivileged against a temp root, with fake systemctl,
systemd-run, getent, ip and hostname first on PATH. The real applier's own
verify-only run (test_apply_full_harness.py) exits before any write, so the
block is the unit under test; the call sites are pinned by source guards at
the end.
"""

from __future__ import annotations

import re
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


LIB = _block("config_unchanged") + _block("harness_egress")
ENV = "NODE_ID=host3\nNOO_GATEWAY_URL=https://ctl.example.net:8000\nNATS_URL=tls://nats.example.net:4222\n"
NSS = "passwd: files systemd\ngroup: files systemd\nhosts: files mdns4_minimal dns\n"
PROBE_EPERM = "bash: connect: Operation not permitted\nbash: /dev/tcp/192.0.2.1/9: Operation not permitted\n"


class Node:
    """One node's root in a temp dir, and the fakes the block calls."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.root = tmp / "root"
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.root.mkdir()
        self.log = tmp / "calls.log"
        self.log.write_text("")
        self.env = self.root / "noo-harness.env"
        self.env.write_text(ENV)
        self.unit = self.root / "noo-harness.service"
        self.unit.write_text("[Service]\n")
        self.nss = self.root / "nsswitch.conf"
        self.nss.write_text(NSS)
        self.net = self.root / "harness-net"
        self.dropin_dir = self.root / "noo-harness.service.d"
        self.dropin = self.dropin_dir / "50-noomesh-egress.conf"
        self.hosts_db = tmp / "getent.db"      # "name addr" lines; absent name = unresolvable
        self.hosts_db.write_text("ctl.example.net 203.0.113.9\nnats.example.net 100.64.1.2\n")
        self.ip_out = tmp / "ip.out"
        self.ip_out.write_text("")
        self.probe_out = tmp / "probe.out"
        self.probe_out.write_text(PROBE_EPERM)
        self.probe_rc = tmp / "probe.rc"
        self.probe_rc.write_text("1")
        # The system tools, minus systemd-run: a host's own must not answer for the fake.
        self.tools = tmp / "tools"
        self.tools.mkdir()
        for t in Path("/usr/bin").iterdir():
            if t.name != "systemd-run":
                (self.tools / t.name).symlink_to(t)
        self.set_nss(True)
        self._fake("systemctl", 'echo "systemctl $*" >> "$CALLS"\nexit 0')
        self._fake("hostname", "echo host3")
        self._fake("getent", '[ "$1" = ahosts ] || exit 2\n'
                             'awk -v n="$2" \'$1 == n {print $2, "STREAM", n; print $2, "DGRAM"; print $2, "RAW"}\' "$GETENT_DB" | grep . || exit 2')
        # A clock that moves on every call: the hosts header's stamp must never count as a change.
        self._fake("date", 'n=$(cat "$CLOCK" 2>/dev/null || echo 0); echo $((n + 1)) > "$CLOCK"; printf "2026-11-12T10:00:%02dZ\\n" "$n"')
        self._fake("ip", 'cat "$IP_OUT"')
        self._fake("systemd-run", 'echo "systemd-run $*" >> "$CALLS"\ncat "$PROBE_OUT"\nexit "$(cat "$PROBE_RC")"')

    def _fake(self, name: str, body: str) -> None:
        p = self.bin / name
        p.write_text("#!/bin/sh\n" + body + "\n")
        p.chmod(p.stat().st_mode | stat.S_IXUSR)

    def set_nss(self, present: bool) -> None:
        if not present and self.nss.exists():
            self.nss.unlink()
        elif present:
            self.nss.write_text(NSS)

    def drop_systemd_run(self) -> None:
        (self.bin / "systemd-run").unlink()

    def run(self, fn: str = "harness_egress_apply") -> subprocess.CompletedProcess:
        script = (
            "set -eu\n" + LIB +
            'applied=""; need_harness_restart=0\n'
            f"{fn}\n"
            'echo "APPLIED=$applied"; echo "RESTART=$need_harness_restart"\n'
        )
        owner = subprocess.check_output(["sh", "-c", "echo $(id -un):$(id -gn)"], text=True).strip()
        env = {
            "PATH": f"{self.bin}:{self.tools}",
            "CALLS": str(self.log), "CLOCK": str(self.tmp / "clock"), "GETENT_DB": str(self.hosts_db), "IP_OUT": str(self.ip_out),
            "PROBE_OUT": str(self.probe_out), "PROBE_RC": str(self.probe_rc),
            "HE_NET_DIR": str(self.net), "HE_DROPIN_DIR": str(self.dropin_dir), "HE_UNIT": str(self.unit),
            "HE_ENV": str(self.env), "HE_NSSWITCH_SRC": str(self.nss),
            "HE_OWNER_ARGS": "", "HE_STAT_OWNER": owner,
        }
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines()


@pytest.fixture
def node(tmp_path: Path) -> Node:
    return Node(tmp_path)


def applied_of(r: subprocess.CompletedProcess) -> str:
    assert r.returncode == 0, (r.stdout, r.stderr)
    return re.search(r"^APPLIED=(.*)$", r.stdout, re.M).group(1)


def allow_line(node: Node) -> str:
    return re.search(r"^IPAddressAllow=(.*)$", node.dropin.read_text(), re.M).group(1)


BASE_ALLOW = sorted("localhost 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 fe80::/10 100.64.0.0/10 fd7a:115c:a1e0::/48".split())


# ── the rendered files, exactly ─────────────────────────────────────────────

def test_the_drop_in_is_exactly_the_contract(node: Node) -> None:
    node.hosts_db.write_text("ctl.example.net 203.0.113.9\nnats.example.net 100.64.1.2\n")
    applied_of(node.run())
    assert node.dropin.read_text() == (
        "# Rendered by noo-apply: the harness and every CLI it launches reach only local and tailnet\n"
        "# addresses and cannot resolve internet names (docs/security/telemetry.md).\n"
        "[Service]\n"
        "IPAddressDeny=any\n"
        f"IPAddressAllow={' '.join(sorted(BASE_ALLOW + ['203.0.113.9/32']))}\n"
        f"BindReadOnlyPaths={node.net}/resolv.conf:/etc/resolv.conf\n"
        f"BindReadOnlyPaths={node.net}/hosts:/etc/hosts\n"
        f"BindReadOnlyPaths={node.net}/nsswitch.conf:/etc/nsswitch.conf\n"
        "InaccessiblePaths=-/run/systemd/resolve -/run/nscd -/var/run/nscd "
        "-/run/dbus/system_bus_socket -/var/run/dbus/system_bus_socket\n"
        "RuntimeDirectory=noo-harness\n"
        "RuntimeDirectoryMode=0755\n"
    )


def test_resolv_conf_names_the_unreachable_test_net_address_and_nothing_else(node: Node) -> None:
    applied_of(node.run())
    lines = (node.net / "resolv.conf").read_text().splitlines()
    assert lines[0].startswith("# Rendered by noo-apply")
    assert lines[1:] == ["nameserver 192.0.2.53", "options timeout:1 attempts:1"]
    assert "127." not in (node.net / "resolv.conf").read_text()


def test_nsswitch_keeps_every_line_and_swaps_only_hosts(node: Node) -> None:
    applied_of(node.run())
    assert (node.net / "nsswitch.conf").read_text() == (
        "passwd: files systemd\ngroup: files systemd\nhosts: files dns\n")


def test_without_a_host_nsswitch_the_minimal_one_is_written(node: Node) -> None:
    node.set_nss(False)
    applied_of(node.run())
    assert (node.net / "nsswitch.conf").read_text() == "passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n"


def test_hosts_file_has_header_locals_and_one_line_per_address(node: Node) -> None:
    node.hosts_db.write_text("ctl.example.net 203.0.113.9\nctl.example.net 2001:db8::9\nnats.example.net 100.64.1.2\n")
    applied_of(node.run())
    lines = (node.net / "hosts").read_text().splitlines()
    assert re.fullmatch(r"# Rendered by noo-apply at \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", lines[0]), lines[0]
    assert lines[1:] == [
        "# names: ctl.example.net nats.example.net",
        "127.0.0.1 localhost", "::1 localhost", "127.0.1.1 host3",
        "2001:db8::9 ctl.example.net", "203.0.113.9 ctl.example.net", "100.64.1.2 nats.example.net",
    ]


def test_literal_ips_and_localhost_are_not_names(node: Node) -> None:
    node.env.write_text("NODE_ID=h\nNOO_GATEWAY_URL=https://10.1.2.3:8000\nNATS_URL=nats://localhost:4222,tls://[fd00::1]:4222\n")
    applied_of(node.run())
    assert (node.net / "hosts").read_text().splitlines()[1].strip() == "# names:"
    assert allow_line(node).split() == sorted(BASE_ALLOW)


# ── the allowlist ───────────────────────────────────────────────────────────

def test_allowlist_without_a_public_controller_address_is_the_base_only(node: Node) -> None:
    node.hosts_db.write_text("ctl.example.net 192.168.1.5\nnats.example.net 100.64.1.2\n")
    applied_of(node.run())
    assert allow_line(node).split() == sorted(BASE_ALLOW)


def test_a_public_controller_address_is_the_one_public_entry(node: Node) -> None:
    applied_of(node.run())
    assert allow_line(node).split() == sorted(BASE_ALLOW + ["203.0.113.9/32"])


def test_a_public_v6_controller_address_is_a_slash_128(node: Node) -> None:
    node.hosts_db.write_text("ctl.example.net 2001:db8::9\nnats.example.net 100.64.1.2\n")
    applied_of(node.run())
    assert "2001:db8::9/128" in allow_line(node).split()


def test_ipv4_mapped_addresses_from_getent_are_judged_as_ipv4(node: Node) -> None:
    node.hosts_db.write_text("ctl.example.net ::ffff:10.9.8.7\nnats.example.net ::ffff:203.0.113.77\n")
    applied_of(node.run())
    hosts = (node.net / "hosts").read_text()
    assert "10.9.8.7 ctl.example.net" in hosts and "203.0.113.77 nats.example.net" in hosts
    assert allow_line(node).split() == sorted(BASE_ALLOW + ["203.0.113.77/32"])


def test_172_just_outside_the_private_range_is_public(node: Node) -> None:
    node.hosts_db.write_text("ctl.example.net 172.32.0.1\nnats.example.net 172.31.255.255\n")
    applied_of(node.run())
    assert allow_line(node).split() == sorted(BASE_ALLOW + ["172.32.0.1/32"])


def test_fc00_7_only_with_a_global_ula_on_this_host(node: Node) -> None:
    applied_of(node.run())
    assert "fc00::/7" not in allow_line(node).split()
    node.ip_out.write_text("2: eth0    inet6 fd12:3456:789a::5/64 scope global \n")
    applied_of(node.run())
    assert "fc00::/7" in allow_line(node).split()


def test_the_tailnet_own_ula_address_does_not_open_fc00_7(node: Node) -> None:
    node.ip_out.write_text("3: tailscale0    inet6 fd7a:115c:a1e0::1234/128 scope global \n"
                           "2: eth0    inet6 2001:db8::5/64 scope global \n"
                           "2: eth0    inet6 fd12::5/64 scope link \n")
    applied_of(node.run())
    assert "fc00::/7" not in allow_line(node).split()


def test_nothing_in_test_net_1_is_ever_allowed(node: Node) -> None:
    applied_of(node.run())
    assert "192.0.2" not in node.dropin.read_text().split("IPAddressAllow=")[1].split("\n")[0]


# ── a name that does not resolve ───────────────────────────────────────────

def test_an_unresolvable_name_is_tagged_left_out_and_never_falls_back(node: Node) -> None:
    node.hosts_db.write_text("nats.example.net 100.64.1.2\n")
    r = node.run()
    assert "harness-egress=UNRESOLVED:ctl.example.net" in applied_of(r)
    assert "ctl.example.net does not resolve" in r.stderr or "'ctl.example.net' does not resolve" in r.stderr
    hosts = (node.net / "hosts").read_text()
    assert "100.64.1.2 nats.example.net" in hosts
    assert not re.search(r"^\S+ ctl\.example\.net$", hosts, re.M)
    assert "# names: ctl.example.net nats.example.net" in hosts   # still listed, so the agent can call it stale
    assert "nameserver 192.0.2.53" in (node.net / "resolv.conf").read_text()
    assert "hosts: files dns" in (node.net / "nsswitch.conf").read_text()


# ── the probe ──────────────────────────────────────────────────────────────

def test_probe_operation_not_permitted_is_enforced(node: Node) -> None:
    a = applied_of(node.run())
    assert a.endswith(" harness-egress=enforced") and "UNENFORCED" not in a, a
    call = [c for c in node.calls() if c.startswith("systemd-run")][0]
    assert "-p IPAddressDeny=any" in call and "-p IPAddressAllow=localhost" in call and "--collect" in call


def test_probe_connection_refused_is_unenforced(node: Node) -> None:
    node.probe_out.write_text("bash: connect: Connection refused\n")
    a = applied_of(node.run())
    assert "harness-egress=UNENFORCED:connection-refused" in a and "harness-egress=enforced" not in a, a


def test_probe_with_no_systemd_run_is_unenforced(node: Node) -> None:
    node.drop_systemd_run()
    a = applied_of(node.run())
    assert "harness-egress=UNENFORCED:systemd-run-missing" in a and "harness-egress=enforced" not in a, a


def test_probe_that_fails_silently_is_unenforced(node: Node) -> None:
    node.probe_out.write_text("")
    node.probe_rc.write_text("0")
    a = applied_of(node.run())
    assert "harness-egress=UNENFORCED:probe-rc-0" in a and "harness-egress=enforced" not in a, a


def test_a_probe_that_times_out_is_unenforced(node: Node) -> None:
    node.probe_out.write_text("")
    node.probe_rc.write_text("124")
    assert "harness-egress=UNENFORCED:probe-timeout" in applied_of(node.run())


def test_the_probe_never_blocks_the_files(node: Node) -> None:
    node.probe_out.write_text("bash: connect: Connection refused\n")
    applied_of(node.run())
    assert node.dropin.exists() and (node.net / "resolv.conf").exists()


# ── reload and restart; idempotence ────────────────────────────────────────

def test_a_first_apply_reloads_before_the_probe_and_asks_for_the_restart(node: Node) -> None:
    r = node.run()
    a = applied_of(r)
    assert "harness-egress-files" in a and "RESTART=1" in r.stdout
    calls = node.calls()
    assert calls.index("systemctl daemon-reload") < next(i for i, c in enumerate(calls) if c.startswith("systemd-run"))
    assert not any("restart" in c for c in calls), "restart goes through the applier's own path, not here"


def test_a_second_identical_apply_rewrites_nothing_and_restarts_nothing(node: Node) -> None:
    applied_of(node.run())
    files = [node.dropin, node.net / "resolv.conf", node.net / "hosts", node.net / "nsswitch.conf"]
    before = {f: (f.read_text(), f.stat().st_mtime_ns) for f in files}
    node.log.write_text("")
    r = node.run()
    a = applied_of(r)
    assert {f: (f.read_text(), f.stat().st_mtime_ns) for f in files} == before
    assert "harness-egress-files" not in a and "RESTART=0" in r.stdout
    assert "systemctl daemon-reload" not in node.calls()


def test_a_changed_controller_address_rewrites_and_restarts(node: Node) -> None:
    applied_of(node.run())
    node.hosts_db.write_text("ctl.example.net 203.0.113.10\nnats.example.net 100.64.1.2\n")
    r = node.run()
    assert "harness-egress-files" in applied_of(r) and "RESTART=1" in r.stdout
    assert "203.0.113.10/32" in allow_line(node).split()


def test_files_are_0644(node: Node) -> None:
    applied_of(node.run())
    for f in (node.dropin, node.net / "resolv.conf", node.net / "hosts", node.net / "nsswitch.conf"):
        assert stat.S_IMODE(f.stat().st_mode) == 0o644, f


# ── teardown ───────────────────────────────────────────────────────────────

def test_teardown_removes_the_drop_in_and_the_directory(node: Node) -> None:
    applied_of(node.run())
    assert node.dropin.exists() and node.net.exists()
    assert node.run("harness_egress_remove").returncode == 0
    assert not node.dropin.exists() and not node.net.exists()


# ── source guards: the call sites ───────────────────────────────────────────

def test_the_apply_runs_only_where_the_harness_unit_is_part_of_the_bundle() -> None:
    assert re.search(r'if \[ -f "\$HE_UNIT" \] && \{ \[ -f "\$WORK/files/harness-unit" \] \|\| \[ -f "\$WORK/files/harness-env" \]; \}; then\n    harness_egress_apply\n', APPLY)
    assert APPLY.index("harness_egress_apply\nfi") < APPLY.index("vendor_apply \"$WORK/files\"")
    # …and before the `applied:` line is printed, so the tags ride it.
    assert APPLY.index("harness_egress_apply\nfi") < APPLY.index('echo "applied:$applied"')


def test_teardown_calls_the_removal_before_it_hands_off() -> None:
    i = APPLY.index("harness_egress_remove\n    logger -t noo-apply \"teardown authorized")
    assert i < APPLY.index('echo "applied: teardown')
