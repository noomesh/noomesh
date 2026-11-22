# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The root applier gives noo-addons-after-boot.service its bounds (i1160 risk 7).

`noo onboard` writes the unit on a controller with `TimeoutStartSec=3600` and
`DefaultDependencies=no` (the rest of a service's defaults restored by hand),
so multi-user.target no longer waits for it. A controller onboarded before
that kept a unit without them, and only `noo onboard --only addons` rewrote it.
The controller's self node runs the root applier, so the applier (release-listed
as `applier`, i908) renders a FIXED drop-in itself, no bundle kind, and
daemon-reloads. It never starts, stops or restarts the unit.

The `addons_unit_bounds` block (with `config_unchanged`) is lifted out between
its markers and run unprivileged with a fake systemctl first on PATH, as
tests/test_apply_fetch_unit_timeout.py runs fetch_unit_timeout.
"""

from __future__ import annotations

import re
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
APPLY = (REPO / "scripts/noo-apply.sh").read_text()
DEENROLL = (REPO / "scripts/deenroll-node-local.sh").read_text()
AFTER_BOOT = (REPO / "noo-cli/src/commands/addon_after_boot.rs").read_text()

SET_LINE = ("noo-apply: noo-addons-after-boot unit: bounds set "
            "(start timeout 3600 s; multi-user.target does not wait)")
DROPIN = (
    "# Written by noo-apply: the boot does not wait for add-on starts, and a stalled start ends.\n"
    "[Unit]\n"
    "DefaultDependencies=no\n"
    "Requires=sysinit.target\n"
    "After=sysinit.target basic.target\n"
    "Conflicts=shutdown.target\n"
    "Before=shutdown.target\n"
    "\n"
    "[Service]\n"
    "TimeoutStartSec=3600\n"
)
# What onboard wrote before the bounds (i509): the service defaults, no timeout.
OLD_UNIT = (
    "[Unit]\nDescription=noomesh: start enabled add-ons that are down after a boot (once)\n"
    "After=docker.service network-online.target\nWants=network-online.target\n\n"
    "[Service]\nType=oneshot\nUser=owner\nExecStart=/usr/local/bin/noo addons after-boot\n\n"
    "[Install]\nWantedBy=multi-user.target\n"
)


def _block(name: str) -> str:
    m = re.search(rf"# BEGIN {name}\n(.*?)# END {name}\n", APPLY, re.S)
    assert m, f"{name} is not delimited in noo-apply.sh"
    return m.group(1)


LIB = _block("config_unchanged") + _block("addons_unit_bounds")


class Host:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.log = tmp / "calls.log"
        self.log.write_text("")
        self.units = tmp / "units"
        self.units.mkdir()
        self.unit = self.units / "noo-addons-after-boot.service"
        self.unit.write_text(OLD_UNIT)
        self.dropin = self.units / "noo-addons-after-boot.service.d" / "10-bounds.conf"
        (tmp / "systemd").mkdir()  # this host "runs systemd" unless a test says otherwise
        self._exe("systemctl", '#!/bin/sh\necho "systemctl $*" >> "$CALLS"\nexit 0\n')

    def _exe(self, name: str, body: str) -> None:
        f = self.bin / name
        f.write_text(body)
        f.chmod(f.stat().st_mode | stat.S_IXUSR)

    def run(self, **extra: str) -> subprocess.CompletedProcess:
        script = "set -eu\n" + LIB + "addons_unit_bounds_apply\necho DONE\n"
        owner = subprocess.check_output(["sh", "-c", "echo $(id -un):$(id -gn)"], text=True).strip()
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "CALLS": str(self.log), "TMPDIR": str(self.tmp),
            "AB_UNIT_DIR": str(self.units), "AB_OWNER_ARGS": "", "AB_STAT_OWNER": owner,
            "AB_SYSTEMD_DIR": str(self.tmp / "systemd"),
        }
        env.update(extra)
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
        assert r.returncode == 0 and r.stdout.rstrip().endswith("DONE"), (r.stdout, r.stderr)
        return r

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines()


@pytest.fixture
def host(tmp_path: Path) -> Host:
    return Host(tmp_path)


def _no_unit_control(calls: list[str]) -> None:
    for c in calls:
        assert c == "systemctl daemon-reload", calls


def test_an_installed_unit_gets_the_drop_in_and_a_reload_and_nothing_else(host: Host) -> None:
    r = host.run()
    assert host.dropin.read_text() == DROPIN
    assert stat.S_IMODE(host.dropin.stat().st_mode) == 0o644
    assert host.calls() == ["systemctl daemon-reload"]
    _no_unit_control(host.calls())
    assert r.stdout.splitlines()[0] == SET_LINE, r.stdout
    # The unit itself is not touched: onboard owns it.
    assert host.unit.read_text() == OLD_UNIT


def test_a_second_apply_is_silent_and_runs_nothing(host: Host) -> None:
    host.run()
    host.log.write_text("")
    r = host.run()
    assert host.calls() == [] and r.stdout == "DONE\n", (host.calls(), r.stdout)


def test_a_unit_that_already_has_the_bounds_still_gets_the_drop_in_once(host: Host) -> None:
    # A fresh install's unit carries the same lines: the drop-in is written
    # anyway (it sets nothing new) and the next apply is silent.
    host.unit.write_text(OLD_UNIT.replace("[Service]\n", "[Service]\nTimeoutStartSec=3600\n"))
    host.run()
    assert host.dropin.read_text() == DROPIN
    host.log.write_text("")
    assert host.run().stdout == "DONE\n" and host.calls() == []


def test_a_different_drop_in_is_replaced(host: Host) -> None:
    host.dropin.parent.mkdir()
    host.dropin.write_text("[Service]\nTimeoutStartSec=60\n")
    r = host.run()
    assert host.dropin.read_text() == DROPIN
    assert host.calls() == ["systemctl daemon-reload"] and SET_LINE in r.stdout


def test_a_drop_in_with_another_mode_is_rewritten(host: Host) -> None:
    host.dropin.parent.mkdir()
    host.dropin.write_text(DROPIN)
    host.dropin.chmod(0o666)
    host.run()
    assert stat.S_IMODE(host.dropin.stat().st_mode) == 0o644
    assert host.calls() == ["systemctl daemon-reload"]


def test_no_unit_no_drop_in(host: Host) -> None:
    host.unit.unlink()
    r = host.run()
    assert not host.dropin.parent.exists() and host.calls() == [] and r.stdout == "DONE\n"


def test_no_systemd_no_drop_in(host: Host) -> None:
    (host.tmp / "systemd").rmdir()
    r = host.run()
    assert not host.dropin.parent.exists() and host.calls() == [] and r.stdout == "DONE\n"


def test_a_write_that_fails_says_so_and_does_not_fail_the_apply(host: Host) -> None:
    host.dropin.parent.write_text("not a directory")
    r = host.run()
    assert host.calls() == []
    assert "noo-addons-after-boot unit: could not write" in r.stderr, r.stderr


# ── source guards ─────────────────────────────────────────────────────────

def test_the_block_never_starts_stops_or_restarts_a_unit() -> None:
    body = _block("addons_unit_bounds")
    calls = re.findall(r"^\s*(?:if ! )?systemctl ([a-z-]+)", body, re.M)
    calls += re.findall(r"\$\(systemctl ([a-z-]+)", body)
    assert calls == ["daemon-reload"], calls
    assert re.search(r"^\s*systemctl daemon-reload 2>/dev/null \|\| true$", body, re.M)


def test_it_runs_once_after_the_apply_and_the_floor_outside_any_kind() -> None:
    sites = [m.start() for m in re.finditer(r"^addons_unit_bounds_apply$", APPLY, re.M)]
    assert len(sites) == 1, sites
    at = sites[0]
    assert APPLY.rindex('release_floor_write "$RELEASE_OK_VERSION"', 0, at) < at
    assert APPLY.rindex("\nfetch_unit_timeout_apply\n", 0, at) < at
    assert at < APPLY.index("# ── 4. Orchestrate")
    # Not keyed on any kind: no bundle carries it.
    assert "addons-unit" not in APPLY.split("KNOWN_KINDS=", 1)[1].split("\n", 1)[0]
    # Never fails the apply: every path out of the function is `return 0`.
    body = _block("addons_unit_bounds")
    fn = body[body.index("addons_unit_bounds_apply() {"):]
    assert re.findall(r"\breturn [0-9]+", fn) and set(re.findall(r"\breturn ([0-9]+)", fn)) == {"0"}
    assert not re.search(r"\bexit\b", fn)


def test_the_drop_in_carries_every_bound_onboard_writes_into_the_unit() -> None:
    m = re.search(r'pub fn render_unit\(.*?Ok\(format!\(\n\s*"([^"]*)"', AFTER_BOOT, re.S)
    assert m, "render_unit's format string not found"
    unit = m.group(1).replace("\\n", "\n")
    unit_sec, service_sec = unit.split("\n[Service]\n", 1)
    drop_unit, drop_service = DROPIN.split("\n[Service]\n", 1)
    for line in ("DefaultDependencies=no", "Requires=sysinit.target", "After=sysinit.target basic.target",
                 "Conflicts=shutdown.target", "Before=shutdown.target"):
        assert f"\n{line}\n" in unit_sec and f"\n{line}\n" in drop_unit, line
    t = re.search(r"^TimeoutStartSec=([0-9]+)$", service_sec, re.M)
    assert t and f"TimeoutStartSec={t.group(1)}\n" == drop_service, (t, drop_service)
    assert re.search(rf"^AB_TIMEOUT_S={t.group(1)}$", APPLY, re.M)
    assert re.search(r'^pub const UNIT_PATH: &str = "/etc/systemd/system/noo-addons-after-boot\.service";$',
                     AFTER_BOOT, re.M)


def test_teardown_removes_the_drop_in() -> None:
    assert "rm -f /etc/systemd/system/noo-addons-after-boot.service.d/10-bounds.conf" in DEENROLL
    rm = DEENROLL.index("noo-addons-after-boot.service.d/10-bounds.conf")
    assert rm < DEENROLL.index('say "noo-fetch loop disarmed + removed"')
    assert rm < DEENROLL.index("systemctl daemon-reload", rm)
