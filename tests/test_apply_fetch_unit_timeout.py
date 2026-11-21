# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The root applier gives noo-fetch.service its start timeout (i1160 risk 4).

prep-host writes `TimeoutStartSec=7200` into noo-fetch.service on a fresh
install, but the unit is written only at enroll, so a node enrolled before it
kept a oneshot that could stay activating for ever. The applier (release-listed
as `applier`, i908) now renders a FIXED drop-in itself, no bundle kind, and
daemon-reloads. It never starts, stops or restarts noo-fetch.service: that is
the unit the apply runs in.

A daemon-reload re-reads the running fetch's unit too, and systemd counts the
new start timeout from when that run started, so the drop-in is written only
while the current run is younger than an hour (or when the unit is not
starting). The `fetch_unit_timeout` block (with `config_unchanged`) is lifted
out between its markers and run unprivileged with a fake systemctl and ps
first on PATH, as tests/test_netns_unit_apply.py runs netns_unit.
"""

from __future__ import annotations

import re
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
APPLY = (REPO / "scripts/noo-apply.sh").read_text()
PREP = (REPO / "scripts/prep-host.sh").read_text()
DEENROLL = (REPO / "scripts/deenroll-node-local.sh").read_text()

SET_LINE = "noo-apply: noo-fetch unit: start timeout set (7200 s)"
DROPIN = (
    "# Written by noo-apply: a stalled bundle pull ends, and the timer runs again.\n"
    "[Service]\n"
    "TimeoutStartSec=7200\n"
)


def _block(name: str) -> str:
    m = re.search(rf"# BEGIN {name}\n(.*?)# END {name}\n", APPLY, re.S)
    assert m, f"{name} is not delimited in noo-apply.sh"
    return m.group(1)


LIB = _block("config_unchanged") + _block("fetch_unit_timeout")


class Node:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.log = tmp / "calls.log"
        self.log.write_text("")
        self.units = tmp / "units"
        self.units.mkdir()
        (self.units / "noo-fetch.service").write_text("[Service]\nType=oneshot\nExecStart=/usr/local/bin/noo-fetch\n")
        self.dropin = self.units / "noo-fetch.service.d" / "10-timeout.conf"
        (tmp / "systemd").mkdir()  # this host "runs systemd" unless a test says otherwise
        # systemctl show -p ActiveState|MainPID --value noo-fetch.service, from env.
        self._exe("systemctl",
                  '#!/bin/sh\necho "systemctl $*" >> "$CALLS"\n'
                  'if [ "$1" = show ]; then\n'
                  '  case "$3" in\n'
                  '    ActiveState) echo "$FT_STATE" ;;\n'
                  '    MainPID) echo "$FT_PID" ;;\n'
                  '  esac\n'
                  'fi\nexit 0\n')
        self._exe("ps", '#!/bin/sh\necho "ps $*" >> "$CALLS"\necho "  $FT_ETIMES"\n')

    def _exe(self, name: str, body: str) -> None:
        f = self.bin / name
        f.write_text(body)
        f.chmod(f.stat().st_mode | stat.S_IXUSR)

    def run(self, state: str = "activating", pid: str = "4321", etimes: str = "40",
            **extra: str) -> subprocess.CompletedProcess:
        script = "set -eu\n" + LIB + "fetch_unit_timeout_apply\necho DONE\n"
        owner = subprocess.check_output(["sh", "-c", "echo $(id -un):$(id -gn)"], text=True).strip()
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "CALLS": str(self.log), "TMPDIR": str(self.tmp),
            "FETCH_UNIT_DIR": str(self.units), "FT_OWNER_ARGS": "", "FT_STAT_OWNER": owner,
            "FT_SYSTEMD_DIR": str(self.tmp / "systemd"),
            "FT_STATE": state, "FT_PID": pid, "FT_ETIMES": etimes,
        }
        env.update(extra)
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
        assert r.returncode == 0 and r.stdout.rstrip().endswith("DONE"), (r.stdout, r.stderr)
        return r

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines()


@pytest.fixture
def node(tmp_path: Path) -> Node:
    return Node(tmp_path)


def _no_unit_control(calls: list[str]) -> None:
    for c in calls:
        assert not re.match(r"systemctl (start|stop|restart|kill|try-restart|reload-or-restart|disable|mask)\b", c), calls


def test_a_young_run_gets_the_drop_in_and_a_reload_and_nothing_else(node: Node) -> None:
    r = node.run()
    assert node.dropin.read_text() == DROPIN
    assert stat.S_IMODE(node.dropin.stat().st_mode) == 0o644
    assert "systemctl daemon-reload" in node.calls()
    _no_unit_control(node.calls())
    assert r.stdout.splitlines()[0] == SET_LINE, r.stdout


def test_a_second_apply_is_silent_and_runs_nothing(node: Node) -> None:
    node.run()
    node.log.write_text("")
    r = node.run()
    assert node.calls() == [] and r.stdout == "DONE\n", (node.calls(), r.stdout)


def test_a_different_drop_in_is_replaced(node: Node) -> None:
    node.dropin.parent.mkdir()
    node.dropin.write_text("[Service]\nTimeoutStartSec=60\n")
    r = node.run()
    assert node.dropin.read_text() == DROPIN
    assert "systemctl daemon-reload" in node.calls() and SET_LINE in r.stdout


def test_an_apply_run_by_hand_writes_it(node: Node) -> None:
    node.run(state="inactive", pid="0", etimes="")
    assert node.dropin.read_text() == DROPIN
    assert "systemctl daemon-reload" in node.calls()


def test_a_run_an_hour_old_writes_nothing_and_says_so(node: Node) -> None:
    r = node.run(etimes="3600")
    assert not node.dropin.exists()
    assert "systemctl daemon-reload" not in node.calls()
    assert "start timeout not set yet (this run started 3600 s ago" in r.stdout, r.stdout


@pytest.mark.parametrize("pid,etimes", [("0", "40"), ("", "40"), ("4321", "")])
def test_an_unreadable_run_age_writes_nothing(node: Node, pid: str, etimes: str) -> None:
    r = node.run(pid=pid, etimes=etimes)
    assert not node.dropin.exists()
    assert "systemctl daemon-reload" not in node.calls()
    assert "this run's age cannot be read" in r.stdout, r.stdout


def test_no_fetch_unit_no_drop_in(node: Node) -> None:
    (node.units / "noo-fetch.service").unlink()
    node.run()
    assert not node.dropin.exists() and node.calls() == []


def test_no_systemd_no_drop_in(node: Node) -> None:
    (node.tmp / "systemd").rmdir()
    node.run()
    assert not node.dropin.exists() and node.calls() == []


# ── source guards ─────────────────────────────────────────────────────────

def test_the_block_never_starts_stops_or_restarts_a_unit() -> None:
    body = _block("fetch_unit_timeout")
    calls = re.findall(r"^\s*(?:if ! )?systemctl ([a-z-]+)", body, re.M)
    calls += re.findall(r"\$\(systemctl ([a-z-]+)", body)
    assert set(calls) == {"show", "daemon-reload"}, calls


def test_it_runs_once_after_the_apply_and_the_floor_outside_any_kind() -> None:
    sites = [m.start() for m in re.finditer(r"^fetch_unit_timeout_apply$", APPLY, re.M)]
    assert len(sites) == 1, sites
    at = sites[0]
    assert APPLY.rindex('release_floor_write "$RELEASE_OK_VERSION"', 0, at) < at
    assert APPLY.rindex('echo "ca-lane: retired"', 0, at) < at
    assert at < APPLY.index("# ── 4. Orchestrate")
    # Not keyed on any kind: no bundle carries it.
    assert "fetch-unit" not in APPLY.split("KNOWN_KINDS=", 1)[1].split("\n", 1)[0]


def test_the_drop_in_timeout_is_prep_hosts() -> None:
    m = re.search(r"cat > /etc/systemd/system/noo-fetch\.service <<'UNIT'\n(.*?)\nUNIT\n", PREP, re.S)
    assert m, "prep-host's noo-fetch.service heredoc not found"
    assert re.search(r"^TimeoutStartSec=7200$", m.group(1), re.M), m.group(1)
    assert re.search(r"^FETCH_TIMEOUT_S=7200$", APPLY, re.M)


def test_teardown_removes_the_drop_in() -> None:
    assert "rm -f /etc/systemd/system/noo-fetch.service.d/10-timeout.conf" in DEENROLL
    rm = DEENROLL.index("noo-fetch.service.d/10-timeout.conf")
    assert rm < DEENROLL.index('say "noo-fetch loop disarmed + removed"')
