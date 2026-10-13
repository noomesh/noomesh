# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The `host-telemetry` bundle kind: switch off tailscaled's log upload.

`host_telemetry_apply` in scripts/noo-apply.sh is lifted out between its
markers and run against a temp tree with `pidof`, `systemctl`, `logger` and
`sleep` stubbed as shell functions (the way test_agent_secret_files_applier.py
drives its block). The kind is delivered by `noo cluster host-telemetry apply`;
it restarts tailscaled, so the properties pinned here are the ones that keep
that safe: the operator's opt-in marker wins, a restart happens only when
something changed (or the running process lacks the switch), and a re-run is
a no-op.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
APPLIER = REPO / "scripts" / "noo-apply.sh"


def block() -> str:
    m = re.search(r"# BEGIN host_telemetry\n(.*?)# END host_telemetry", APPLIER.read_text(), re.S)
    assert m, "host_telemetry is not delimited in noo-apply.sh"
    body = m.group(1)
    assert "TS_NO_LOGS_NO_SUPPORT=true" in body, "the block no longer sets the switch"
    return body


class Node:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.defaults = tmp / "default-tailscaled"
        self.marker = tmp / "allow-tailscale-log-upload"
        self.proc = tmp / "proc"
        self.systemd = tmp / "systemd"
        self.systemd.mkdir()
        self.log = tmp / "calls.log"
        self.log.write_text("")
        self.running = tmp / "running"

    def start_tailscaled(self, switch: bool, how: str = "environ") -> None:
        d = self.proc / "123"
        d.mkdir(parents=True, exist_ok=True)
        cmd = b"/usr/sbin/tailscaled\0--state=/var/lib/tailscale/tailscaled.state\0"
        env = b"PATH=/usr/bin\0"
        if switch and how == "environ":
            env += b"TS_NO_LOGS_NO_SUPPORT=true\0"
        if switch and how == "flag":
            cmd += b"--no-logs-no-support\0"
        (d / "cmdline").write_bytes(cmd)
        (d / "environ").write_bytes(env)
        self.running.write_text("")

    def run(self) -> subprocess.CompletedProcess:
        script = f"""set -eu
HT_MARKER={self.marker}
HT_DEFAULTS={self.defaults}
HT_PROC={self.proc}
HT_SYSTEMD={self.systemd}
pidof() {{ [ -e {self.running} ] && echo 123 || return 1; }}
systemctl() {{ echo "systemctl $*" >> {self.log}; }}
logger() {{ :; }}
sleep() {{ :; }}
tailscaled() {{ :; }}
{block()}
host_telemetry_apply
"""
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True)

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines()


def test_a_running_tailscaled_without_the_switch_gets_it_and_one_restart(tmp_path: Path) -> None:
    n = Node(tmp_path)
    n.defaults.write_text('FLAGS=""\nPORT="41641"\n')
    n.start_tailscaled(switch=False)
    r = n.run()
    assert r.returncode == 0, r.stderr
    assert "TS_NO_LOGS_NO_SUPPORT=true" in n.defaults.read_text().splitlines()
    assert n.defaults.read_text().startswith('FLAGS=""\nPORT="41641"\n'), "existing lines were disturbed"
    assert n.calls().count("systemctl restart tailscaled") == 1, n.calls()
    assert "restarted" in r.stdout, r.stdout


def test_the_operator_opt_in_marker_wins_and_nothing_is_touched(tmp_path: Path) -> None:
    n = Node(tmp_path)
    n.marker.write_text("")
    n.start_tailscaled(switch=False)
    r = n.run()
    assert r.returncode == 0, r.stderr
    assert not n.defaults.exists(), "wrote the switch over an operator's opt-in"
    assert n.calls() == [], n.calls()
    assert "operator opt-in" in r.stdout, r.stdout


def test_a_rerun_after_the_restart_is_a_no_op(tmp_path: Path) -> None:
    n = Node(tmp_path)
    n.defaults.write_text("")
    n.start_tailscaled(switch=False)
    assert n.run().returncode == 0
    n.start_tailscaled(switch=True)  # what the restart produced
    before = n.defaults.read_text()
    n.log.write_text("")
    r = n.run()
    assert r.returncode == 0, r.stderr
    assert n.defaults.read_text() == before, "a second run appended again"
    assert n.calls() == [], f"a no-change re-run restarted tailscaled: {n.calls()}"
    assert "already off" in r.stdout


def test_a_file_edited_without_a_restart_still_gets_the_restart(tmp_path: Path) -> None:
    n = Node(tmp_path)
    n.defaults.write_text("TS_NO_LOGS_NO_SUPPORT=true\n")
    n.start_tailscaled(switch=False)  # the process predates the file
    r = n.run()
    assert r.returncode == 0, r.stderr
    assert n.defaults.read_text() == "TS_NO_LOGS_NO_SUPPORT=true\n"
    assert n.calls().count("systemctl restart tailscaled") == 1, n.calls()


def test_the_flag_form_on_the_running_command_line_counts_as_off(tmp_path: Path) -> None:
    n = Node(tmp_path)
    n.defaults.write_text('FLAGS="--no-logs-no-support"\n')
    n.start_tailscaled(switch=True, how="flag")
    r = n.run()
    assert r.returncode == 0, r.stderr
    assert n.calls() == [], n.calls()
    assert n.defaults.read_text() == 'FLAGS="--no-logs-no-support"\n'


def test_a_stopped_tailscaled_is_not_started_by_the_applier(tmp_path: Path) -> None:
    n = Node(tmp_path)
    r = n.run()
    assert r.returncode == 0, r.stderr
    assert "TS_NO_LOGS_NO_SUPPORT=true" in n.defaults.read_text()
    assert n.calls() == [], f"started or restarted a stopped tailscaled: {n.calls()}"


def test_an_unterminated_last_line_is_not_glued_to_the_new_one(tmp_path: Path) -> None:
    n = Node(tmp_path)
    n.defaults.write_text('PORT="41641"')
    n.start_tailscaled(switch=False)
    assert n.run().returncode == 0
    assert n.defaults.read_text().splitlines() == ['PORT="41641"', "TS_NO_LOGS_NO_SUPPORT=true"]


def test_a_commented_switch_is_not_mistaken_for_a_set_one(tmp_path: Path) -> None:
    n = Node(tmp_path)
    n.defaults.write_text("# TS_NO_LOGS_NO_SUPPORT=true\n")
    n.start_tailscaled(switch=False)
    assert n.run().returncode == 0
    assert n.defaults.read_text().splitlines()[-1] == "TS_NO_LOGS_NO_SUPPORT=true"
    assert n.calls().count("systemctl restart tailscaled") == 1


def test_a_node_without_systemd_is_skipped_not_failed(tmp_path: Path) -> None:
    n = Node(tmp_path)
    n.systemd.rmdir()
    r = n.run()
    assert r.returncode == 0, r.stderr
    assert not n.defaults.exists() and n.calls() == []


def payload_rc(tmp: Path, body: str, node: str = "host2") -> subprocess.CompletedProcess:
    f = tmp / "host-telemetry"
    f.write_text(body)
    script = f"set -eu\n{block()}\nhost_telemetry_payload_ok {f} {node}\n"
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True)


def test_the_payload_is_exactly_the_node_name_and_nothing_else(tmp_path: Path) -> None:
    """The kind is a FIXED operation: no script, command, path or value may
    ride in it, so it adds no capability beyond TS_NO_LOGS_NO_SUPPORT=true in
    /etc/default/tailscaled and a tailscaled restart."""
    assert payload_rc(tmp_path, "NODE=host2\n").returncode == 0
    for extra in [
        "NODE=host2\nTS_NO_LOGS_NO_SUPPORT=false\n",
        "NODE=host2\nrm -rf /\n",
        "NODE=host2\nPATH=/tmp/evil\n",
        "#!/bin/sh\nNODE=host2\n",
        "NODE=host2\nNODE=host2\n",
        "NODE=host2;reboot\n",
        "NODE=$(id)\n",
        "NODE=../../etc\n",
        "apply\n",
        "",
    ]:
        r = payload_rc(tmp_path, extra)
        assert r.returncode == 65, f"accepted {extra!r}: rc={r.returncode} {r.stderr}"
        assert "nothing but NODE=" in r.stderr


def test_a_payload_for_another_node_is_refused_76(tmp_path: Path) -> None:
    r = payload_rc(tmp_path, "NODE=host6\n", node="host2")
    assert r.returncode == 76, r.stderr


def test_the_dispatch_checks_the_payload_before_acting_and_touches_one_file_one_service() -> None:
    text = APPLIER.read_text()
    m = re.search(r'if \[ -f "\$WORK/files/host-telemetry" \]; then\n(.*?)\nfi\n', text, re.S)
    assert m, "noo-apply has no host-telemetry dispatch"
    body = m.group(1)
    assert body.index("host_telemetry_payload_ok") < body.index("host_telemetry_apply"), body
    assert '"$NODE_ID"' in body
    # Nothing in the applier block reads the payload for content: the only
    # thing it writes is the one key, and the only service it restarts is tailscaled.
    blk = block()
    assert "files/host-telemetry" not in blk.replace("host_telemetry_payload_ok", ""), "the block reads the payload"
    calls = re.findall(r"systemctl [^\n|;&]*", blk)
    assert calls, "the block no longer restarts tailscaled"
    assert all(c.rstrip().endswith("tailscaled") or " tailscaled " in c for c in calls), calls
    assert not re.search(r"\b(docker|rm|curl|wget|eval|source)\b", blk.replace("# ", "#")), "the block does more than the one key"
    assert blk.count("TS_NO_LOGS_NO_SUPPORT=true'") == 1
    assert "/etc/default/tailscaled" in blk
