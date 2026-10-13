# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""After the rail installs a new agent binary, the applier restarts the sensor
companion that bind-mounts it — and nothing else.

#899 retired hostd's swap, which used to restart NOO_HOSTD_COMPANION_CONTAINERS
after a healthy swap (host9 runs one). The replacement lives in the applier
(`companion_restart`, lifted out between its markers and run with `docker`,
`systemctl` and `logger` stubbed). It is a restart only, decided from this host:
the shipped name shape AND a bind-mount of /usr/local/bin/noo-node-agent, from
the hostd unit's declared list when it has one. A bundle names nothing here.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
APPLIER = REPO / "scripts" / "noo-apply.sh"
AGENT_BIN = "/usr/local/bin/noo-node-agent"


def block() -> str:
    m = re.search(r"# BEGIN companion_restart\n(.*?)# END companion_restart", APPLIER.read_text(), re.S)
    assert m, "companion_restart is not delimited in noo-apply.sh"
    return m.group(1)


def run(tmp: Path, containers: dict[str, list[str]], declared: str = "", restart_fails: str = "",
        companion_first: bool = False) -> tuple[subprocess.CompletedProcess, list[str]]:
    log = tmp / "calls"
    log.write_text("")
    env_order = (f"NOO_HOSTD_COMPANION_CONTAINERS={declared} NOO_HOSTD_MODE=worker" if companion_first
                 else f"NOO_HOSTD_MODE=worker NOO_HOSTD_COMPANION_CONTAINERS={declared}")
    mounts = "\n".join(f'    {n}) printf "%s\\n" {" ".join(repr(m) for m in ms) or "\"\""} ;;' for n, ms in containers.items())
    script = f"""set -eu
logger() {{ :; }}
systemctl() {{
    # `systemctl show -p Environment [--value]`: the property prefix only
    # without --value; the declared list first or after another variable.
    [ -n "{declared}" ] || return 0
    _vars="{env_order}"
    case " $* " in *" --value "*) echo "$_vars" ;; *) echo "Environment=$_vars" ;; esac
}}
docker() {{
    case "$1" in
        ps) printf '%s\\n' {' '.join(containers) or '""'} ;;
        inspect) case "$4" in
{mounts}
            *) return 1 ;;
            esac ;;
        restart) echo "restart $2" >> "{log}"; [ "$2" != "{restart_fails}" ] ;;
    esac
}}
{block()}
companion_restart
"""
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    return r, [l.split()[1] for l in log.read_text().splitlines()]


def test_the_sensor_companion_that_mounts_the_agent_is_restarted(tmp_path: Path) -> None:
    r, restarted = run(tmp_path, {
        "noo-node-agent-sensors": ["/etc/noo/pki/ca.crt", AGENT_BIN],
        "noo-vllm": [AGENT_BIN],                        # wrong shape: never
        "noo-other-node-agent-sensors": ["/srv/x"],     # right shape, no mount: never
    })
    assert r.returncode == 0, r.stderr
    assert restarted == ["noo-node-agent-sensors"]
    assert "restarted onto the new agent binary" in r.stdout


@pytest.mark.parametrize("companion_first", [False, True], ids=["after-another-var", "first"])
def test_a_declared_list_narrows_and_is_still_held_to_the_shape(tmp_path: Path, companion_first: bool) -> None:
    r, restarted = run(tmp_path, {
        "noo-node-agent-sensors": [AGENT_BIN],
        "lab-node-agent-sensors": [AGENT_BIN],
        "evil": [AGENT_BIN],
    }, declared="lab-node-agent-sensors,evil", companion_first=companion_first)
    assert r.returncode == 0, r.stderr
    assert restarted == ["lab-node-agent-sensors"]


def test_a_failed_restart_is_loud_and_does_not_fail_the_apply(tmp_path: Path) -> None:
    r, restarted = run(tmp_path, {"noo-node-agent-sensors": [AGENT_BIN]}, restart_fails="noo-node-agent-sensors")
    assert r.returncode == 0
    assert "ALERT" in r.stderr and "PREVIOUS agent binary" in r.stderr


def test_no_companion_no_restart(tmp_path: Path) -> None:
    r, restarted = run(tmp_path, {"noo-vllm": [], "noo-ollama": []})
    assert r.returncode == 0 and restarted == []


def test_it_runs_only_when_the_agent_binary_was_applied_and_after_the_agent_is_up() -> None:
    text = APPLIER.read_text()
    tail = text[text.index("# ── 4. Orchestrate"):]
    assert tail.index("systemctl is-active noo-node-agent") < tail.index("companion_restart ;;")
    assert '*" agent-binary "*) companion_restart ;;' in tail
    # Nothing from the bundle reaches it: it reads no $WORK path.
    assert "$WORK" not in block()


@pytest.mark.parametrize("name", ["noo-node-agent-sensors", "lab-node-agent-sensors"])
def test_the_shape_matches_the_compose_container_name(name: str) -> None:
    compose = (REPO / "docker-compose.cluster.yml").read_text()
    assert "container_name: ${NOO_CONTAINER_PREFIX:-noo}-node-agent-sensors" in compose
    shape = re.search(r"^COMPANION_SHAPE='(.*)'$", block(), re.M).group(1)
    assert re.fullmatch(shape.strip("^$"), name)
