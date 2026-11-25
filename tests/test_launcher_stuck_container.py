# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""One unkillable container must not take the whole stack down
(scripts/lib-stuck-container.sh; controller ctrl, 2026-10-20).

`docker compose up --force-recreate` failed with "cannot stop container: <id>:
tried to kill container, but did not receive an exit event" for
noo-ollama-embed and aborted, leaving every service Created. The launcher
must name the stuck service, start every OTHER service, and exit 75 so
`noo upgrade` can say "stack up except <service>". Any other failure keeps
compose's own exit code, and a clean `up` stays silent.

A fake `docker` on PATH stands in for the daemon; nothing real is touched.
"""

from __future__ import annotations

import os
import re
import subprocess
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
STUCK_ID = "c5bba1c9" + "0" * 56

FAKE_DOCKER = r"""#!/bin/bash
echo "$*" >> "$FAKE_LOG"
case "$*" in
  *"config --services"*) printf '%s\n' postgres redis gateway ollama-embed ;;
  "inspect -f {{.Name}} "*) echo "/noo-ollama-embed" ;;
  "inspect -f {{ index .Config.Labels"*) echo "ollama-embed" ;;
  *" up "*" ollama-embed"*|*" up "*"--no-deps"*) [ -n "$FAKE_SECOND_UP_FAILS" ] && { echo "boom" >&2; exit 1; }; exit 0 ;;
  *" up "*) printf '%s\n' "$FAKE_UP_STDERR" >&2; exit "$FAKE_UP_RC" ;;
  *) exit 0 ;;
esac
"""


def _run(tmp_path: Path, up_stderr: str, up_rc: int = 1, second_fails: bool = False):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    d = bin_dir / "docker"
    d.write_text(FAKE_DOCKER)
    d.chmod(0o755)
    log = tmp_path / "docker.log"
    report = tmp_path / "report"
    script = textwrap.dedent(f"""
        . {SCRIPTS}/lib-ui.sh
        . {SCRIPTS}/lib-stuck-container.sh
        noo_compose_up_isolating_stuck compose -f a.yml --profile controller up -d --force-recreate --scale node-agent=0
        echo "RC=$?"
    """)
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "FAKE_LOG": str(log),
        "FAKE_UP_STDERR": up_stderr,
        "FAKE_UP_RC": str(up_rc),
        "FAKE_SECOND_UP_FAILS": "1" if second_fails else "",
        "NOO_STUCK_REPORT": str(report),
        "NO_COLOR": "1",
        "LC_ALL": "C",
    }
    p = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    calls = log.read_text().splitlines() if log.exists() else []
    rc = int(re.search(r"RC=(\d+)", p.stdout).group(1))
    return p, calls, rc, report


STUCK_MSG = (
    f"Error response from daemon: cannot stop container: {STUCK_ID}: "
    "tried to kill container, but did not receive an exit event"
)


def test_stuck_container_starts_everything_else_and_exits_75(tmp_path):
    p, calls, rc, report = _run(tmp_path, STUCK_MSG)
    assert rc == 75, p.stdout + p.stderr
    out = p.stdout + p.stderr
    assert ("noo-ollama-embed (ollama-embed) is stuck: its process will not exit (kill -9 and docker restart "
            "cannot clear it); a reboot of this host clears it. Starting everything else.") in out
    second = [c for c in calls if " up " in f" {c} " and "--no-deps" in c]
    assert len(second) == 1, calls
    c = second[0]
    assert c.endswith("postgres redis gateway"), c
    assert "ollama-embed" not in c
    assert "-f a.yml --profile controller" in c and "--force-recreate" in c and "--scale node-agent=0" in c
    assert report.read_text().split() == ["ollama-embed", STUCK_ID]
    assert not any(x.startswith("rename") or " kill" in x for x in calls), "never rename or kill"


def test_the_other_services_failing_keeps_composes_own_code(tmp_path):
    p, calls, rc, _ = _run(tmp_path, STUCK_MSG, second_fails=True)
    assert rc == 1, p.stdout + p.stderr


def test_any_other_failure_is_passed_through_untouched(tmp_path):
    p, calls, rc, report = _run(tmp_path, "Error response from daemon: toomanyrequests", up_rc=3)
    assert rc == 3
    assert not report.exists()
    assert not any("--no-deps" in c for c in calls), "no isolation for a transient registry error"
    assert "is stuck" not in p.stdout + p.stderr


def test_a_clean_up_is_silent_and_zero(tmp_path):
    p, calls, rc, _ = _run(tmp_path, "", up_rc=0)
    assert rc == 0
    assert len([c for c in calls if " up " in f" {c} "]) == 1


def test_both_launchers_use_it_and_the_rust_code_agrees():
    for name in ("noomesh-start.sh", "noomesh-restart.sh"):
        t = (SCRIPTS / name).read_text()
        assert "lib-stuck-container.sh" in t, name
        # start's whole-stack `up` lives in lib-start-inputs.sh
        # (start_inputs_full_up), forcing only under --recreate.
        up = t
        if name == "noomesh-start.sh":
            assert re.search(r"^\s*start_inputs_full_up \$BUILD_FLAG", t, re.M), name
            up = (SCRIPTS / "lib-start-inputs.sh").read_text()
        assert re.search(r"^\s*noo_compose_up_isolating_stuck compose .* up -d .*(--force-recreate|\$START_UP_FORCE)", up, re.M), name
        assert '"$NOO_EXIT_STACK_PARTIAL"' in t
    assert "NOO_EXIT_STACK_PARTIAL=75" in (SCRIPTS / "lib-stuck-container.sh").read_text()
    assert "lib-stuck-container.sh" in (REPO_ROOT / "noo-cli" / "build.rs").read_text()


# ---------------------------------------------------------------------------
# The third shape (2026-11-25, 0.6.30): the container's process survived
# SIGKILL, containerd could not delete the task, and from then on every docker
# call naming that one container (`docker inspect` included) never returned.
# No compose error text to read: the launcher asks first, with a bound, and
# nothing it runs afterwards names the held container.
# ---------------------------------------------------------------------------

import json
import time

HUNG_ID = "9f3e1d2c" + "0" * 4  # a short id, as `docker ps` prints it
HUNG_SLEEP = 25  # past the bound; the tests' own deadline is below this

# The fixture config: the GPU embedder joins its stunnel door's network
# namespace and compose restarts it whenever it restarts the door
# (docker-compose.cluster.yml); the gateway needs postgres and redis.
CONFIG_JSON = json.dumps({"services": {
    "gateway": {"depends_on": {"postgres": {"condition": "service_healthy"}, "redis": {"condition": "service_healthy"}}},
    "postgres": {}, "redis": {}, "loki": {},
    "stunnel-ollama-embed": {},
    "ollama-embed": {"network_mode": "service:stunnel-ollama-embed",
                     "depends_on": {"stunnel-ollama-embed": {"condition": "service_started", "restart": True}}},
}})

FAKE_DOCKER_HUNG = r"""#!/bin/bash
echo "$*" >> "$FAKE_LOG"
case "$*" in
  *"config --services"*) printf '%s\n' gateway postgres redis loki stunnel-ollama-embed ollama-embed ;;
  *"config --format json"*) cat "$FAKE_CONFIG" ;;
  "ps -a --filter status=created"*) [ -n "$FAKE_CREATED" ] && echo "ddd444 noo-loki loki" ;;
  "ps -a "*) [ -n "$FAKE_PS_HANGS" ] && sleep 25
    printf '%s\n' "aaa111 noo-gateway gateway" "bbb222 noo-postgres postgres" \
        "ccc333 noo-redis redis" "eee555 noo-loki loki" \
        "fff666 noo-stunnel-ollama-embed stunnel-ollama-embed" "$HUNG_ID noo-ollama-embed ollama-embed" ;;
  "ps -aq --filter label=com.docker.compose.project="*) printf '%s\n' aaa111 bbb222 ccc333 "$HUNG_ID" ;;
  "inspect -f {{.State.Status}} $HUNG_ID") [ -z "$FAKE_HUNG_OFF" ] && sleep 25; echo exited ;;
  "inspect -f {{.State.Status}} $SLOW_ID") sleep "$SLOW_SECS"; echo running ;;
  "inspect -f {{.State.Status}} "*) echo running ;;
  "inspect -f {{if .State.Health}}"*) echo healthy ;;
  "inspect -f {{index .Config.Labels"*) for a in "$@"; do case "$a" in -f|inspect|'{{index .Config.Labels "com.docker.compose.service"}} {{.Id}} {{.State.Status}}') ;; *) echo "svc $a running" ;; esac; done ;;
  *"ps -aq"*) echo "ps-ok" ;;
  *) exit 0 ;;
esac
"""


def _run_hung(tmp_path: Path, body: str, hung: bool = True, extra_env: dict | None = None, lib_start_inputs: bool = False):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    d = bin_dir / "docker"
    d.write_text(FAKE_DOCKER_HUNG)
    d.chmod(0o755)
    cfg = tmp_path / "config.json"
    cfg.write_text(CONFIG_JSON)
    log = tmp_path / "docker.log"
    report = tmp_path / "report"
    start_inputs = ""
    if lib_start_inputs:
        start_inputs = textwrap.dedent(f"""
            . {SCRIPTS}/lib-start-inputs.sh
            start_inputs_prepare() {{ START_UP_FORCE=""; return 0; }}
            _compose_project_name() {{ echo noo; }}
            start_inputs_report() {{ rm -f "$1" "$2"; return 0; }}
        """)
    script = textwrap.dedent(f"""
        . {SCRIPTS}/lib-ui.sh
        . {SCRIPTS}/lib-stuck-container.sh
        {start_inputs}
        COMPOSE_FILES="-f a.yml"; PROFILE_ARGS="--profile controller"
        {body}
    """)
    env = {
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "FAKE_LOG": str(log), "FAKE_CONFIG": str(cfg),
        "HUNG_ID": HUNG_ID, "SLOW_ID": "none", "SLOW_SECS": "0",
        "FAKE_HUNG_OFF": "" if hung else "1",
        "NOO_DOCKER_PROBE_SECS": "1", "NOO_DOCKER_REPROBE_SECS": "1", "NOO_STAGE_WAIT_SECS": "3",
        "NOO_STUCK_REPORT": str(report),
        "NO_COLOR": "1", "LC_ALL": "C",
    }
    env.update(extra_env or {})
    t0 = time.time()
    # Well inside the fake's sleep: a hung call makes this raise
    # TimeoutExpired and the test fails.
    p = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=HUNG_SLEEP - 8)
    calls = log.read_text().splitlines() if log.exists() else []
    return p, calls, report, time.time() - t0


UP = "compose -f a.yml --profile controller up --no-deps -d"


def test_a_held_container_is_named_and_the_rest_start_in_stages(tmp_path):
    p, calls, report, took = _run_hung(tmp_path, textwrap.dedent("""
        noo_compose_up_isolating_stuck compose $COMPOSE_FILES $PROFILE_ARGS up -d --force-recreate
        echo "RC=$?"
        echo "ISO=$NOO_ISOLATED_SERVICES EXC=$NOO_EXCLUDED_SERVICES"
    """), extra_env={"FAKE_CREATED": "1"})
    out = p.stdout + p.stderr
    assert "RC=75" in out, out
    assert "ISO=ollama-embed EXC=stunnel-ollama-embed" in out
    assert took < 17, took
    ups = [c for c in calls if " up " in f" {c} "]
    # stage 1: the data stores (postgres, redis), waited for; then the rest by
    # dependency layer: loki and the gateway needing both stores.
    assert ups[0] == f"{UP} --force-recreate postgres redis", ups
    assert ups[1:] == [f"{UP} --force-recreate gateway loki"] or ups[1:] == [f"{UP} --force-recreate loki gateway"], ups
    i0 = calls.index(ups[0])
    waits = [k for k, c in enumerate(calls) if "ps -aq postgres" in c or "ps -aq redis" in c]
    assert waits and min(waits) > i0 and max(waits) < calls.index(ups[1]), "stage 1 is waited for before stage 2"
    # the Created sweep runs last and starts the leftover by name
    assert calls[-1] == "start noo-loki", calls[-3:]
    # neither the held container nor the door it joins is named in any compose call
    for c in calls:
        if c.startswith("compose") and "config" not in c:
            assert "ollama-embed" not in c, c
    assert not any(HUNG_ID in c for c in calls if not c.startswith("inspect -f {{.State.Status}}") and not c.startswith("ps ")), calls
    assert "not touching stunnel-ollama-embed (ollama-embed joins its network namespace)" in out
    assert out.count("Docker did not answer for noo-ollama-embed (ollama-embed)") == 1, out
    assert "If it still does not answer, its process most likely did not exit" in out
    assert "only a reboot of this host removes it" in out
    assert report.read_text().split() == ["ollama-embed", HUNG_ID]
    assert not any(x.startswith("rename") or " kill" in x or x.startswith("rm") for x in calls)


def test_a_held_door_leaves_its_backend_out_too(tmp_path):
    p, calls, report, took = _run_hung(tmp_path, textwrap.dedent("""
        FAKE_DUMMY=1
        noo_hold_hung "" compose $COMPOSE_FILES $PROFILE_ARGS
        echo "EXC=$NOO_EXCLUDED_SERVICES"
        noo_service_is_left_out ollama-embed && echo "OUT=ollama-embed"
    """))
    out = p.stdout + p.stderr
    # the held container here is ollama-embed itself: the door is the excluded one
    assert "EXC=stunnel-ollama-embed" in out, out
    # and the relation the other way, from a fixture where the DOOR is held:
    cfg = json.loads(CONFIG_JSON)
    rel = subprocess.run(["bash", "-c", textwrap.dedent(f"""
        . {SCRIPTS}/lib-ui.sh; . {SCRIPTS}/lib-stuck-container.sh
        _NOO_CFG_JSON='{json.dumps(cfg)}'
        _noo_rel excluded stunnel-ollama-embed
        _noo_rel closure gateway
        _noo_rel layers gateway postgres redis loki
    """)], capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
    lines = rel.stdout.splitlines()
    assert lines[0] == "ollama-embed\tit shares the network namespace of stunnel-ollama-embed", rel.stdout + rel.stderr
    assert sorted(lines[1].split()) == ["gateway", "postgres", "redis"]
    assert lines[2:] == ["postgres redis loki", "gateway"], lines


def test_full_and_named_start_probe_before_any_snapshot_inspect(tmp_path):
    p, calls, report, took = _run_hung(tmp_path, textwrap.dedent("""
        start_inputs_full_up --build
        echo "FULL_RC=$?"
        NOO_PROBE_DONE=""
        noo_hold_hung "" compose $COMPOSE_FILES $PROFILE_ARGS
        start_inputs_named_up gateway
        echo "NAMED_RC=$?"
    """), lib_start_inputs=True, extra_env={"COMPOSE_PROJECT_NAME": "noo"})
    out = p.stdout + p.stderr
    assert "FULL_RC=75" in out and "NAMED_RC=0" in out, out
    # every inspect that names the held container is the bounded probe (twice
    # per probe: the first bound, then the second); none is a snapshot call
    for c in calls:
        if HUNG_ID in c and c.startswith("inspect"):
            assert c == f"inspect -f {{{{.State.Status}}}} {HUNG_ID}", c
    snaps = [c for c in calls if c.startswith("inspect -f {{index .Config.Labels")]
    assert snaps and not any(HUNG_ID in c for c in snaps), snaps
    # named gateway: what it needs that is not held starts first, as a stage of its own
    named = [c for c in calls if " up " in f" {c} "][-2:]
    assert named == [f"{UP} postgres redis", f"{UP} gateway"], named


def test_a_slow_docker_is_not_a_held_one(tmp_path):
    p, calls, report, took = _run_hung(tmp_path, textwrap.dedent("""
        noo_hold_hung "" compose $COMPOSE_FILES $PROFILE_ARGS
        echo "ISO=[$NOO_ISOLATED_SERVICES]"
    """), hung=False, extra_env={"SLOW_ID": "ccc333", "SLOW_SECS": "2", "NOO_DOCKER_REPROBE_SECS": "5"})
    out = p.stdout + p.stderr
    assert "ISO=[]" in out and "did not answer" not in out, out


def test_when_docker_cannot_list_containers_nothing_is_started(tmp_path):
    p, calls, report, took = _run_hung(tmp_path, textwrap.dedent("""
        noo_compose_up_isolating_stuck compose $COMPOSE_FILES $PROFILE_ARGS up -d
        echo "RC=$?"
    """), extra_env={"FAKE_PS_HANGS": "1"})
    out = p.stdout + p.stderr
    assert "RC=1" in out and "Docker did not list containers" in out, out
    assert not [c for c in calls if " up " in f" {c} "], "compose is never run unbounded behind a Docker that does not answer"


def test_when_every_container_answers_nothing_is_held_and_up_runs_once(tmp_path):
    p, calls, report, _ = _run_hung(tmp_path, textwrap.dedent("""
        noo_compose_up_isolating_stuck compose $COMPOSE_FILES $PROFILE_ARGS up -d
        echo "RC=$?"
    """), hung=False)
    out = p.stdout + p.stderr
    assert "RC=0" in out, out
    assert "did not answer" not in out
    assert [c for c in calls if " up " in f" {c} "] == ["compose -f a.yml --profile controller up -d"]
    assert not report.exists()


def test_restart_and_the_guard_never_ask_compose_about_a_held_service(tmp_path):
    p, calls, report, took = _run_hung(tmp_path, textwrap.dedent("""
        noo_hold_hung "" compose $COMPOSE_FILES $PROFILE_ARGS
        noo_staged_restart gateway postgres redis loki stunnel-ollama-embed ollama-embed
        echo "RC=$?"
        noo_stack_ps_ids
    """))
    assert "RC=0" in p.stdout, p.stdout + p.stderr
    restarts = [c for c in calls if " restart " in f" {c} "]
    assert restarts[0] == "compose -f a.yml --profile controller restart postgres redis", restarts
    assert not any("ollama-embed" in c for c in restarts)
    ps = [c for c in calls if c.endswith("ps -aq gateway postgres redis loki")]
    assert ps, calls


def test_the_launchers_probe_first_and_the_bound_is_in_the_probe():
    stuck = (SCRIPTS / "lib-stuck-container.sh").read_text()
    assert re.search(r'_noo_bounded "\$NOO_DOCKER_PROBE_SECS" docker inspect -f', stuck)
    start = (SCRIPTS / "noomesh-start.sh").read_text()
    restart = (SCRIPTS / "noomesh-restart.sh").read_text()
    # whole-stack start: probe, then the add-on stop checks, then the up
    assert start.index("noo_hold_hung") < start.index("addons_stop_leftovers addons_stop_disabled")
    assert start.count("noo_hold_hung") >= 2, "whole-stack and named start"
    assert restart.count("noo_hold_hung") >= 2, "whole-stack and named restart"
    assert restart.index("noo_hold_hung") < restart.index('if [ "$FORCE_RECREATE" = true ]')
    si = (SCRIPTS / "lib-start-inputs.sh").read_text()
    full = si[si.index("start_inputs_full_up() {"):si.index("start_inputs_named_up() {")]
    assert full.index("noo_hold_hung") < full.index("start_inputs_snapshot")
    assert "noo_not_held_ids" in si
    for t in (restart, start):
        assert "noo_stack_ps_ids" in t
        assert "ps -aq" not in re.sub(r"#.*", "", t), "guard ids come from noo_stack_ps_ids"
