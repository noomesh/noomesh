# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""One container Docker does not answer for must not take the stack down
(scripts/lib-stuck-container.sh; controller, 2026-11-25).

A container whose process survived SIGKILL: from then on every docker call
naming it (`docker inspect` included, and any compose call that touches it)
never returned. These tests run the REAL scripts/noomesh-start.sh and
noomesh-restart.sh in a scratch install against the stateful fake `docker` in
tests/fake_docker_held.py (a call that names the held container sleeps 60 s;
the test deadline is shorter, so a launcher that waits on it FAILS the test),
and assert on the recorded docker calls and the exit code. Nothing real is
touched.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HUNG = "9f3e1d2c0000"
DEADLINE = 90  # the fake sleeps 60 s on anything that touches the held container
QUICK = 30  # a launcher that waits on the held container takes 60 s or more; a loaded host takes a fraction of this

CFG = {"services": {
    "gateway": {"depends_on": {"postgres": {"condition": "service_healthy"}, "redis": {"condition": "service_healthy"}}},
    "postgres": {}, "redis": {}, "loki": {}, "node-agent": {},
    "embed-user": {"depends_on": {"ollama-embed": {"condition": "service_started"}}},
    "stunnel-ollama-embed": {},
    "ollama-embed": {"network_mode": "service:stunnel-ollama-embed",
                     "depends_on": {"stunnel-ollama-embed": {"condition": "service_started", "restart": True}}},
}}

FAKE_SOPS = """#!/bin/sh
for k in POSTGRES_PASSWORD NOO_JWT_SECRET NOO_CLUSTER_SECRET NOO_BUS_KEY_WORKER \\
         NOO_BUS_KEY_TRELLION NOO_BUS_KEY_TRELLION_INTEL NOO_BROWSER_KEY GRAFANA_PASSWORD REDIS_PASSWORD NOO_AUDIT_HMAC_KEY; do
  echo "$k=x$k"
done
exit 0
"""


def _containers(held: bool, extra=()):
    base = [
        ("gw0000000001", "noo-gateway", "gateway"), ("pg0000000002", "noo-postgres", "postgres"),
        ("rd0000000003", "noo-redis", "redis"), ("lk0000000004", "noo-loki", "loki"),
        ("st0000000005", "noo-stunnel-ollama-embed", "stunnel-ollama-embed"),
        (HUNG, "noo-ollama-embed", "ollama-embed"),
    ]
    out = [{"id": i, "name": n, "service": s, "project": "noomesh", "status": "running"} for i, n, s in base]
    out += list(extra)
    return out


class Install:
    """A scratch dev install with the real scripts and a fake docker."""

    def __init__(self, tmp: Path, *, held: bool = True, cfg: dict | None = None, extra_containers=(), services=None,
                 up_leaves_created=(), reown_dir: bool = False):
        self.tmp = tmp
        self.work, self.bin = tmp / "w", tmp / "bin"
        self.bin.mkdir()
        shutil.copytree(ROOT / "scripts", self.work / "scripts")
        for f in ROOT.glob("docker-compose*.yml"):
            shutil.copy(f, self.work / f.name)
        shutil.copy(ROOT / "tests" / "fake_docker_held.py", self.bin / "docker")
        for name, body in {"sops": FAKE_SOPS, "noo": "#!/bin/sh\ncat >/dev/null 2>&1 || true\nexit 0\n",
                           "ss": "#!/bin/sh\nexit 1\n"}.items():
            (self.bin / name).write_text(body)
        for f in self.bin.iterdir():
            f.chmod(0o755)
        cfg = cfg or CFG
        self.state_path = tmp / "state.json"
        state = {
            "containers": _containers(held, extra_containers),
            "hung": HUNG if held else None,
            "touch_hang": ["ollama-embed", "stunnel-ollama-embed"] if held else [],
            "services": services or ["gateway", "postgres", "redis", "loki", "stunnel-ollama-embed", "ollama-embed", "node-agent", "embed-user"],
            "volumes": ["noomesh_ollama-embed-data"] if reown_dir else [],
            "cfg": json.dumps(cfg),
            "up_leaves_created": list(up_leaves_created),
        }
        self.state_path.write_text(json.dumps(state))
        (self.work / "noomesh.yaml").write_text("compose_env: {}\n")
        (self.work / "secrets").mkdir()
        (self.work / "secrets" / "env.sops").write_text("x\n")
        (tmp / "data").mkdir()
        # The re-own helper hook (lib-reown.sh NOO_REOWN_CMD): the probe finds
        # one path until the chown has run.
        reown = tmp / "reown.sh"
        reown.write_text('''#!/bin/sh
case "$2" in
  find*) [ -f "$0.done" ] || echo /d/x ;;
  chown*) touch "$0.done" ;;
esac
''')
        reown.chmod(0o755)
        (self.work / ".env").write_text(f"NOO_DATA_ROOT={tmp / 'data'}\nNOO_BIND_MODE=local\nNOO_SECRETS_BACKEND=sops\n")
        self.log = tmp / "docker.log"

    def run(self, script: str, *args: str, env: dict | None = None):
        e = {
            "PATH": f"{self.bin}:{os.environ['PATH']}", "HOME": str(self.tmp),
            "FAKE_STATE": str(self.state_path), "FAKE_LOG": str(self.log),
            "NOO_CLI_BIN": str(self.bin / "noo"), "NOO_STUCK_REPORT": str(self.tmp / "report"),
            "NOO_DOCKER_PROBE_SECS": "1", "NOO_DOCKER_REPROBE_SECS": "1", "NOO_STAGE_WAIT_SECS": "3",
            "NOO_CREATED_GUARD_WAIT": "1", "NO_COLOR": "1", "LC_ALL": "C",
        }
        e.update(env or {})
        t0 = time.time()
        p = subprocess.run(["bash", f"scripts/{script}", *args], cwd=self.work, env=e, capture_output=True, text=True,
                           timeout=DEADLINE + 20, stdin=subprocess.DEVNULL)
        took = time.time() - t0
        calls = self.log.read_text().splitlines() if self.log.exists() else []
        return p, calls, took

    def state(self):
        return json.loads(self.state_path.read_text())



RESTART_ONLY_CFG = {"services": {
    "gateway": {"depends_on": {"postgres": {"condition": "service_healthy"}}},
    "postgres": {}, "redis": {}, "loki": {}, "node-agent": {},
    "stunnel-ollama-embed": {},
    # only the `restart: true` relation: no network_mode link
    "ollama-embed": {"depends_on": {"stunnel-ollama-embed": {"condition": "service_started", "restart": True}}},
}}

HELD_MSG = "Docker did not answer for noo-ollama-embed (ollama-embed)"


def compose_calls(calls, verb):
    return [c for c in calls if c.startswith("compose ") and f" {verb} " in f"{c} "]


def untouched(calls):
    """No compose or container call names the held container or its door."""
    bad = []
    for c in calls:
        if c.startswith("compose ") and (" config " in f"{c} "):
            continue
        if c.startswith("compose ") and ("ollama-embed" in c.split(" --profile ")[-1] or "ollama-embed" in c):
            bad.append(c)
        if c.split(" ")[0] in ("start", "stop", "rm", "restart", "logs") and ("ollama-embed" in c or HUNG in c):
            bad.append(c)
    return bad


def snapshot_inspects(calls):
    return [c for c in calls if c.startswith("inspect -f {{index .Config.Labels")]


def test_full_start_with_one_held_container(tmp_path):
    ins = Install(tmp_path)
    p, calls, took = ins.run("noomesh-start.sh")
    out = p.stdout + p.stderr
    assert p.returncode == 75, out
    assert took < QUICK, took
    assert untouched(calls) == [], untouched(calls)
    ups = compose_calls(calls, "up")
    # data stores first (waited for), then the rest by layer; node-agent is scaled out
    assert [u.split(" up ")[1].split(" ")[-2:] for u in ups][0] == ["postgres", "redis"], ups
    assert all("--no-deps" in u for u in ups), ups
    assert not any("node-agent" in u.split(" up ")[1].replace("--scale node-agent=0", "") for u in ups), ups
    # (a whole-stack start brings up everything that is not held or linked to it;
    # embed-user merely depends_on the held service and is started with --no-deps)
    assert sorted(ups[-1].split(" ")[-3:]) == ["embed-user", "gateway", "loki"], ups
    # nothing inspected the held container except the two bounded probes
    assert [c for c in calls if HUNG in c] == [f"inspect -f {{{{.State.Status}}}} {HUNG}"] * 2, [c for c in calls if HUNG in c]
    assert snapshot_inspects(calls) and not any(HUNG in c for c in snapshot_inspects(calls))
    assert HELD_MSG in out and "only a reboot of this host removes it" in out
    assert "not touching stunnel-ollama-embed" in out
    assert (tmp_path / "report").read_text().split() == ["ollama-embed", HUNG]


@pytest.mark.parametrize("force", [False, True])
def test_whole_stack_restart_with_one_held_container(tmp_path, force):
    ins = Install(tmp_path)
    p, calls, took = ins.run("noomesh-restart.sh", *(["--force"] if force else []))
    out = p.stdout + p.stderr
    assert p.returncode == 75, out
    assert took < QUICK, took
    assert untouched(calls) == [], untouched(calls)
    verb = "up" if force else "restart"
    stages = compose_calls(calls, verb)
    assert stages[0].split(f" {verb} ")[1].split(" ")[-2:] == ["postgres", "redis"], stages
    assert not any(f" {verb} " in f"{c} " and c.rstrip().endswith(f" {verb}") for c in calls), "never a restart/up with no service names"
    assert HELD_MSG in out and "NOT running" in out


@pytest.mark.parametrize("script,verb", [("noomesh-start.sh", "up"), ("noomesh-restart.sh", "restart")])
@pytest.mark.parametrize("named,rc,touches", [
    ("ollama-embed", 75, False),           # the held service itself
    ("stunnel-ollama-embed", 75, False),   # its door: compose would restart the held one
    ("embed-user", 75, False),             # needs the held one
    ("loki", 0, True),                     # unrelated
    ("gateway", 0, True),                  # needs postgres and redis, which are not held
])
def test_named_start_and_restart_with_one_held_container(tmp_path, script, verb, named, rc, touches):
    ins = Install(tmp_path)
    p, calls, took = ins.run(script, named)
    out = p.stdout + p.stderr
    assert p.returncode == rc, out
    assert took < QUICK, took
    assert untouched(calls) == [], untouched(calls)
    stages = compose_calls(calls, verb)
    if not touches:
        assert stages == [], stages
    elif named == "gateway" and verb == "up":
        # what it needs that is not held starts first, as a stage of its own
        assert [x.split(" up ")[1].split(" ")[-1] for x in stages] == ["redis", "gateway"] or \
            [x.split(" up ")[1].split(" ")[-2:] for x in stages][0] == ["postgres", "redis"], stages
    else:
        assert stages and stages[-1].endswith(named), stages


@pytest.mark.parametrize("script,args", [("noomesh-start.sh", []), ("noomesh-restart.sh", []), ("noomesh-restart.sh", ["--force"])])
def test_nothing_held_is_one_unchanged_compose_call(tmp_path, script, args):
    ins = Install(tmp_path, held=False)
    p, calls, took = ins.run(script, *args)
    assert p.returncode == 0, p.stdout + p.stderr
    verb = "restart" if script.endswith("restart.sh") and "--force" not in args else "up"
    stages = compose_calls(calls, verb)
    assert len(stages) == 1, stages
    assert "--no-deps" not in stages[0] and " ps " not in stages[0]
    assert "did not answer" not in p.stdout + p.stderr


@pytest.mark.parametrize("script", ["noomesh-start.sh", "noomesh-restart.sh"])
def test_docker_not_listing_containers_starts_nothing(tmp_path, script):
    ins = Install(tmp_path)
    p, calls, took = ins.run(script, env={"FAKE_PS_HANGS": "1"})
    out = p.stdout + p.stderr
    assert p.returncode == 1, out
    assert "Docker did not list containers" in out
    assert compose_calls(calls, "up") == [] and compose_calls(calls, "restart") == []
    assert took < QUICK, took


def test_created_leftovers_of_another_project_or_scaled_out_are_not_started(tmp_path):
    extra = [
        {"id": "ot0000000009", "name": "other-redis", "service": "redis", "project": "other", "status": "created"},
        {"id": "na0000000008", "name": "noo-node-agent", "service": "node-agent", "project": "noomesh", "status": "created"},
        # linked to the held container: left out, so never started even though it is Created
    ]
    ins = Install(tmp_path, extra_containers=extra, up_leaves_created=["loki"])
    # the door itself is Created and left out: the sweep must not start it
    st = ins.state()
    for c in st["containers"]:
        if c["name"] == "noo-stunnel-ollama-embed":
            c["status"] = "created"
    ins.state_path.write_text(json.dumps(st))
    p, calls, took = ins.run("noomesh-start.sh")
    assert p.returncode == 75, p.stdout + p.stderr
    started = [c for c in calls if c.startswith("start ")]
    assert "start noo-loki" in started, calls          # left in Created by the up: started by name
    assert not any(x in " ".join(started) for x in ("other-redis", "noo-node-agent", "stunnel", "ollama-embed")), started


def test_a_store_needing_re_owning_on_the_held_service_does_not_bring_the_hang_back(tmp_path):
    ins = Install(tmp_path, reown_dir=True)
    p, calls, took = ins.run("noomesh-start.sh", env={"NOO_REOWN_CMD": str(tmp_path / "reown.sh")})
    out = p.stdout + p.stderr
    assert p.returncode == 75, out
    assert took < QUICK, took
    assert untouched(calls) == [], untouched(calls)
    assert "not re-owning" in out, out


def test_the_restart_true_relation_alone_leaves_the_door_out(tmp_path):
    ins = Install(tmp_path, cfg=RESTART_ONLY_CFG, services=["gateway", "postgres", "redis", "loki", "node-agent", "stunnel-ollama-embed", "ollama-embed"])
    p, calls, took = ins.run("noomesh-restart.sh")
    out = p.stdout + p.stderr
    assert p.returncode == 75, out
    assert took < QUICK, took
    assert untouched(calls) == [], untouched(calls)
    assert "stunnel-ollama-embed (compose restarts ollama-embed with it)" in out, out


def test_a_slow_docker_is_not_a_held_one(tmp_path):
    ins = Install(tmp_path, held=False)
    p, calls, took = ins.run("noomesh-restart.sh", env={"FAKE_SLOW_ID": "rd0000000003", "FAKE_SLOW_SECS": "2",
                                                       "NOO_DOCKER_REPROBE_SECS": "6"})
    assert p.returncode == 0, p.stdout + p.stderr
    assert "did not answer" not in p.stdout + p.stderr


def test_exit_code_is_75_when_the_rest_came_up_and_1_when_a_non_held_service_did_not(tmp_path):
    ins = Install(tmp_path)
    p, calls, took = ins.run("noomesh-start.sh", env={"FAKE_UP_RC": "1"})
    assert p.returncode == 75, "a stage's own exit code does not matter when everything it brought up is up: " + p.stdout + p.stderr
    (tmp_path / "second").mkdir()
    ins2 = Install(tmp_path / "second", up_leaves_created=["loki"])
    p2, calls2, _ = ins2.run("noomesh-start.sh", env={"FAKE_START_FAILS": "1"})
    assert p2.returncode == 1, p2.stdout + p2.stderr
    assert "did not come up: loki" in p2.stdout + p2.stderr


# --- library level: the snapshot, the bound, fail-closed ---------------------

def _lib(ins: Install, body: str, env: dict | None = None):
    scripts = ins.work / "scripts"
    script = f"""
        . {scripts}/lib-ui.sh
        . {scripts}/lib-stuck-container.sh
        . {scripts}/lib-start-inputs.sh
        start_inputs_prepare() {{ START_UP_FORCE=""; return 0; }}
        _compose_project_name() {{ echo noomesh; }}
        start_inputs_report() {{ rm -f "$1" "$2"; return 0; }}
        COMPOSE_FILES="-f a.yml"; PROFILE_ARGS="--profile controller"
        {body}
    """
    e = {"PATH": f"{ins.bin}:/usr/bin:/bin", "FAKE_STATE": str(ins.state_path), "FAKE_LOG": str(ins.log),
         "NOO_DOCKER_PROBE_SECS": "1", "NOO_DOCKER_REPROBE_SECS": "1", "NOO_STAGE_WAIT_SECS": "3", "NO_COLOR": "1", "LC_ALL": "C"}
    e.update(env or {})
    t0 = time.time()
    p = subprocess.run(["bash", "-c", script], env=e, capture_output=True, text=True, timeout=DEADLINE)
    calls = ins.log.read_text().splitlines() if ins.log.exists() else []
    return p, calls, time.time() - t0


def test_the_snapshot_functions_never_inspect_the_held_container(tmp_path):
    ins = Install(tmp_path)
    p, calls, took = _lib(ins, """
        start_inputs_full_up --build
        echo "FULL_RC=$?"
        NOO_PROBE_DONE=""
        noo_hold_hung "" compose $COMPOSE_FILES $PROFILE_ARGS
        start_inputs_named_up gateway
        echo "NAMED_RC=$?"
    """)
    out = p.stdout + p.stderr
    assert "FULL_RC=75" in out and "NAMED_RC=0" in out, out
    assert took < QUICK, took  # two probe rounds and two stages; the fake sleeps 60 s
    assert [c for c in calls if HUNG in c and c.startswith("inspect")] == [f"inspect -f {{{{.State.Status}}}} {HUNG}"] * 4
    assert snapshot_inspects(calls) and not any(HUNG in c for c in snapshot_inspects(calls))
    assert [c.split(" up ")[1] for c in compose_calls(calls, "up")][-2:] == ["--no-deps -d postgres redis", "--no-deps -d gateway"]


def test_a_bounded_call_is_never_run_unbounded_when_it_cannot_be_bounded(tmp_path):
    ins = Install(tmp_path)
    p, calls, _ = _lib(ins, '_noo_bounded 1 docker ps -a; echo "RC=$?"', env={"TMPDIR": str(tmp_path / "no" / "such" / "dir")})
    assert "RC=125" in p.stdout, p.stdout + p.stderr
    assert calls == [], "the command must not run at all"


def test_the_relations_are_read_from_the_config_not_a_list(tmp_path):
    ins = Install(tmp_path)
    cfg = json.dumps(CFG)
    p, calls, _ = _lib(ins, f"""
        _NOO_CFG_JSON='{cfg}'
        _noo_rel excluded stunnel-ollama-embed
        _noo_rel excluded ollama-embed
        _noo_rel closure gateway
        _noo_rel layers gateway postgres redis loki
    """)
    lines = p.stdout.splitlines()
    assert lines[0] == "ollama-embed\tit shares the network namespace of stunnel-ollama-embed", p.stdout + p.stderr
    assert lines[1] == "stunnel-ollama-embed\tollama-embed joins its network namespace"
    assert sorted(lines[2].split()) == ["gateway", "postgres", "redis"]
    assert lines[3:] == ["postgres redis loki", "gateway"]


def test_launchers_probe_before_every_step_that_touches_a_container():
    start = (ROOT / "scripts" / "noomesh-start.sh").read_text()
    full = start[:start.index("Specific services requested")]
    assert full.index("noo_hold_hung") < full.index('    reown_nonroot_dirs "${_state_root') < full.index("compose_remove_retired .")
    assert full.index("noo_hold_hung") < full.index("addons_stop_leftovers addons_stop_disabled")
    named = start[start.index("Specific services requested"):]
    assert named.index("noo_hold_hung") < named.index('reown_nonroot_dirs "${_state_root')
    restart = (ROOT / "scripts" / "noomesh-restart.sh").read_text()
    assert restart.index("noo_hold_hung") < restart.index("compose_remove_retired .")


def test_a_held_store_the_gateway_needs_says_the_controller_is_not_up(tmp_path):
    ins = Install(tmp_path)
    st = ins.state()
    st["hung"] = "rd0000000003"                       # redis
    st["touch_hang"] = ["redis"]
    ins.state_path.write_text(json.dumps(st))
    p, calls, took = ins.run("noomesh-restart.sh")
    out = p.stdout + p.stderr
    assert p.returncode == 75, out
    assert "THE CONTROLLER IS NOT UP: noo-redis (redis) is held and the gateway needs it" in out, out
    assert took < QUICK, took
    # and the held embedder (which the gateway does not need) does not say it
    ins2 = Install(tmp_path / "b") if (tmp_path / "b").mkdir() is None else None
    p2, _, _ = ins2.run("noomesh-restart.sh")
    assert "THE CONTROLLER IS NOT UP" not in p2.stdout + p2.stderr


def test_an_unhealthy_gateway_after_a_held_start_is_said(tmp_path):
    ins = Install(tmp_path)
    p, calls, took = ins.run("noomesh-restart.sh", env={"FAKE_UNHEALTHY": "gateway"})
    out = p.stdout + p.stderr
    assert p.returncode == 75, out
    assert "the gateway is up but not healthy (unhealthy): it may be restarting" in out, out


def test_a_probe_that_cannot_be_bounded_stops_the_launch(tmp_path):
    ins = Install(tmp_path)
    p, calls, _ = _lib(ins, 'noo_hold_hung "" compose $COMPOSE_FILES $PROFILE_ARGS; echo "RC=$?"',
                       env={"TMPDIR": str(tmp_path / "no" / "such")})
    assert "RC=3" in p.stdout, p.stdout + p.stderr
    assert not [c for c in calls if c.startswith("inspect")], calls


def test_the_probe_lists_the_launchers_own_project(tmp_path):
    ins = Install(tmp_path)
    p, calls, _ = _lib(ins, f"""
        . {ins.work}/scripts/lib-compose.sh
        cd {ins.work}
        _noo_project""")
    want = (ins.work / "docker-compose.cluster.yml").read_text()
    import re
    m = re.search(r"^name:\s*(\S+)", want, re.M)
    assert p.stdout.strip() == (m.group(1) if m else "noomesh"), p.stdout + p.stderr


def test_a_reown_stop_that_times_out_refuses_instead_of_chowning_on(tmp_path):
    scripts = ROOT / "scripts"
    r = subprocess.run(["bash", "-c", f"""
        . {scripts}/lib-reown.sh
        NOO_REOWN_CMD={tmp_path}/reown.sh
        printf '#!/bin/sh\\ncase "$2" in find*) [ -f "$0.done" ] || echo /d/x ;; chown*) touch "$0.done" ;; esac\\n' > {tmp_path}/reown.sh
        chmod +x {tmp_path}/reown.sh
        mkdir -p {tmp_path}/root/redis
        reown_stop_service() {{ return 124; }}
        reown_nonroot_dirs {tmp_path}/root redis; echo "RC=$?"
    """], capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
    assert "RC=1" in r.stdout and "did not stop in time" in r.stderr, r.stdout + r.stderr
    assert not (tmp_path / "reown.sh.done").exists(), "the chown must not run"
