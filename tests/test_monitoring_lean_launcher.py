# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Grafana, Loki and Tempo run unless noomesh.yaml says `cluster.monitoring: lean`.

THE RULE: the fleet controller is itself a standalone-profile install
(tests/test_monitoring_profile_parity.py), so the profile cannot tell a
one-machine install from the fleet. A MISSING decision must mean FULL: the
launcher adds `--profile monitoring` unless the declaration is exactly `lean`.
Planted mutant (unset read as lean): in lib-config.sh `monitoring_level`,
`lean) printf 'lean' ;;` -> `lean|"") printf 'lean' ;;` turns
`test_unset_is_full` and `test_no_noomesh_yaml_is_full` red.

The helpers run for real under bash, reading the yaml through the same chain
the launcher uses (a fake `noo config launch-render monitoring`, else python3).
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "scripts" / "lib-config.sh"
SCRIPTS = ROOT / "scripts"


def _bash(tmp_path: Path, body: str, yaml: str | None, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    if yaml is not None:
        (tmp_path / "noomesh.yaml").write_text(yaml)
    env = {k: v for k, v in os.environ.items() if k not in ("COMPOSE_PROFILES", "NOO_CLI_BIN", "NOO_CONTAINER_PREFIX")}
    # No `noo` on PATH: the python3 fallback reads the file (a test box has
    # PyYAML; the launcher's own fallback order is noo, then python3).
    env["PATH"] = ":".join(p for p in env.get("PATH", "").split(":") if not (Path(p) / "noo").exists())
    env.update(env_extra or {})
    return subprocess.run(["bash", "-c", f". {LIB}\n{body}"], cwd=tmp_path, env=env,
                          capture_output=True, text=True, timeout=30)


def _profile(tmp_path: Path, yaml: str | None, **kw) -> subprocess.CompletedProcess:
    return _bash(tmp_path, "monitoring_profile_args", yaml, **kw)


def test_unset_is_full(tmp_path):
    r = _profile(tmp_path, "cluster:\n  default_backend: vllm\n")
    assert r.returncode == 0, r
    assert r.stdout == "--profile monitoring", "an install that never chose must keep Grafana, Loki and Tempo"


def test_no_noomesh_yaml_is_full(tmp_path):
    assert _profile(tmp_path, None).stdout == "--profile monitoring"


def test_lean_leaves_the_three_out(tmp_path):
    r = _profile(tmp_path, "cluster:\n  monitoring: lean\n")
    assert r.returncode == 0, r
    assert r.stdout == ""


def test_full_and_a_typo_are_full(tmp_path):
    assert _profile(tmp_path, "cluster:\n  monitoring: full\n").stdout == "--profile monitoring"
    r = _profile(tmp_path, "cluster:\n  monitoring: lena\n")
    assert r.stdout == "--profile monitoring"
    assert "neither full nor lean" in r.stderr


def test_only_the_cluster_key_counts(tmp_path):
    assert _profile(tmp_path, "monitoring: lean\n").stdout == "--profile monitoring"
    assert _profile(tmp_path, "cluster:\n  backends:\n    monitoring: lean\n").stdout == "--profile monitoring"


def test_an_environment_variable_is_not_the_switch(tmp_path):
    r = _profile(tmp_path, "cluster:\n  default_backend: vllm\n",
                 env_extra={"NOO_MONITORING": "lean", "CLUSTER_MONITORING": "lean"})
    assert r.stdout == "--profile monitoring"


def test_compose_profiles_listing_monitoring_wins_and_says_so(tmp_path):
    r = _bash(tmp_path, 'printf "%s|%s" "$(monitoring_profile_args)" "$(operator_profile_args)"',
              "cluster:\n  monitoring: lean\n", env_extra={"COMPOSE_PROFILES": "embed-cpu,monitoring"})
    assert r.stdout == "|--profile embed-cpu --profile monitoring", r
    assert "COMPOSE_PROFILES lists monitoring, which wins over cluster.monitoring: lean" in r.stderr


def _fake_noo(tmp_path: Path, script: str) -> str:
    noo = tmp_path / "fake-noo"
    noo.write_text("#!/bin/bash\n" + script)
    noo.chmod(0o755)
    return str(noo)


def test_the_noo_renderer_is_read_first(tmp_path):
    # The yaml says full; the CLI's renderer (the ONE parser) says lean: the
    # launcher believes the CLI, proving it asked it.
    noo = _fake_noo(tmp_path, '[ "$1 $2 $3" = "config launch-render monitoring" ] && { echo lean; exit 0; }\nexit 64\n')
    r = _profile(tmp_path, "cluster:\n  monitoring: full\n", env_extra={"NOO_CLI_BIN": noo})
    assert r.stdout == "", r


def test_an_older_noo_without_the_section_falls_back_to_python(tmp_path):
    noo = _fake_noo(tmp_path, 'echo "x Unknown command" >&2\nexit 2\n')
    assert _profile(tmp_path, "cluster:\n  monitoring: lean\n", env_extra={"NOO_CLI_BIN": noo}).stdout == ""
    assert _profile(tmp_path, "cluster: {}\n", env_extra={"NOO_CLI_BIN": noo}).stdout == "--profile monitoring"


@pytest.mark.parametrize("svc", ["grafana", "loki", "tempo", "noo-grafana"])
def test_a_named_start_of_grafana_loki_or_tempo_on_lean_is_refused(tmp_path, svc):
    r = _bash(tmp_path, f'monitoring_refuse_named "--profile standalone" gateway {svc}; echo "rc=$?"',
              "cluster:\n  monitoring: lean\n")
    assert r.stdout.strip() == "rc=1", r
    assert "is off on this install (cluster.monitoring: lean in noomesh.yaml); nothing was started" in r.stderr
    assert "noo stack monitoring on" in r.stderr


@pytest.mark.parametrize("yaml,profile_args,svc", [
    ("cluster:\n  default_backend: vllm\n", "--profile standalone --profile monitoring", "grafana"),
    ("cluster:\n  monitoring: lean\n", "--profile standalone", "gateway"),
    ("cluster:\n  monitoring: lean\n", "--profile controller", "grafana"),
    ("cluster:\n  monitoring: lean\n", "--profile standalone --profile monitoring", "grafana"),
])
def test_named_starts_that_are_not_refused(tmp_path, yaml, profile_args, svc):
    r = _bash(tmp_path, f'monitoring_refuse_named "{profile_args}" {svc}; echo "rc=$?"', yaml)
    assert r.stdout.strip() == "rc=0", r


FAKE_DOCKER = r"""#!/bin/bash
echo "docker $*" >> "$DOCKER_LOG"
case "$*" in
  *"com.docker.compose.service=grafana"*) echo cid-grafana ;;
  *"com.docker.compose.service=loki"*) echo cid-loki ;;
esac
exit 0
"""


def _remove(tmp_path: Path, yaml: str, active: str) -> tuple[subprocess.CompletedProcess, str]:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "docker").write_text(FAKE_DOCKER)
    (bindir / "docker").chmod(0o755)
    log = tmp_path / "docker.log"
    log.write_text("")
    r = _bash(tmp_path, f'export PATH="{bindir}:$PATH"\nmonitoring_remove_when_lean "{active}"', yaml,
              env_extra={"DOCKER_LOG": str(log)})
    return r, log.read_text()


def test_lean_removes_leftover_containers_and_keeps_data(tmp_path):
    r, log = _remove(tmp_path, "cluster:\n  monitoring: lean\n", "gateway\nprometheus")
    assert "docker stop cid-loki" in log and "docker rm cid-loki" in log, log
    assert "docker stop cid-grafana" in log and "docker rm cid-grafana" in log, log
    assert " -v" not in log and "volume" not in log, "containers only; the data stays"
    assert "removed loki grafana (data kept" in r.stdout, r


def test_full_removes_nothing(tmp_path):
    _, log = _remove(tmp_path, "cluster:\n  default_backend: vllm\n", "gateway")
    assert log == ""


def test_lean_under_the_controller_profile_removes_nothing_it_manages(tmp_path):
    # The controller profile projects the three: they are in this up's set.
    _, log = _remove(tmp_path, "cluster:\n  monitoring: lean\n", "gateway\nloki\ntempo\ngrafana")
    assert "docker stop" not in log and "docker rm" not in log, log


@pytest.mark.parametrize("script", ["noomesh-start.sh", "noomesh-restart.sh", "noomesh-rebuild.sh"])
def test_every_launcher_adds_the_monitoring_profile(script):
    assert "$(monitoring_profile_args)" in (SCRIPTS / script).read_text(), script


@pytest.mark.parametrize("script", ["noomesh-start.sh", "noomesh-restart.sh", "noomesh-rebuild.sh"])
def test_every_launcher_refuses_a_named_optional_service_on_lean(script):
    assert re.search(r'monitoring_refuse_named "\$PROFILE_ARGS" .*\|\| exit 1', (SCRIPTS / script).read_text()), script


def test_a_named_restart_refuses_before_anything_runs():
    """`noo stack restart grafana` on a lean install: the refusal comes after
    PROFILE_ARGS has the declaration and before the names are resolved or
    compose is asked to `up`/`restart` anything."""
    src = (SCRIPTS / "noomesh-restart.sh").read_text()
    named = src[src.index('    ui_phase "Stack"\n    # Names resolve'):]
    refuse = named.index('monitoring_refuse_named "$PROFILE_ARGS" "${SERVICES[@]}" || exit 1')
    assert refuse < named.index("restart_resolve_all")
    assert refuse < named.index("up -d --no-build --no-deps")
    assert refuse < named.index(" restart \"${_present[@]}\"")
    assert src.index("$(monitoring_profile_args)") < src.index('    ui_phase "Stack"\n    # Names resolve')


def test_start_removes_lean_leftovers_after_the_up():
    src = (SCRIPTS / "noomesh-start.sh").read_text()
    up = src.index("noo_compose_up_isolating_stuck compose $COMPOSE_FILES $PROFILE_ARGS up -d --force-recreate")
    assert up < src.index('monitoring_remove_when_lean "$ACTIVE_SVCS"')
    # The monitoring profile is in PROFILE_ARGS before the active set is read.
    assert src.index('_mon_profile="$(monitoring_profile_args)"') < src.index("compose_active_services $COMPOSE_FILES $PROFILE_ARGS")


def test_the_launcher_never_reads_an_environment_switch_for_it():
    lib = LIB.read_text()
    body = lib[lib.index("monitoring_setting() {"):]
    assert "NOO_MONITORING" not in body and "${MONITORING" not in body
