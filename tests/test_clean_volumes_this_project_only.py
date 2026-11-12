# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""`noo stack clean --volumes/--deep` (scripts/noomesh-clean.sh) removes the
volumes of THIS install's compose project, by exact label, and nothing else.

It filtered `name=pai-assistant` until i677a. The project is `noomesh`, so no
stack volume ever matched, and --volumes/--deep (and `stack reset`, which runs
--deep) removed none. A name glob is not the fix either: a box can run several
stacks, so the filter is docker's exact project label. The functions are
lifted out of the real script and run under bash with a fake `docker`."""
import os
import re
import stat
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "noomesh-clean.sh"


def _fn(name: str) -> str:
    src = SCRIPT.read_text()
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", src, re.S | re.M)
    assert m, f"noomesh-clean.sh has no {name}()"
    return m.group(0)


def _run(tmp_path: Path, body: str, env: dict | None = None, volumes: str = "") -> tuple[str, list[str]]:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    argv_log = tmp_path / "docker.argv"
    fake = bindir / "docker"
    fake.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> "{argv_log}"\n'
        f"printf '%s' '{volumes}'\n"
    )
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    script = "\n".join(_fn(n) for n in ("clean_project", "stack_volumes", "plan_volumes", "print_plan")) + "\n" + body
    e = {"PATH": f"{bindir}:{os.environ['PATH']}"}
    e.update(env or {})
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=e, timeout=30)
    assert out.returncode == 0, out.stderr
    calls = argv_log.read_text().splitlines() if argv_log.exists() else []
    return out.stdout, calls


def test_the_volume_list_is_this_projects_exact_label_and_no_name_glob(tmp_path):
    out, calls = _run(tmp_path, 'stack_volumes "$(clean_project)"', volumes="noomesh_a\nnoomesh_b\n")
    assert out.split() == ["noomesh_a", "noomesh_b"]
    assert calls[0] == "volume ls --filter label=com.docker.compose.project=noomesh --format {{.Name}}"
    assert all(c.startswith("volume inspect") and "noomesh_noo-data" in c for c in calls[1:]), calls
    assert not any("name=" in c for c in calls), "never a name-glob listing"


def test_the_project_is_noomesh_or_the_named_instances(tmp_path):
    out, _ = _run(tmp_path, "clean_project")
    assert out.strip() == "noomesh"
    out, _ = _run(tmp_path, "clean_project", env={"COMPOSE_PROJECT_NAME": "noo-galaxy"})
    assert out.strip() == "noo-galaxy"


def test_the_plan_keeps_models_and_asks_for_stateful_volumes_only_on_deep(tmp_path):
    vols = "noomesh_hf-cache noomesh_postgres-data noomesh_redis-data noomesh_noo-data noomesh_nats"
    out, _ = _run(tmp_path, f"plan_volumes false {vols}")
    assert out.splitlines() == [
        "keep noomesh_hf-cache", "keep noomesh_postgres-data", "keep noomesh_redis-data",
        "keep noomesh_noo-data", "remove noomesh_nats",
    ], "noo-data is stateful (i677 #20): never in the bulk removal"
    out, _ = _run(tmp_path, f"plan_volumes true {vols}")
    assert out.splitlines() == [
        "keep noomesh_hf-cache", "ask noomesh_postgres-data", "ask noomesh_redis-data",
        "ask noomesh_noo-data", "remove noomesh_nats",
    ], "on --deep the stateful volumes are ASKED one by one, never in the bulk removal"


def test_the_volume_section_lists_before_it_asks_and_fails_on_a_survivor():
    src = SCRIPT.read_text()
    assert "name=pai-assistant" not in src.split("# --- Bind-mounted data directories")[0].replace(
        "# The old `name=pai-assistant` filter", ""
    ), "no name-glob volume filter is left"
    sec = src[src.index('if [ "$REMOVE_VOLUMES" = true ]; then'):src.index('ui_done "Volume cleanup complete"')]
    listed = sec.index('printf \'%s\\n\' "$PLAN" | print_plan "$ASSUME_YES"')
    first_ask = sec.index("confirm ")
    first_rm = sec.index("docker volume rm")
    assert listed < first_ask < first_rm, "the plan is printed before any prompt or removal"
    relist = sec.index('stack_volumes "$PROJECT" | grep -qx "$vol"')
    assert relist > first_rm and "exit 1" in sec[relist:], "a volume that survives its removal fails the clean"


def test_under_yes_the_plan_says_the_stateful_volumes_will_be_removed_before_it_happens(tmp_path):
    plan = "keep noomesh_hf-cache\\nask noomesh_postgres-data\\nremove noomesh_nats\\n"
    out, _ = _run(tmp_path, f"printf '{plan}' | print_plan true")
    assert out.splitlines() == [
        "  keep    noomesh_hf-cache",
        "  remove  noomesh_postgres-data (stateful, by -y: ALL of its data)",
        "  remove  noomesh_nats",
    ]
    out, _ = _run(tmp_path, f"printf '{plan}' | print_plan false")
    assert "  ask     noomesh_postgres-data (stateful)" in out.splitlines()


def _confirm_run(tmp_path, assume_yes: str, stdin):
    script = _fn("confirm") + f'ASSUME_YES={assume_yes}\nconfirm "Remove noomesh_postgres-data?" && echo CONFIRMED\necho AFTER\n'
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, stdin=stdin, timeout=20)


def test_without_yes_and_without_a_terminal_the_script_refuses_instead_of_blocking(tmp_path):
    """As the docs say for --json and pipes: refuse, never block on a read
    nobody answers. Same words as the CLI's confirm_prompt."""
    r = _confirm_run(tmp_path, "false", subprocess.PIPE)  # an open pipe nobody writes to
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert "confirmation required: pass --yes (stdin is not a TTY; refusing to block on: Remove noomesh_postgres-data?)" in r.stderr
    assert "CONFIRMED" not in r.stdout and "AFTER" not in r.stdout, "nothing after the refusal runs"


def test_under_yes_the_script_answers_itself_without_a_terminal(tmp_path):
    r = _confirm_run(tmp_path, "true", subprocess.DEVNULL)
    assert r.returncode == 0, r.stderr
    assert r.stdout.splitlines() == ["  Remove noomesh_postgres-data? (y/N) y  [--yes]", "CONFIRMED", "AFTER"]

def _field_docker(tmp_path, noo_data_label: str) -> Path:
    """docker as an existing install shows it: two labelled volumes from the
    label filter, and noomesh_noo-data, labelled or not."""
    bindir = tmp_path / "fbin"
    bindir.mkdir()
    fake = bindir / "docker"
    labelled = "noomesh_postgres-data\nnoomesh_nats\n" + ("noomesh_noo-data\n" if noo_data_label else "")
    fake.write_text(
        "#!/bin/sh\n"
        'case "$1 $2" in\n'
        f"  'volume ls') printf '{labelled}' ;;\n"
        '  "volume inspect") case "$*" in *noomesh_noo-data*) ;; *) exit 1 ;; esac\n'
        f'    case "$*" in *Labels*) printf "%s\\n" "{noo_data_label}" ;; esac ;;\n'
        "esac\nexit 0\n"
    )
    fake.chmod(0o755)
    return bindir


def _field_plan(tmp_path, label: str) -> list[str]:
    bindir = _field_docker(tmp_path, label)
    script = "\n".join(_fn(n) for n in ("clean_project", "stack_volumes", "plan_volumes")) + \
        '\nplan_volumes false $(stack_volumes "$(clean_project)")\n'
    e = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}
    e.pop("COMPOSE_PROJECT_NAME", None)
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=e, timeout=30)
    assert out.returncode == 0, out.stderr
    return out.stdout.splitlines()


def test_an_existing_installs_unlabelled_noo_data_is_in_the_plan_once(tmp_path):
    """i677: the launcher created <project>_noo-data outside compose, so on
    every existing install it has no project label. It is planned by its exact
    name, beside the labelled ones; a labelled one is not listed twice."""
    assert _field_plan(tmp_path, "") == [
        "keep noomesh_postgres-data", "remove noomesh_nats", "keep noomesh_noo-data",
    ]
    (tmp_path / "b").mkdir()
    assert _field_plan(tmp_path / "b", "noomesh") == [
        "keep noomesh_postgres-data", "remove noomesh_nats", "keep noomesh_noo-data",
    ]


def _gate_run(tmp_path, docker_body: str | None):
    """Run the REAL script up to (at most) its first step with a fake docker
    and fake helpers, so only the gate decides. The fake docker logs calls."""
    bindir = tmp_path / "gbin"
    bindir.mkdir()
    log = tmp_path / "calls.log"
    if docker_body is not None:
        d = bindir / "docker"
        d.write_text("#!/bin/sh\n" + f'printf "%s\\n" "$*" >> "{log}"\n' + docker_body)
        d.chmod(0o755)
    src = SCRIPT.read_text()
    i = src.index("# i677 #20: docker must ANSWER")
    j = src.index("\nfi\n", i) + 4
    script = src[i:j] + 'echo "PAST THE GATE"\n'
    env = {"PATH": f"{bindir}:/usr/bin:/bin"}
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=30)
    calls = log.read_text().splitlines() if log.exists() else []
    return r, calls


def test_a_docker_that_does_not_answer_stops_the_clean_before_anything(tmp_path):
    r, calls = _gate_run(tmp_path, 'echo "permission denied while trying to connect to the docker API at unix:///var/run/docker.sock" >&2\nexit 1\n')
    assert r.returncode == 1 and "PAST THE GATE" not in r.stdout
    assert "cannot reach docker (permission denied while trying to connect to the docker API" in r.stderr
    assert "nothing was removed" in r.stderr and "newgrp docker" in r.stderr and "sudo noo stack clean" in r.stderr
    assert calls == ["info --format {{.ServerVersion}}"], "nothing but the probe ran"


def test_a_daemon_that_is_down_stops_the_clean_too(tmp_path):
    r, _ = _gate_run(tmp_path, 'echo "" >&2; echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?" >&2\nexit 1\n')
    assert r.returncode == 1
    assert "cannot reach docker (Cannot connect to the Docker daemon" in r.stderr


def test_an_answering_docker_or_no_docker_at_all_passes_the_gate(tmp_path):
    r, _ = _gate_run(tmp_path, 'echo 29.0.1\nexit 0\n')
    assert r.returncode == 0 and "PAST THE GATE" in r.stdout
    (tmp_path / "b").mkdir()
    r, _ = _gate_run(tmp_path / "b", None)
    assert r.returncode == 0 and "PAST THE GATE" in r.stdout, "no docker binary: a positive answer, the files are still cleaned"


def test_the_gate_comes_before_every_removal_in_the_script():
    src = SCRIPT.read_text()
    gate = src.index("# i677 #20: docker must ANSWER")
    for needle in ["docker compose", "docker volume rm", "docker image prune", "remove_secret_files", "untrust-ca", "rm -rf"]:
        k = src.find(needle)
        assert k == -1 or k > gate, f"{needle} runs before the gate"
