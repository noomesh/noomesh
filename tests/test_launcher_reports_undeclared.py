# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A whole-stack `up` reports containers no compose file declares, and never
reaps them (noomesh-internal 186b, plan 2026-10-30, PR a).

`noo-cluster-executor` kept running for two days after #98 deleted it, because
compose does not stop a container whose service disappeared. The launchers
(`noomesh-start.sh`, `noomesh-restart.sh` whole-stack path, `noomesh-rebuild.sh`
full path) now call `compose_report_undeclared` (lib-compose.sh) after the
`up`, which prints one line per such container and changes no exit status.
`--remove-orphans` is never passed to any `up`: compose computes orphans
against the services, profiles and add-on overlays of THAT invocation.
"""

from __future__ import annotations

import re
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"


def _run(tmp: Path, declared: str, running: str, *, compose_rc: int = 0, ps_rc: int = 0,
         env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Run compose_report_undeclared with a fake docker.

    `compose ... config --services` prints `declared`; `ps` prints `running`
    ("<service> <name>" rows, as the --format the function asks for). Every
    call is logged so a test can see the project filter and profile flag."""
    b = tmp / "bin"
    b.mkdir(exist_ok=True)
    (tmp / "declared").write_text(declared)
    (tmp / "running").write_text(running)
    d = b / "docker"
    d.write_text(
        "#!/bin/sh\n"
        'echo "$@" >> "$DOCKER_LOG"\n'
        'case "$1" in\n'
        f'  compose) [ {compose_rc} -ne 0 ] && exit {compose_rc}; cat "$TMP/declared" ;;\n'
        f'  ps) [ {ps_rc} -ne 0 ] && exit {ps_rc}; cat "$TMP/running" ;;\n'
        "esac\n"
    )
    d.chmod(d.stat().st_mode | stat.S_IEXEC)
    e = {
        "PATH": f"{b}:/usr/bin:/bin",
        "TMP": str(tmp),
        "DOCKER_LOG": str(tmp / "docker.log"),
        "COMPOSE_FILES": "-f a.yml -f b.yml",
        "HOME": str(tmp),
    }
    e.update(env or {})
    (tmp / "docker.log").write_text("")
    return subprocess.run(
        ["bash", "-c", f'. "{SCRIPTS}/lib-compose.sh" && compose_report_undeclared "{tmp}"; echo "rc=$?"'],
        capture_output=True, text=True, env=e, cwd=tmp,
    )


def test_an_undeclared_container_is_reported_with_its_remedy(tmp_path: Path) -> None:
    r = _run(tmp_path, "gateway\npostgres\n", "gateway noo-gateway\ncluster-executor noo-cluster-executor\npostgres noo-postgres\n")
    assert "rc=0" in r.stdout
    lines = [l for l in r.stderr.splitlines() if l.startswith("!")]
    assert lines == [
        "! noo-cluster-executor is not declared by any compose file of this install: docker rm -f noo-cluster-executor"
    ], r.stderr


def test_a_declared_service_and_an_agent_managed_container_are_left_alone(tmp_path: Path) -> None:
    # The agent-managed backend has no service label: its row has an empty
    # service, which the function skips; a declared profile service stays quiet.
    r = _run(tmp_path, "gateway\nvllm\n", "gateway noo-gateway\nvllm noo-vllm\n noo-llamacpp-agent\n")
    assert r.stderr.strip() == "", r.stderr
    assert "rc=0" in r.stdout


def test_every_profile_counts_and_the_project_is_the_instances(tmp_path: Path) -> None:
    _run(tmp_path, "gateway\n", "", env={"COMPOSE_PROJECT_NAME": "noo-lab"})
    log = (tmp_path / "docker.log").read_text()
    assert "--profile * config --services" in log, log
    assert "label=com.docker.compose.project=noo-lab" in log, log
    assert "--remove-orphans" not in log


def test_the_project_falls_back_to_the_cluster_files_name(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.cluster.yml").write_text("name: pai-x\nservices: {}\n")
    _run(tmp_path, "gateway\n", "")
    assert "label=com.docker.compose.project=pai-x" in (tmp_path / "docker.log").read_text()


def test_it_never_reads_clean_when_it_could_not_look(tmp_path: Path) -> None:
    r = _run(tmp_path, "", "x noo-x\n", compose_rc=1)
    assert "NOT compared" in r.stderr and "not a pass" in r.stderr, r.stderr
    assert "rc=0" in r.stdout
    r = _run(tmp_path, "gateway\n", "", ps_rc=1)
    assert "NOT compared" in r.stderr, r.stderr
    assert "rc=0" in r.stdout


@pytest.mark.parametrize("name", ["noomesh-start.sh", "noomesh-restart.sh", "noomesh-rebuild.sh"])
def test_the_launcher_reports_after_its_whole_stack_up(name: str) -> None:
    text = (SCRIPTS / name).read_text()
    assert "compose_report_undeclared" in text, f"{name} must report undeclared containers"


def _code_lines(path: Path) -> list[str]:
    """Shell lines with backslash continuations joined and comments dropped."""
    out, cur = [], ""
    for raw in path.read_text().splitlines():
        line = cur + raw.strip()
        if line.endswith("\\"):
            cur = line[:-1] + " "
            continue
        cur = ""
        if not line.startswith("#"):
            out.append(line)
    return out


def test_no_up_line_passes_remove_orphans() -> None:
    """Compose's orphan rule is relative to the services, profiles and overlays
    of the invocation, and every `up` we make hands it a partial picture; the
    flag lives on `down` in noomesh-stop.sh (the full file list) and nowhere
    else. Guard: no script line that runs an `up` carries it."""
    scripts = sorted(SCRIPTS.glob("*.sh"))
    assert len(scripts) > 10, "the glob found no scripts: the guard would pass on nothing"
    bad = [
        f"{p.name}: {l}"
        for p in scripts
        for l in _code_lines(p)
        if "--remove-orphans" in l and re.search(r"(^|\s)up(\s|$)", l)
    ]
    assert not bad, "\n".join(bad)
    # The guard must see the one legitimate use, or it is reading nothing.
    assert any("--remove-orphans" in l for l in _code_lines(SCRIPTS / "noomesh-stop.sh"))
