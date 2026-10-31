# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Retired compose services are declared too, as retired (noomesh-internal
186b, plan 2026-10-30, PR b).

`noo-cluster-executor` ran for two days after #98 deleted its service, because
`up` never stops a container whose service disappeared. `config/retired-services.txt`
(`<service>  <YYYY-MM-DD>  <PR>`) is the repo saying "this service is gone and
must stay gone":

* the launchers remove a container of it before the whole-stack `up`
  (`compose_remove_retired`, lib-compose.sh) and nothing else;
* `noo doctor orphans` / `noo cluster verify` FAIL while one runs (Rust tests);
* this file's guard fails the build when a service that existed disappears from
  the compose files without a line in the list.
"""

from __future__ import annotations

import re
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
LIST = ROOT / "config" / "retired-services.txt"
SNAPSHOT = ROOT / "tests" / "fixtures" / "compose-services.txt"


def _retired(text: str) -> dict[str, tuple[str, str]]:
    """{service: (date, pr)}; whole-line `#` comments only (the PR column starts
    with `#` itself)."""
    out: dict[str, tuple[str, str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        out[parts[0]] = (parts[1] if len(parts) > 1 else "", " ".join(parts[2:]))
    return out


def _declared() -> set[str]:
    """Every service name in every docker-compose*.yml at the repo root, all
    profiles (a profile-gated service is declared)."""
    names: set[str] = set()
    files = sorted(ROOT.glob("docker-compose*.yml"))
    assert files, "no compose files found: the guard would pass on nothing"
    for f in files:
        doc = yaml.safe_load(f.read_text()) or {}
        names |= set((doc.get("services") or {}).keys())
    return names


# ── the list and the guard ────────────────────────────────────────────────


def test_the_list_parses_and_starts_with_cluster_executor() -> None:
    got = _retired(LIST.read_text())
    assert got.get("cluster-executor") == ("2026-09-11", "#98"), got
    for svc, (date, pr) in got.items():
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", date), f"{svc}: date {date!r} is not YYYY-MM-DD"
        assert re.fullmatch(r"#\d+", pr), f"{svc}: PR {pr!r} is not #<number>"


def test_cluster_executor_name_matches_the_removal_comment() -> None:
    """The service name on the list is the one the compose comment retired."""
    text = (ROOT / "docker-compose.cluster.yml").read_text()
    assert re.search(r"REMOVED 2026-09-11 .{0,10}the `cluster-executor` sidecar", text), (
        "the REMOVED comment no longer names cluster-executor: re-check the list entry"
    )


def test_a_removed_service_needs_a_retired_line() -> None:
    """A service that existed (the snapshot) must still be declared or be on the
    retired list. Removing one from the compose files without a line fails here,
    naming the line to add."""
    snap = {l.strip() for l in SNAPSHOT.read_text().splitlines() if l.strip() and not l.startswith("#")}
    assert snap, "the snapshot is empty: the guard would pass on nothing"
    gone = sorted(snap - _declared() - set(_retired(LIST.read_text())))
    assert not gone, (
        "service(s) removed from the compose files with no line in config/retired-services.txt "
        "(compose never stops their container; `noo doctor orphans` could not tell it was meant to go). "
        "Add:\n" + "\n".join(f"{s}  <YYYY-MM-DD>  #<PR>" for s in gone)
    )


def test_the_snapshot_is_current() -> None:
    """A new service must be added to tests/fixtures/compose-services.txt, so the
    removal above is guarded from the day it exists."""
    snap = {l.strip() for l in SNAPSHOT.read_text().splitlines() if l.strip() and not l.startswith("#")}
    new = sorted(_declared() - snap)
    assert not new, (
        "service(s) declared in a compose file but missing from tests/fixtures/compose-services.txt; "
        "add these line(s) (keep the file sorted):\n" + "\n".join(new)
    )
    lines = [l for l in SNAPSHOT.read_text().splitlines() if l.strip()]
    assert lines == sorted(lines), "tests/fixtures/compose-services.txt must stay sorted"


def test_a_retired_service_is_not_declared_again() -> None:
    back = sorted(set(_retired(LIST.read_text())) & _declared())
    assert not back, (
        f"{back} are on config/retired-services.txt but a compose file declares them: the launcher "
        "would remove the container it just started. Drop the retired line or the service."
    )


def test_the_guard_notices_a_removal() -> None:
    """Self-check with a synthetic pair: the comparison the guard makes fails
    for an unlisted removal and passes once the line exists."""
    snap, declared = {"a", "b", "c"}, {"a", "c"}
    assert sorted(snap - declared - set(_retired("# x\n"))) == ["b"]
    assert sorted(snap - declared - set(_retired("b  2026-10-30  #1\n"))) == []


def test_the_list_ships_in_the_standalone_slice() -> None:
    """The launcher on an installed box reads <root>/config/retired-services.txt;
    an installed box has no checkout, so build.rs must embed it."""
    build = (ROOT / "noo-cli" / "build.rs").read_text()
    assert '"config/retired-services.txt"' in build


# ── the launcher removal, with a fake docker ──────────────────────────────

FAKE_DOCKER = r"""#!/bin/sh
echo "$@" >> "$DOCKER_LOG"
case "$1" in
  ps)
    [ "${PS_RC:-0}" -ne 0 ] && exit "$PS_RC"
    proj=""
    for a in "$@"; do
      case "$a" in label=com.docker.compose.project=*) proj="${a#label=com.docker.compose.project=}" ;; esac
    done
    # containers.tsv: project<TAB>service<TAB>name<TAB>state ; `ps -a` lists all, `ps` only running
    awk -F'\t' -v p="$proj" -v all="$([ "$2" = -a ] && echo 1)" \
      '$1 == p && (all == 1 || $4 == "running") { print $2 " " $3 }' "$TMP/containers.tsv"
    ;;
  rm)
    [ "$2" = -f ] || exit 2
    for f in $FAIL_RM; do [ "$f" = "$3" ] && exit 1; done
    echo "$3" >> "$TMP/removed"
    ;;
esac
"""

LIST_TEXT = "# c\ncluster-executor  2026-09-11  #98\nold-thing  2026-01-02  #7\n"


def _remove(tmp: Path, containers: list[tuple[str, str, str, str]], *, list_text: str | None = LIST_TEXT,
            env: dict[str, str] | None = None, fail_rm: str = "", ps_rc: int = 0):
    b = tmp / "bin"
    b.mkdir(exist_ok=True)
    d = b / "docker"
    d.write_text(FAKE_DOCKER)
    d.chmod(d.stat().st_mode | stat.S_IEXEC)
    (tmp / "containers.tsv").write_text("".join("\t".join(c) + "\n" for c in containers))
    (tmp / "removed").write_text("")
    (tmp / "docker.log").write_text("")
    (tmp / "config").mkdir(exist_ok=True)
    lst = tmp / "config" / "retired-services.txt"
    if list_text is None:
        lst.unlink(missing_ok=True)
    else:
        lst.write_text(list_text)
    e = {
        "PATH": f"{b}:/usr/bin:/bin",
        "TMP": str(tmp),
        "DOCKER_LOG": str(tmp / "docker.log"),
        "HOME": str(tmp),
        "FAIL_RM": fail_rm,
        "PS_RC": str(ps_rc),
    }
    e.update(env or {})
    r = subprocess.run(
        ["bash", "-c", f'. "{SCRIPTS}/lib-compose.sh" && compose_remove_retired "{tmp}"; echo "rc=$?"'],
        capture_output=True, text=True, env=e, cwd=tmp,
    )
    removed = (tmp / "removed").read_text().split()
    return r, removed


NOOMESH = "noomesh"


def test_only_listed_services_of_this_project_are_removed(tmp_path: Path) -> None:
    r, removed = _remove(tmp_path, [
        (NOOMESH, "gateway", "noo-gateway", "running"),
        (NOOMESH, "cluster-executor", "noo-cluster-executor", "running"),
        (NOOMESH, "foo", "noo-foo", "running"),                      # undeclared but NOT retired
        (NOOMESH, "", "noo-llamacpp-agent", "running"),              # no service label
        ("other", "cluster-executor", "other-cluster-executor", "running"),  # another project
    ])
    assert removed == ["noo-cluster-executor"], (removed, r.stderr)
    assert r.stdout.splitlines()[0] == (
        "- removed noo-cluster-executor: service cluster-executor was retired on 2026-09-11 (#98)"
    ), r.stdout
    assert "rc=0" in r.stdout and r.stderr.strip() == ""
    log = (tmp_path / "docker.log").read_text()
    assert "--remove-orphans" not in log
    assert "label=com.docker.compose.project=noomesh" in log


def test_a_stopped_retired_container_is_removed_too(tmp_path: Path) -> None:
    r, removed = _remove(tmp_path, [
        (NOOMESH, "cluster-executor", "noo-cluster-executor", "exited"),
        (NOOMESH, "old-thing", "noo-old-thing", "running"),
    ])
    assert sorted(removed) == ["noo-cluster-executor", "noo-old-thing"], r.stderr
    assert "- removed noo-old-thing: service old-thing was retired on 2026-01-02 (#7)" in r.stdout


def test_the_project_is_the_instances(tmp_path: Path) -> None:
    r, removed = _remove(tmp_path, [
        (NOOMESH, "cluster-executor", "noo-cluster-executor", "running"),
        ("noo-lab", "cluster-executor", "lab-cluster-executor", "running"),
    ], env={"COMPOSE_PROJECT_NAME": "noo-lab"})
    assert removed == ["lab-cluster-executor"], r.stderr


def test_a_failed_rm_prints_a_line_and_continues(tmp_path: Path) -> None:
    r, removed = _remove(tmp_path, [
        (NOOMESH, "cluster-executor", "noo-cluster-executor", "running"),
        (NOOMESH, "old-thing", "noo-old-thing", "running"),
    ], fail_rm="noo-cluster-executor")
    assert removed == ["noo-old-thing"]
    assert "! could not remove noo-cluster-executor" in r.stderr and "docker rm -f noo-cluster-executor" in r.stderr
    assert "rc=0" in r.stdout


def test_nothing_retired_running_prints_nothing(tmp_path: Path) -> None:
    r, removed = _remove(tmp_path, [(NOOMESH, "gateway", "noo-gateway", "running")])
    assert removed == [] and r.stdout.strip() == "rc=0" and r.stderr.strip() == ""


def test_an_unreadable_list_or_docker_is_said_not_read_as_clean(tmp_path: Path) -> None:
    r, removed = _remove(tmp_path, [(NOOMESH, "cluster-executor", "noo-cluster-executor", "running")], list_text=None)
    assert removed == [] and "NOT checked" in r.stderr and "rc=0" in r.stdout
    r, removed = _remove(tmp_path, [(NOOMESH, "cluster-executor", "noo-cluster-executor", "running")], ps_rc=1)
    assert removed == [] and "NOT checked" in r.stderr and "rc=0" in r.stdout


def test_a_bare_list_line_still_removes(tmp_path: Path) -> None:
    r, removed = _remove(tmp_path, [(NOOMESH, "bare", "noo-bare", "running")], list_text="bare\n")
    assert removed == ["noo-bare"], r.stderr
    assert r.stdout.startswith("- removed noo-bare: service bare was retired on  ()"), r.stdout


@pytest.mark.parametrize("name", ["noomesh-start.sh", "noomesh-restart.sh", "noomesh-rebuild.sh"])
def test_the_launcher_removes_retired_before_its_whole_stack_up(name: str) -> None:
    text = (SCRIPTS / name).read_text()
    lines = [l for l in text.splitlines() if not l.strip().startswith("#")]
    call = next((i for i, l in enumerate(lines) if "compose_remove_retired" in l), None)
    report = next((i for i, l in enumerate(lines) if "compose_report_undeclared" in l), None)
    assert call is not None, f"{name} must remove retired services"
    assert report is not None and call < report, f"{name}: removal must come before the up and its report"
    ups = [i for i, l in enumerate(lines) if re.search(r"(^|\s)up\s+-d", l)]
    assert ups and call < min(ups), f"{name}: removal at {call} must precede the first up at {min(ups)}"
