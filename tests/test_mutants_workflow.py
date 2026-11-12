# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The mutant workflow (.github/workflows/mutants.yml) and its harness
(scripts/ci-mutants.py).

The workflow runs untrusted-shaped code with operator-typed input, so the file
itself is held here: no expression is interpolated into a `run:` script, no
secret is referenced, the token is read-only, caches are restore-only, and the
judge runs from the workflow's own commit. The harness's validation, lanes,
tallies and verdicts are tested directly.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WF_PATH = ROOT / ".github" / "workflows" / "mutants.yml"
WF_TEXT = WF_PATH.read_text()
WF = yaml.safe_load(WF_TEXT)

_spec = importlib.util.spec_from_file_location("ci_mutants", ROOT / "scripts" / "ci-mutants.py")
cm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cm)


# On a push the planner, the harness and the summary come from dev; on a
# dispatch from the workflow's own commit.
DEV_ON_PUSH = "${{ github.event_name == 'push' && 'refs/heads/dev' || github.sha }}"


def _steps():
    for name, job in WF["jobs"].items():
        for step in job.get("steps", []):
            yield name, step


# ---- the workflow file -------------------------------------------------------

def test_no_expression_is_interpolated_into_a_run_script():
    runs = [(job, s.get("name", s.get("uses", "?")), s["run"]) for job, s in _steps() if "run" in s]
    assert len(runs) >= 8, runs
    for job, name, script in runs:
        assert "${{" not in script, f"{job} / {name}: an expression in run: (pass it through env:)"
    # The named ones too, as a plain text check over the whole file.
    for bad in ("${{ inputs", "${{ matrix.branch", "${{ github.event"):
        for block in re.findall(r"run: \|\n((?:\s{8,}.*\n)+)|run: (.*)", WF_TEXT):
            assert bad not in "".join(block), bad


def test_no_secret_no_environment_and_a_read_only_token():
    assert "secrets." not in WF_TEXT
    assert WF["permissions"] == {"contents": "read"}
    for name, job in WF["jobs"].items():
        assert "permissions" not in job, f"{name} widens the token"
        assert "environment" not in job, f"{name} uses an environment"


def test_caches_are_restore_only():
    uses = [s.get("uses", "") for _, s in _steps()]
    assert not [u for u in uses if u.startswith(("actions/cache@", "actions/cache/save@"))], uses
    assert any(u.startswith("actions/cache/restore@") for u in uses)
    # setup-* actions save their own cache: setup-go by default (unless
    # `cache: false`), setup-python / setup-node when `cache:` names a manager.
    for job, s in _steps():
        u, w = s.get("uses", ""), s.get("with", {}) or {}
        if u.startswith("actions/setup-go@"):
            assert w.get("cache") is False, f"{job}: setup-go saves a Go cache unless `cache: false`"
        elif u.startswith(("actions/setup-python@", "actions/setup-node@")):
            assert not w.get("cache"), f"{job}: {u.split('@')[0]} with `cache:` saves a cache"


def test_the_verdict_upload_includes_its_dot_directory_and_fails_without_it():
    # 11-11: upload-artifact skips hidden paths by default, so every verdict in
    # .mutant-results/ was dropped and every caught mutant's run read red.
    ups = [(job, s["with"]) for job, s in _steps() if s.get("uses", "").startswith("actions/upload-artifact@")]
    assert ups, "the mutant job uploads its verdict"
    for job, w in ups:
        hidden = any(part.startswith(".") for part in str(w["path"]).split("/") if part not in ("", ".", ".."))
        if hidden:
            assert w.get("include-hidden-files") is True, f"{job}: {w['path']} is a dot path; set include-hidden-files: true"
        assert w.get("if-no-files-found") == "error", f"{job}: a missing verdict must fail the job, not warn"


def test_every_checkout_drops_its_credentials_and_every_action_is_pinned():
    for job, s in _steps():
        u = s.get("uses", "")
        if u:
            assert re.match(r"^[\w./-]+@[0-9a-f]{40}$", u), f"{job}: {u} is not pinned to a SHA"
        if u.startswith("actions/checkout@"):
            assert s.get("with", {}).get("persist-credentials") is False, f"{job}: checkout keeps credentials"


def test_the_judge_comes_from_the_workflows_commit_not_the_mutant():
    m = WF["jobs"]["mutant"]
    harness = [s for s in m["steps"] if s.get("with", {}).get("path") == ".mutant-harness"]
    assert len(harness) == 1 and harness[0]["with"]["ref"] == DEV_ON_PUSH
    assert m["env"]["HARNESS"].endswith("/.mutant-harness/scripts/ci-mutants.py")
    for s in m["steps"]:
        if "run" in s and "ci-mutants.py" in s["run"]:
            raise AssertionError(f"{s.get('name')}: runs the subject's copy of the harness")
    calls = [s["run"] for s in m["steps"] if "run" in s and "$HARNESS" in s["run"]]
    assert calls == ['python3 "$HARNESS" run base', 'python3 "$HARNESS" run mutant', 'python3 "$HARNESS" judge']


def test_the_parent_is_tested_before_the_mutant_and_gates_it():
    steps = WF["jobs"]["mutant"]["steps"]
    names = [s.get("name", "") for s in steps]
    base, go, mut = names.index("Test the PARENT (must be green, else no verdict)"), names.index("Go to the mutant"), \
        names.index("Test the MUTANT")
    assert base < go < mut
    assert steps[go]["if"] == steps[mut]["if"] == "steps.base.outputs.green == 'true'"
    assert WF["jobs"]["mutant"]["strategy"]["fail-fast"] is False


def test_the_database_service_needs_no_credential():
    pg = WF["jobs"]["mutant"]["services"]["postgres"]
    assert "credentials" not in pg, "the mirror package is public: no token is needed to pull it"
    assert "pgvector/pgvector:pg18" in pg["image"] and "github.repository_owner" in pg["image"], pg["image"]


# ---- the harness: validation ------------------------------------------------

@pytest.mark.parametrize("spec", [
    "wt/x;rm -rf /", "wt/x$(id)", "-ofoo", "wt/../x", "wt//x", "wt/x.lock", "wt/x`id`", "wt/x:a'b",
    "wt/x:$(id)", "wt/x:a;b", "wt/x wt/x", "", "wt/x:-k", "wt/x/.hidden",
])
def test_plan_refuses_anything_but_names_and_filters(spec):
    with pytest.raises(cm.Refused):
        cm.parse_mutants(spec)


def test_plan_accepts_the_mutant_shapes_in_use():
    got = cm.parse_mutants("wt/fa-door-leaf-mutant-1 wt/fa-wl-tmpfs-mutant-2:TestEveryOtherScratchKeepsNoexec,"
                           "controller_host_tests::controller_url_fix "
                           "wt/x:tests/test_core_names_no_addon.py::test_x")
    assert got == [
        ("wt/fa-door-leaf-mutant-1", []),
        ("wt/fa-wl-tmpfs-mutant-2", ["TestEveryOtherScratchKeepsNoexec", "controller_host_tests::controller_url_fix"]),
        ("wt/x", ["tests/test_core_names_no_addon.py::test_x"]),
    ]


def test_too_many_mutants_are_refused():
    with pytest.raises(cm.Refused):
        cm.parse_mutants(" ".join(f"wt/m-{i}" for i in range(cm.MAX_MUTANTS + 1)))


def test_lane_override_is_held_to_the_known_lanes():
    assert cm.parse_lanes("python gateway-rust") == ["python", "gateway-rust"]
    with pytest.raises(cm.Refused):
        cm.parse_lanes("python; curl x")


def test_lanes_follow_the_mutant_commit_like_noo_batch():
    assert cm.lanes_for(["gateway-rust/src/a.rs"], set(), set()) == ["gateway-rust"]
    assert cm.lanes_for(["crates/addon-manifest/src/lib.rs"], set(), set()) == ["gateway-rust", "noo-cli"]
    assert cm.lanes_for(["node-agent-go/internal/docker/x.go"], set(), set()) == ["node-agent-go"]
    assert cm.lanes_for(["scripts/noo-apply.sh"], {"scripts/noo-apply.sh"}, set()) == ["gateway-rust"]
    assert cm.lanes_for(["noomesh/x.py", "tests/test_x.py"], set(), set()) == ["python"]
    assert cm.lanes_for(["docs/x.md"], set(), set()) == []


# ---- the harness: tallies and verdicts --------------------------------------

def test_tallies_read_each_runner():
    cargo = ("test a::b ... ok\ntest a::c ... FAILED\n"
             "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n"
             "test result: ok. 3 passed; 0 failed; 0 ignored\n")
    assert cm.tally_cargo(cargo) == (5, 1, ["a::c"])
    go = "=== RUN   TestA\n--- PASS: TestA (0.00s)\n    --- FAIL: TestB/sub (0.00s)\n--- FAIL: TestB (0.00s)\n"
    assert cm.tally_go(go) == (3, 2, ["TestB/sub", "TestB"])
    py = "FAILED tests/test_x.py::test_y - assert 1\n1 failed, 4 passed in 0.5s\n"
    assert cm.tally_pytest(py) == (5, 1, ["tests/test_x.py::test_y"])


def _lane(ran, failed, rcs, names=()):
    return {"ran": ran, "failed": failed, "names": list(names), "rcs": rcs}


def _phase(**lanes):
    return {"lanes": lanes}


def test_verdicts():
    green = _phase(**{"gateway-rust": _lane(10, 0, [0, 0])})
    caught = _phase(**{"gateway-rust": _lane(10, 1, [101, 0], ["a::b"])})
    survived = _phase(**{"gateway-rust": _lane(10, 0, [0, 0])})
    nobuild = _phase(**{"gateway-rust": _lane(0, 0, [101])})
    ran_none = _phase(**{"gateway-rust": _lane(0, 0, [0])})
    assert cm.judge(green, caught) == ("red", "a::b")
    assert cm.judge(green, survived)[0] == "green"
    assert cm.judge(green, nobuild)[0] == "error"
    assert cm.judge(green, ran_none)[0] == "error"
    # A red base is NO verdict, whatever the mutant did: the #958 trap.
    v, d = cm.judge(caught, caught)
    assert v == "base-red" and "NO VERDICT" in d and "a::b" in d
    assert cm.judge(ran_none, caught)[0] == "base-red"
    assert cm.judge(None, None)[0] == "error"
    assert cm.judge(green, None)[0] == "error"
    # Two lanes: one caught it, the other passed -> caught.
    two = _phase(**{"gateway-rust": _lane(5, 1, [101], ["x"]), "python": _lane(3, 0, [0])})
    base2 = _phase(**{"gateway-rust": _lane(5, 0, [0]), "python": _lane(3, 0, [0])})
    assert cm.judge(base2, two)[0] == "red"


def test_summary_is_green_only_when_every_mutant_was_caught(tmp_path, monkeypatch):
    import json
    for i, v in enumerate(["red", "red"]):
        d = tmp_path / f"mutant-{i}"
        d.mkdir()
        (d / "verdict.json").write_text(json.dumps({"branch": f"wt/m-{i}", "sha": "abcdef12", "verdict": v, "detail": "x"}))
    monkeypatch.setenv("EXPECTED", "2")
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    assert cm.cmd_summary(str(tmp_path)) == 0
    monkeypatch.setenv("EXPECTED", "3")  # one job reported nothing
    assert cm.cmd_summary(str(tmp_path)) == 1
    (tmp_path / "mutant-1" / "verdict.json").write_text(
        json.dumps({"branch": "wt/m-1", "sha": "abcdef12", "verdict": "base-red", "detail": "x"}))
    monkeypatch.setenv("EXPECTED", "2")
    assert cm.cmd_summary(str(tmp_path)) == 1


# ---- the push trigger (2026-11-11) ----------------------------------------------
# A dispatched workflow is looked up on the default branch (main), so dispatch
# 404s until a promotion carries this file there; a push runs it from the
# pushed commit. The mutant is the pushed branch, its expected-red tests come
# from `Mutant-Test:` trailers, and it may not edit its own judge.

def test_a_mutant_branch_push_runs_it_and_dispatch_stays():
    on = WF[True]
    assert on["push"] == {"branches": ["wt/*-mut-*", "wt/*-mutant-*"]}, on["push"]
    assert set(on["workflow_dispatch"]["inputs"]) == {"mutants", "lanes"}
    for shape in ("wt/97-console-by-digest-mut-3", "wt/97-upgrade-stage-nonblocking-mut-7",
                  "wt/cf-mutant-mbx-retired-recipient", "wt/fa-orphan-test-race-mutant-1"):
        assert cm.PUSH_BRANCH_RE.match(shape), shape
    for not_a_mutant in ("wt/97-console-by-digest", "dev", "main", "wt/mut", "feature/x-mut-1", "wt/../x-mut-1"):
        assert not (cm.PUSH_BRANCH_RE.match(not_a_mutant) and cm.valid_branch(not_a_mutant)), not_a_mutant


def test_a_push_is_one_group_per_branch_and_a_repush_replaces_it():
    c = WF["concurrency"]
    assert c["group"] == ("${{ github.event_name == 'push' && format('mutants-{0}', github.ref) "
                          "|| format('mutants-{0}', github.run_id) }}")
    assert c["cancel-in-progress"] == "${{ github.event_name == 'push' }}"


def test_on_a_push_the_planner_judge_and_summary_come_from_dev():
    plan = WF["jobs"]["plan"]["steps"]
    assert plan[0]["with"]["ref"] == DEV_ON_PUSH
    assert next(s for s in plan if s.get("id") == "plan")["env"]["PUSH_REF"] == \
        "${{ github.event_name == 'push' && github.ref_name || '' }}"
    assert WF["jobs"]["summary"]["steps"][0]["with"]["ref"] == DEV_ON_PUSH


def _repo(d: Path, message: str) -> str:
    import subprocess
    d.mkdir(parents=True, exist_ok=True)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(d), "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}

    def run(*a: str) -> str:
        return subprocess.run(["git", *a], cwd=d, env=env, check=True, capture_output=True, text=True).stdout.strip()

    run("init", "-q")
    (d / "f").write_text("x")
    run("add", "f")
    run("commit", "-qm", message)
    return run("rev-parse", "HEAD")


def test_the_expected_red_tests_come_from_mutant_test_trailers(tmp_path):
    sha = _repo(tmp_path, "MUTANT 3 (do not merge): x\n\nsome free text naming not_this_test\n\n"
                "Mutant-Test: commands::kiosk_seat::console_identity_tests::a, tests/test_x.py::test_y\n"
                "Mutant-Test: TestGoThing\n")
    assert cm.trailer_filters(sha, cwd=str(tmp_path)) == [
        (None, "commands::kiosk_seat::console_identity_tests::a"), (None, "tests/test_x.py::test_y"),
        (None, "TestGoThing")]


def test_a_trailer_may_name_its_lane(tmp_path):
    sha = _repo(tmp_path, "MUTANT 1: x\n\nMutant-Test: gateway-rust: auth::tests::a, auth::tests::b\n"
                "Mutant-Test: node-agent-go: TestThing\nMutant-Test: routes::x::tests::c\n")
    assert cm.trailer_filters(sha, cwd=str(tmp_path)) == [
        ("gateway-rust", "auth::tests::a"), ("gateway-rust", "auth::tests::b"),
        ("node-agent-go", "TestThing"), (None, "routes::x::tests::c")]
    # A cargo path is a filter, not a lane: no lane is named "routes", and a
    # lane needs `: ` (colon, space) after it.
    sha = _repo(tmp_path / "p", "MUTANT 2: x\n\nMutant-Test: gateway-rust::not_a_lane_prefix\n")
    assert cm.trailer_filters(sha, cwd=str(tmp_path / "p")) == [(None, "gateway-rust::not_a_lane_prefix")]


def test_named_lanes_run_alone_and_an_unnamed_filter_keeps_every_lane():
    both = ["gateway-rust", "noo-cli"]  # a gateway file noo-cli include_str!s (fa's auth.rs mutants)
    assert cm.resolve_lanes(both, [("gateway-rust", "auth::tests::a")]) == (["gateway-rust"], ["auth::tests::a"])
    assert cm.resolve_lanes(both, [(None, "auth::tests::a")]) == (both, ["auth::tests::a"]), "unchanged default"
    assert cm.resolve_lanes(both, [("gateway-rust", "a"), (None, "b")]) == (both, ["a", "b"])
    assert cm.resolve_lanes(both, [("noo-cli", "c"), ("gateway-rust", "a")]) == (both, ["c", "a"]), \
        "lanes run in LANES order whatever the trailer order"
    with pytest.raises(cm.Refused, match="does not reach"):
        cm.resolve_lanes(both, [("node-agent-go", "TestX")])
    with pytest.raises(cm.Refused, match="does not reach"):
        cm.resolve_lanes(["gateway-rust"], [("gateway-rust", "a"), ("python", "tests/t.py")])


def test_a_lane_that_runs_no_test_is_still_no_verdict():
    # Skipping an unnamed lane must not weaken "nothing ran proves nothing":
    # every lane that DOES run is held to it.
    ran0 = {"phase": "mutant", "lanes": {"gateway-rust": {"ran": 0, "failed": 0, "names": [], "rcs": [0]}}}
    base = {"phase": "base", "lanes": {"gateway-rust": {"ran": 3, "failed": 0, "names": [], "rcs": [0]}}}
    assert cm.judge(base, ran0)[0] == "error"


def test_no_trailer_or_a_bad_filter_is_refused(tmp_path):
    sha = _repo(tmp_path / "a", "MUTANT 1: expect red: some_test")  # free text only
    with pytest.raises(cm.Refused, match="no `Mutant-Test:"):
        cm.trailer_filters(sha, cwd=str(tmp_path / "a"))
    sha = _repo(tmp_path / "b", "MUTANT 2: x\n\nMutant-Test: $(rm -rf /)\n")
    with pytest.raises(cm.Refused, match="not a test filter"):
        cm.trailer_filters(sha, cwd=str(tmp_path / "b"))


def test_a_mutant_may_not_edit_its_judge():
    assert cm.judge_edits(["gateway-rust/src/x.rs", "tests/test_y.py"]) == []
    assert cm.judge_edits([".github/workflows/mutants.yml", "x"]) == [".github/workflows/mutants.yml"]
    assert cm.judge_edits(["scripts/ci-mutants.py"]) == ["scripts/ci-mutants.py"]


def test_a_pushed_branch_off_the_patterns_is_refused_before_any_fetch(monkeypatch, capsys):
    monkeypatch.setenv("PUSH_REF", "wt/feature-x")  # no -mut-/-mutant- marker
    monkeypatch.setenv("MUTANTS", "")
    assert cm.cmd_plan() == 2
    assert "does not judge" in capsys.readouterr().out
