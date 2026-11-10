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
    assert len(harness) == 1 and harness[0]["with"]["ref"] == "${{ github.sha }}"
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
    assert "credentials" not in pg and pg["image"] == "ghcr.io/noomesh/pgvector:pg18"


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
