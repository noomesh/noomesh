# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""harness-compare (i83 F) against the fake gateway.

What a live run cannot prove on demand: that every kind is placed in turn
with the stored env kept, that the ORIGINAL placement comes back at the end
AND when the run blows up halfway, that a refused kind is a row and not a
crash, that a task the controller ran in process does not count as the
kind's pass, and that the fixture run writes both report files.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpx
import pytest

EVAL = Path(__file__).resolve().parents[1] / "eval"
sys.path.insert(0, str(EVAL))

from noo_eval import harness_compare as hcmp  # noqa: E402
from noo_eval import run as eval_run  # noqa: E402
from noo_eval.harness_fake import FakeHarnessGateway, KindProfile, PROFILES  # noqa: E402
from noo_eval.scenario import HarnessCompareSpec, Scenario  # noqa: E402

SAMPLE = EVAL / "scenarios" / "harness-compare-awolf.yaml"


def _spec(**kw) -> HarnessCompareSpec:
    base = {"node": "awolf", "kinds": ["noo", "copilot", "claude-code"],
            "tasks": [{"name": "reply-ok", "objective": "Reply with the single word: ok", "check": "contains:ok"},
                      {"name": "delegate", "objective": "Delegate a child task, then finish with: pong",
                       "check": "contains:pong"}]}
    base.update(kw)
    return HarnessCompareSpec.model_validate(base)


def _run(spec, fake: FakeHarnessGateway, transport_handler=None):
    async def go():
        handler = transport_handler or fake.handle
        async with httpx.AsyncClient(base_url="http://fake", transport=httpx.MockTransport(handler)) as c:
            return await hcmp.run_compare(spec, c, clock=fake.clock, sleep=fake.clock.sleep, log=lambda _: None)
    return asyncio.run(go())


def _placed_kinds(fake):
    return [b["env"]["NOO_HARNESS_KIND"] for m, _, b in fake.writes if m == "PUT"]


# ── checks ──

@pytest.mark.parametrize("check,state,result,want", [
    ("contains:OK", "done", "the answer is ok.", True),
    ("contains:pong", "done", "ping", False),
    ("regex:(?i)^\\W*ok\\W*$", "done", " OK. ", True),
    ("regex:^ok$", "done", "ok then", False),
    ("nonempty", "done", "x", True),
    ("nonempty", "done", "  \n ", False),
    ("state:done", "done", "", True),
    ("state:done", "failed", "boom", False),
    ("contains:a:b", "done", "has a:b in it", True),   # only the first colon splits
])
def test_check_evaluators(check, state, result, want):
    passed, reason = hcmp.evaluate_check(check, state, result)
    assert passed is want
    assert (reason == "") is want, reason


@pytest.mark.parametrize("bad", ["equals:ok", "regex:(", "contains:", "nonempty:x", "state:"])
def test_a_bad_check_fails_at_load_not_mid_run(bad):
    with pytest.raises(ValueError):
        _spec(tasks=[{"name": "t", "objective": "o", "check": bad}])


def test_the_sample_scenario_loads():
    scn = Scenario.load(SAMPLE)
    hc = scn.harness_compare
    assert hc is not None and hc.node == "awolf"
    assert hc.kinds == ["noo", "copilot", "claude-code", "codex"]
    assert [t.name for t in hc.task_sets[0].tasks] == ["reply-ok", "mesh-nodes", "delegate"]
    assert not scn.workloads, "a compare scenario drives no load"


# ── the kind cycle ──

def test_each_kind_is_placed_in_turn_with_the_stored_env_kept_and_the_original_restored():
    fake = FakeHarnessGateway(original_kind="copilot")
    hc = _run(_spec(), fake)
    assert _placed_kinds(fake) == ["noo", "copilot", "claude-code", "copilot"], fake.writes
    for _, _, body in fake.writes:
        assert body["env"]["NOO_HARNESS_LOG"] == "info", "the stored env must be merged, not replaced"
        assert body["role"] == "harness"
    assert hc.original_kind == "copilot" and hc.restored
    assert fake.placement["env"] == {"NOO_HARNESS_KIND": "copilot", "NOO_HARNESS_LOG": "info"}
    assert [k.kind for k in hc.kind_runs if k.ready] == ["noo", "copilot", "claude-code"]


def test_the_original_placement_is_restored_when_the_run_blows_up():
    fake = FakeHarnessGateway(original_kind="noo")
    posts = {"n": 0}

    def exploding(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/api/tasks":
            posts["n"] += 1
            if posts["n"] == 3:      # the first task of the SECOND kind
                raise RuntimeError("driver bug")
        return fake.handle(request)

    with pytest.raises(RuntimeError, match="driver bug"):
        _run(_spec(), fake, exploding)
    assert _placed_kinds(fake) == ["noo", "copilot", "noo"], "restore must run on the way out"
    assert fake.placement["env"]["NOO_HARNESS_KIND"] == "noo"


def test_a_node_with_no_harness_placement_gets_the_one_the_run_made_removed():
    fake = FakeHarnessGateway(original_kind=None)
    hc = _run(_spec(kinds=["noo"]), fake)
    assert hc.original_kind is None and hc.restored
    assert fake.writes[-1][0] == "DELETE" and fake.placement is None


def test_a_placement_the_auto_policy_made_is_removed_not_stored():
    fake = FakeHarnessGateway(original_kind=None, synthesized=True)
    hc = _run(_spec(kinds=["noo", "codex"]), fake)
    assert hc.restored and hc.original_kind is None
    assert fake.writes[-1][0] == "DELETE", "writing the synthesized placement back would pin the node"
    assert all(not (b or {}).get("synthesized") for m, _, b in fake.writes if m == "PUT")


def test_a_refused_kind_is_a_row_and_the_next_kind_still_runs():
    not_installed = 'harness kind "codex": its runner is present but the "codex" command is not installed on this node'
    fake = FakeHarnessGateway(profiles={**PROFILES, "codex": KindProfile(refused=not_installed)})
    hc = _run(_spec(kinds=["codex", "noo"]), fake)
    codex = next(k for k in hc.kind_runs if k.kind == "codex")
    assert not codex.ready and "node refused" in codex.error and "not installed" in codex.error
    rows = {r["harness_kind"]: r for r in hcmp.summarize(hc)}
    assert rows["codex"]["passed"] == 0 and rows["codex"]["total"] == 2
    assert all("node refused" in f for f in rows["codex"]["failures"])
    assert rows["noo"]["passed"] == 2


def test_a_kind_that_never_runs_times_out_instead_of_hanging():
    fake = FakeHarnessGateway()
    fake.down_beats = 10**6

    def stuck(request):
        fake.down_beats = 10**6     # every PUT resets it to 2; keep it down
        return fake.handle(request)

    hc = _run(_spec(kinds=["claude-code"], ready_timeout_s=60), fake, stuck)
    k = hc.kind_runs[0]
    assert not k.ready and "not running 60s after" in k.error and "stopped" in k.error
    assert hc.restored


def test_ready_needs_the_node_to_report_the_placed_kind_running():
    """``running`` alone is not ready: a harness still running the previous
    kind (or one that fell back to ``noo``) would be measured as this one."""
    fake = FakeHarnessGateway(original_kind="noo")
    fake.report_kind = "noo"            # stuck: the node keeps running noo
    hc = _run(_spec(kinds=["copilot"], ready_timeout_s=60), fake)
    k = hc.kind_runs[0]
    assert not k.ready and "not running 60s after placing copilot" in k.error, k.error
    assert "running kind: noo" in k.error, k.error
    assert all(r.state == "not run" for r in hc.runs), "no task runs under the wrong kind"
    # An agent that reports no kind never qualifies either, and says why.
    fake = FakeHarnessGateway(original_kind="noo")
    fake.report_kind = ""
    k = _run(_spec(kinds=["noo"], ready_timeout_s=60), fake).kind_runs[0]
    assert not k.ready and "an agent older than the kind report" in k.error, k.error
    # The node's own report is what is read.
    n = fake._node()
    assert hcmp.harness_running_kind(n) == "" and hcmp.harness_running_kind(None) == ""
    fake.report_kind = None
    assert hcmp.harness_running_kind(fake._node()) == "noo"


def test_a_task_the_controller_ran_in_process_does_not_count_for_the_kind():
    fake = FakeHarnessGateway()
    real_create = fake._create

    def in_process(body):
        out = real_create(body)
        out.update({"dispatched": False, "node": "gateway-ctl", "why": "NOO_HARNESS_DISPATCH=0 on the controller"})
        return out

    fake._create = in_process
    hc = _run(_spec(kinds=["noo"]), fake)
    assert not any(r.passed for r in hc.runs)
    assert all("NOO_HARNESS_DISPATCH=0" in r.note for r in hc.runs)
    assert _run(_spec(kinds=["noo"], require_dispatch=False), FakeHarnessGateway()).runs[0].passed


def test_a_task_that_outlives_its_timeout_fails_and_says_it_was_left_running():
    slow = dict(PROFILES, noo=KindProfile(polls=10**6))
    fake = FakeHarnessGateway(profiles=slow)
    hc = _run(_spec(kinds=["noo"], task_timeout_s=30), fake)
    r = hc.runs[0]
    assert not r.passed and r.state.startswith("timeout") and "/stop" in r.note


def test_kind_restricted_tasks_are_skipped_not_failed():
    spec = _spec(kinds=["noo", "copilot"], tasks=[
        {"name": "everyone", "objective": "Reply with the single word: ok", "check": "contains:ok"},
        {"name": "noo-only", "objective": "Delegate ... pong", "check": "contains:pong", "kinds": ["noo"]}])
    hc = _run(spec, FakeHarnessGateway())
    rows = {r["harness_kind"]: r for r in hcmp.summarize(hc)}
    assert (rows["noo"]["passed"], rows["noo"]["total"], rows["noo"]["skipped"]) == (2, 2, 0)
    assert (rows["copilot"]["passed"], rows["copilot"]["total"], rows["copilot"]["skipped"]) == (1, 1, 1)


# ── tokens ──

def test_tokens_are_the_harness_kind_usage_diff_and_a_missing_row_is_not_zero():
    hc = _run(_spec(), FakeHarnessGateway())
    rows = {r["harness_kind"]: r for r in hcmp.summarize(hc)}
    assert rows["noo"]["prompt_tokens"] is None, "noo writes no harness:noo row: not reported, never 0"
    assert rows["copilot"]["prompt_tokens"] > 0 and rows["claude-code"]["prompt_tokens"] > rows["copilot"]["prompt_tokens"]
    assert "scoped to eval-user" in hc.token_method


def test_usage_delta_edges():
    assert hcmp.usage_delta(None, {}, "noo")[0] is None
    assert hcmp.usage_delta({}, {}, "noo")[2].startswith("no harness:noo")
    before = {"harness:copilot": (100, 10, 1)}
    assert hcmp.usage_delta(before, {"harness:copilot": (150, 15, 2)}, "copilot")[:2] == (50, 5)
    # a month rollover between the two reads resets the counters: not negative tokens
    assert hcmp.usage_delta(before, {"harness:copilot": (20, 2, 1)}, "copilot")[0] is None


# ── the whole pipeline ──

def test_the_fixture_run_writes_the_html_report_and_its_json_twin(tmp_path):
    out = tmp_path / "hc.html"
    assert eval_run.main(["run", str(SAMPLE), "--fixture", "--out", str(out)]) == 0
    twin = out.with_suffix(".json")
    assert out.is_file() and twin.is_file()
    page = out.read_text()
    assert "harness_kind" in page and "SYNTHETIC FIXTURE" in page
    assert ">noo, claude-code, codex<" in page, "a tie for the best pass rate names every tied kind"
    for kind in ("noo", "copilot", "claude-code", "codex"):
        assert f"<b>{kind}</b>" in page
    doc = json.loads(twin.read_text())
    assert [r["harness_kind"] for r in doc["summary"]] == ["noo", "copilot", "claude-code", "codex"]
    assert {r["task_set"] for r in doc["summary"]} == {"basics"}
    assert len(doc["runs"]) == 12 and doc["restored"] is True
    copilot = next(r for r in doc["summary"] if r["harness_kind"] == "copilot")
    assert copilot["passed"] == 2 and copilot["failures"][0].startswith("delegate:")


def test_a_compare_scenario_without_a_gateway_or_fixture_is_refused():
    with pytest.raises(SystemExit, match="--fixture"):
        eval_run.main(["run", str(SAMPLE)])
