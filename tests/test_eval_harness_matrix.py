# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""harness-matrix (operator, 2026-11-01): harness × node × model, on demand.

What a live run cannot prove on demand: that a node which cannot serve is a
SKIP and never a harness failure, that a model variant is refused when its
model is not already on the node (a benchmark never downloads), that a
variant's placement comes back, that a held build lock or an unconfirmed
model swap stops the run before anything is written, and that the history,
slices and trend the report charts are computed from the rows they claim.
"""
from __future__ import annotations

import asyncio
import fcntl
import json
import sys
from pathlib import Path

EVAL = Path(__file__).resolve().parents[1] / "eval"
sys.path.insert(0, str(EVAL))

from noo_eval import harness_matrix as hm  # noqa: E402
from noo_eval import report  # noqa: E402
from noo_eval import run as eval_run  # noqa: E402
from noo_eval.harness_fake import FakeClock, FakeHarnessGateway, fixture_facts  # noqa: E402
from noo_eval.scenario import HarnessMatrixSpec, Scenario  # noqa: E402
from noo_eval.schema import RunResult  # noqa: E402

SAMPLE = EVAL / "scenarios" / "harness-matrix.yaml"
TASKS = [{"name": "reply-ok", "objective": "Reply with the single word: ok", "check": "contains:ok"}]


def _spec(cells, **kw) -> HarnessMatrixSpec:
    return HarnessMatrixSpec.model_validate({"cells": cells, "kinds": ["noo", "codex"], "tasks": TASKS, **kw})


def _run(spec: HarnessMatrixSpec, facts: dict):
    """One cell against a fake gateway carrying ``facts``; returns (matrix, fake)."""
    clock = FakeClock()
    fake = FakeHarnessGateway(node=spec.cells[0].node, clock=clock, facts=facts)

    async def go():
        async with fake.client() as c:
            return await hm.run_matrix(spec, c, clock=clock, sleep=clock.sleep, log=lambda _: None)
    return asyncio.run(go()), fake


def test_the_sample_scenario_loads_and_names_four_device_types():
    scn = Scenario.load(SAMPLE)
    spec = scn.harness_matrix
    assert spec is not None
    assert [c.node for c in spec.cells] == ["awolf", "mcmini", "pop-os", "robopi"]
    assert spec.cells[3].skip, "robopi is recorded as SKIP until its arm64 stunnel is fixed"
    assert sum(len(ts.tasks) for ts in spec.task_sets) == 6
    assert "~/.cache/noo-batch/run.lock" in spec.busy_locks


def test_a_held_busy_lock_or_an_unconfirmed_model_swap_stops_the_run(tmp_path):
    lock = tmp_path / "run.lock"
    lock.write_text("")
    spec = _spec([{"node": "awolf"}], busy_locks=[str(lock)])
    assert hm.preflight(spec, allow_placement_changes=False) == ""
    with open(lock) as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert "is held" in hm.preflight(spec, allow_placement_changes=True)
    assert hm.preflight(_spec([{"node": "x"}], busy_locks=[str(tmp_path / "absent")]),
                        allow_placement_changes=False) == "", "a lock nobody ever took is free"

    variant = _spec([{"node": "awolf", "variants": [{"backend": "vllm", "model": "m"}]}])
    assert "--allow-placement-changes" in hm.preflight(variant, allow_placement_changes=False)
    assert hm.preflight(variant, allow_placement_changes=True) == ""


def test_hardware_is_read_from_the_node_record_whatever_its_shape():
    gpu = hm.hardware_of(fixture_facts("awolf"))
    assert (gpu.gpu, gpu.vram_gb, gpu.cpu_cores, gpu.stack) == ("NVIDIA GeForce RTX 4090", 24.0, 16, "0.6.15")
    mac = hm.hardware_of(fixture_facts("mcmini"))
    assert mac.unified_memory and mac.gpu == "apple-unified" and mac.arch == "arm64"
    cpu = hm.hardware_of(fixture_facts("pop-os"))
    assert cpu.gpu is None and cpu.vram_gb is None and cpu.cpu_cores == 24
    assert hm.hardware_of(None).gpu is None


def test_a_node_that_serves_no_chat_model_is_skipped_not_failed():
    out, _ = _run(_spec([{"node": "robopi"}]), {"running_backends": {"ollama": ""}})
    (cell,) = out.cells
    assert cell.skipped and "serves no chat model" in cell.skip_reason and cell.compare is None
    rows = hm.rows(out, run_id="r", scenario="s")
    assert [r["status"] for r in rows] == ["skipped"], "a skipped cell is one SKIP row, no task failures"


def test_a_scenario_skip_is_recorded_with_its_reason_and_nothing_is_placed():
    out, fake = _run(_spec([{"node": "robopi", "skip": "stunnel image broken"}]), {})
    assert out.cells[0].skip_reason == "stunnel image broken"
    assert fake.writes == []


def test_a_variant_whose_model_is_not_on_the_node_is_refused_without_a_write():
    spec = _spec([{"node": "awolf", "variants": [{"backend": "vllm", "model": "Qwen/Qwen3-32B"}]}])
    out, fake = _run(spec, fixture_facts("awolf"))
    (cell,) = out.cells
    assert cell.skipped and "never downloads" in cell.skip_reason
    assert fake.writes == [], "nothing placed, so nothing to restore"


def test_a_variant_is_placed_measured_and_its_placement_restored():
    spec = _spec([{"node": "awolf", "variants": [{"backend": "vllm", "model": "Qwen/Qwen3-4B-AWQ"}]}])
    out, fake = _run(spec, fixture_facts("awolf"))
    (cell,) = out.cells
    assert not cell.skipped and cell.variant and cell.model == "Qwen/Qwen3-4B-AWQ"
    assert cell.compare is not None and cell.compare.restored, "the harness placement is restored too"
    vllm = [(m, b) for m, p, b in fake.writes if p.endswith("/placements/vllm")]
    assert vllm[0][0] == "PUT" and vllm[0][1]["model"] == "Qwen/Qwen3-4B-AWQ"
    assert vllm[-1][0] == "DELETE", "the node had no vllm placement before: the run's is removed"
    assert cell.restored


def test_rows_slices_and_trend_count_what_they_claim():
    out, _ = _run(_spec([{"node": "awolf"}]), fixture_facts("awolf"))
    rows = hm.rows(out, run_id="r1", scenario="s")
    assert {r["kind"] for r in rows} == {"noo", "codex"}
    assert all(r["hw_gpu"] == "NVIDIA GeForce RTX 4090" and r["backend"] == "vllm" for r in rows)
    by = hm.slice_by(rows, "backend")["vllm"]
    for kind in ("noo", "codex"):
        mine = [r for r in rows if r["kind"] == kind]
        assert by[kind]["ran"] == len(mine)
        assert by[kind]["passed"] == sum(r["status"] == "pass" for r in mine)
    skipped = [{"run": "r1", "kind": None, "status": "skipped", "node": "robopi"}]
    assert "robopi" not in hm.slice_by(rows + skipped, "node"), "a skipped cell is never counted"

    hist = [{**r, "run": "r0", "status": "fail"} for r in rows] + rows
    tr = hm.trend(hist)
    assert [x for x, _ in tr["noo"]] == [0, 1] and tr["noo"][0][1] == 0.0


def test_history_appends_and_reads_back(tmp_path):
    p = tmp_path / "h.jsonl"
    hm.append_history(p, [{"run": "a", "status": "pass"}])
    hm.append_history(p, [{"run": "b", "status": "fail"}])
    assert [r["run"] for r in hm.read_history(p)] == ["a", "b"]
    assert hm.read_history(tmp_path / "missing.jsonl") == []


def test_the_fixture_run_writes_report_json_and_history(tmp_path):
    out = tmp_path / "m.html"
    hist = tmp_path / "h.jsonl"
    for day in ("2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z"):
        assert eval_run.main(["run", str(SAMPLE), "--fixture", "--out", str(out),
                              "--history", str(hist), "--started-at", day]) == 0
    html = out.read_text()
    assert "SYNTHETIC" in html and "harness matrix" in html
    assert html.count("<svg") == 9, "two charts for each of four slices, plus the trend"
    for slice_title in ("each cell", "hardware (GPU)", "backend", "model"):
        assert f"By {slice_title}" in html
    assert "SKIPPED" in html and "robopi" in html
    rows = hm.read_history(hist)
    assert len({r["run"] for r in rows}) == 2
    assert sum(r["status"] == "skipped" for r in rows) == 2, "robopi, once per run"
    twin = json.loads(out.with_suffix(".json").read_text())
    assert [c["node"] for c in twin["cells"]] == ["awolf", "mcmini", "pop-os", "robopi"]
    assert "history" not in twin


def test_a_refused_run_renders_why_and_charts_nothing():
    res = RunResult(scenario="Harness matrix", harness_matrix=hm.HarnessMatrix(kinds=["noo"], refused="busy: x is held"))
    html = report.build_html(res)
    assert "Not run" in html and "busy: x is held" in html and "<svg" not in html
