# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Availability-aware placement matcher."""
from noomesh.cluster.model_placement import (
    estimate_model_vram, match_node_for_model, model_is_cached,
)

# Real fleet shape
HOST3 = {"node_id": "HOST3", "vram_gb": 16, "ram_gb": 16, "current_load": 0.2,
         "available_models": ["gemma-4-12b", "phi4"], "online": True}
HOST8 = {"node_id": "host8", "vram_gb": 6, "ram_gb": 32, "current_load": 0.1,
         "available_models": [], "online": True}
HOST9 = {"node_id": "host9", "vram_gb": 0, "ram_gb": 4, "current_load": 0.1,
          "available_models": ["llama3.2:1b"], "online": True}
FLEET = [HOST3, HOST8, HOST9]


def test_vram_estimate():
    # 12B fp16 ≈ 12*2.1+2 ≈ 27; 12B AWQ ≈ 12*0.6+1.5 ≈ 8.7
    assert estimate_model_vram("some/Model-12B", "AWQ") == 8.7
    assert estimate_model_vram("some/Model-8B", "GGUF") == 6.2


def test_cached_matching_is_tolerant():
    assert model_is_cached("google/gemma-4-12B-it", ["gemma-4-12b"])
    assert model_is_cached("llama3.2:1b", ["llama3.2:1b"])
    assert not model_is_cached("microsoft/Phi-4", ["gemma-4-12b"])


def test_prefers_node_that_has_the_model():
    # A ~7GB model both HOST3 (cached-ish) and host8 could hold; HOST3 has it.
    r = match_node_for_model("phi4", FLEET, vram_need=7.0)
    assert r["node_id"] == "HOST3"
    assert r["needs_pull"] is False and r["on_gpu"] is True


def test_pull_required_when_uncached():
    # A 5GB model host8 can hold but doesn't have → placed there, needs pull.
    r = match_node_for_model("nvidia/Nemotron-Mini-4B-Instruct", FLEET, vram_need=5.0)
    assert r["node_id"] in ("host8", "HOST3")
    assert r["needs_pull"] is True


def test_cpu_fallback_for_tiny_model_on_gpuless_node():
    # 1.5GB model, only host9 (CPU) free enough by RAM after GPU nodes excluded.
    r = match_node_for_model("meta-llama/Llama-3.2-1B", [HOST9], vram_need=1.5)
    assert r["node_id"] == "host9" and r["on_gpu"] is False


def test_no_capable_node():
    r = match_node_for_model("nvidia/Nemotron-3-Ultra-550B", FLEET, vram_need=400.0)
    assert "error" in r


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_batch_plan_spreads_across_nodes():
    from noomesh.cluster.model_placement import plan_model_placements
    # Two ~6GB models, both fit HOST3(16) and host8(6). Without spread both go
    # to HOST3 (best-fit-ish); with spread, the 2nd prefers a different node.
    fleet = [
        {"node_id": "HOST3", "vram_gb": 24, "ram_gb": 16, "current_load": 0.1, "available_models": [], "online": True},
        {"node_id": "host8", "vram_gb": 24, "ram_gb": 32, "current_load": 0.1, "available_models": [], "online": True},
    ]
    plan = plan_model_placements(["nvidia/A-4B", "nvidia/B-4B"], fleet)
    assert len(plan) == 2
    nodes = {p["node_id"] for p in plan}
    assert len(nodes) == 2  # spread across both, not both on one


def test_batch_plan_reports_errors_per_model():
    from noomesh.cluster.model_placement import plan_model_placements
    plan = plan_model_placements(["nvidia/Tiny-1B", "nvidia/Huge-550B"], FLEET)
    assert plan[0].get("node_id")            # tiny placed
    assert "error" in plan[1]                # huge has nowhere to go


def test_reconcile_skips_already_running():
    from noomesh.cluster.model_placement import reconcile_models
    fleet = [
        {"node_id": "HOST3", "vram_gb": 24, "ram_gb": 16, "current_load": 0.1,
         "running_backends": {"vllm": "google/gemma-4-12B-it"}, "available_models": ["gemma-4-12b"], "online": True},
        {"node_id": "host8", "vram_gb": 24, "ram_gb": 32, "current_load": 0.1,
         "running_backends": {}, "available_models": [], "online": True},
    ]
    # gemma-4 already running → only phi4 needs placing
    plan = reconcile_models(["google/gemma-4-12B-it", "microsoft/Phi-4"], fleet)
    assert [p["model"] for p in plan] == ["microsoft/Phi-4"]


def test_reconcile_empty_when_satisfied():
    from noomesh.cluster.model_placement import reconcile_models
    fleet = [{"node_id": "HOST3", "vram_gb": 24, "ram_gb": 16, "current_load": 0.1,
              "running_backends": {"ollama": "phi4"}, "available_models": [], "online": True}]
    assert reconcile_models(["microsoft/Phi-4"], fleet) == []
