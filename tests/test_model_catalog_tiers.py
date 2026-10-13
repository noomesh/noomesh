# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tier + architecture aware backend/model-class selection.

Covers the gap that made edge nodes (tier 4/5) and arm boards invisible to
`noo models recommended` / add-node auto-placement.
"""
from noomesh.cluster.model_catalog import ModelCatalog as MC


def test_is_arm():
    assert MC.is_arm("aarch64")
    assert MC.is_arm("arm64")
    assert not MC.is_arm("x86_64")
    assert not MC.is_arm(None)


def test_backends_by_tier_x86():
    assert MC.backends_for(1, "x86_64") == ["vllm", "llamacpp", "ollama", "airllm"]
    assert MC.backends_for(2, "x86_64") == ["vllm", "llamacpp", "ollama"]
    assert MC.backends_for(3, "x86_64") == ["llamacpp", "ollama"]
    assert MC.backends_for(4, "x86_64") == ["llamacpp", "ollama"]


def test_arm_never_gets_vllm_or_airllm():
    # host9 is tier 4 aarch64 — must be GGUF only.
    for tier in (1, 2, 3, 4, 5):
        b = MC.backends_for(tier, "aarch64")
        assert "vllm" not in b and "airllm" not in b, f"tier {tier} arm leaked GPU backend: {b}"
    assert MC.backends_for(4, "aarch64") == ["llamacpp", "ollama"]


def test_model_class_shrinks_with_weaker_tier():
    assert MC.model_class_for(1) is None      # tier 1 runs anything
    assert MC.model_class_for(2) == 2
    assert MC.model_class_for(3) == 3
    assert MC.model_class_for(4) == 3          # edge → smallest class
    assert MC.model_class_for(5) == 3


def test_recommend_injects_cached_uncataloged_model(monkeypatch):
    """A cache-resident GGUF the HF catalog doesn't surface must still appear —
    ranked first — so `--auto` picks the LAN-preseedable model."""
    import json as _json
    from typer.testing import CliRunner
    from noomesh.cli import app
    from noomesh.cluster import models_cli

    # Catalog knows only popular Llama GGUFs; host9's local gemma is NOT here.
    monkeypatch.setattr(
        models_cli._catalog, "fetch_models",
        lambda backend, tier=None, limit=20, refresh=False: [
            {"id": "bartowski/Llama-3.2-1B-Instruct-GGUF", "downloads": 500000},
        ] if backend == "llamacpp" else [],
    )
    # But it's cached on the cluster (running on host9).
    monkeypatch.setattr(
        models_cli, "_cached_models",
        lambda: [{"name": "gemma-4-E2B-it-Q4_K_M.gguf", "backend": "llamacpp", "size": "3 GB"}],
    )

    r = CliRunner().invoke(app, ["--json", "models", "recommended", "--tier", "4", "--arch", "aarch64"])
    assert r.exit_code == 0, r.output
    data = _json.loads(r.stdout.strip())
    llama = data["backends"]["llamacpp"]
    assert llama[0]["id"] == "gemma-4-E2B-it-Q4_K_M.gguf", f"cached model not first: {llama}"
    assert llama[0]["cached"] is True
