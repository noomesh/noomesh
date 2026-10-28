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
