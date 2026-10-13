# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for the BackendProfile registry and its wired consumers.

Behavior-identical guarantees: same ports as the historical BACKEND_PORTS,
same health paths as the old inline table, same client selection in
factory.build_llm_client for vllm/llamacpp/ollama, and unknown backends
still fall back to Ollama — while a newly registered api_format="openai"
backend picks up OpenAICompatClient with no factory change.
"""
from __future__ import annotations

import noomesh.backends as bk
from noomesh.factory import build_llm_client
from noomesh.llm import OllamaClient, OpenAICompatClient


# ── registry data matches the historical inline tables ──────────────

def test_port_map_matches_legacy_backend_ports():
    assert bk.port_map() == {"vllm": 8000, "ollama": 11434, "llamacpp": 8085}


def test_gateway_constants_derive_from_registry():
    from noomesh.gateway.constants import BACKEND_PORTS
    assert BACKEND_PORTS == {"vllm": 8000, "ollama": 11434, "llamacpp": 8085}


def test_health_paths_match_legacy_table():
    assert bk.get_profile("vllm").health_path == "/health"
    assert bk.get_profile("ollama").health_path == "/api/tags"
    assert bk.get_profile("llamacpp").health_path == "/v1/models"


def test_gpu_headroom_set_matches_legacy():
    assert bk.gpu_headroom_backends() == {"vllm", "llamacpp", "tgi", "sglang"}


def test_inference_set_matches_legacy():
    assert bk.inference_backends() == {"vllm", "ollama", "llamacpp", "airllm"}


def test_provisionable_matches_node_agent_specs():
    assert set(bk.provisionable_backends()) == {
        "vllm", "llamacpp", "ollama", "airllm", "embedding", "reranker",
    }


def test_no_port_backends_stay_out_of_port_map():
    # parallel_collab skips backends whose port is None — embedding/airllm
    # must not appear in the dial map.
    assert "embedding" not in bk.port_map()
    assert "airllm" not in bk.port_map()


# ── factory: registry-driven client selection ────────────────────────

def test_factory_vllm_and_llamacpp_get_openai_client():
    for bt in ("vllm", "llamacpp"):
        client = build_llm_client("http://x:8000", "m", backend_type=bt)
        assert isinstance(client, OpenAICompatClient), bt


def test_factory_ollama_gets_ollama_client():
    client = build_llm_client("http://x:11434", "m", backend_type="ollama")
    assert isinstance(client, OllamaClient)


def test_factory_unknown_backend_falls_back_to_ollama():
    client = build_llm_client("http://x:1234", "m", backend_type="no-such-backend")
    assert isinstance(client, OllamaClient)


def test_factory_new_openai_backend_just_works():
    """The extension contract: register an api_format="openai" profile and
    the factory serves it with no code change."""
    name = "_test_openai_backend"
    try:
        bk.backend(name, api_format="openai")
        client = build_llm_client("http://x:9000", "m", backend_type=name)
        assert isinstance(client, OpenAICompatClient)
    finally:
        bk._REGISTRY.pop(name, None)


def test_reregistration_overrides():
    name = "_test_override"
    try:
        bk.backend(name, api_format="ollama")
        bk.backend(name, api_format="openai", default_port=7777)
        p = bk.get_profile(name)
        assert p.api_format == "openai" and p.default_port == 7777
    finally:
        bk._REGISTRY.pop(name, None)


# ── wired consumers ──────────────────────────────────────────────────

# test_backend_manager_tables_unchanged was deleted with
# cluster/backend_manager.py (task #23 sweep) — the LIVE port table is
# pinned by test_backend_resolver_ports below.
def test_backend_resolver_ports():
    from noomesh._providers.backend_resolver import GatewayBackendResolver
    r = GatewayBackendResolver()
    assert r.port_for("vllm") == 8000
    assert r.port_for("llamacpp") == 8085
    assert r.port_for("ollama") == 11434
    assert r.port_for("embedding") is None
