# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Backend profile registry — the single Python-side table of per-backend-type
metadata.

This package used to hold a 10-method ``BaseBackend`` ABC + registry +
VRAM-heuristic selector that was never instantiated anywhere. That layer was
deleted (2026-07): the *live* inference abstraction is the 2-method
``LLMClient`` Protocol in ``noomesh.llm``, actual container specs (image,
command, env, GPU flags) live in the Go node-agent
(``node-agent-go/internal/docker/backends.go``), and the hardware-fit
placement brain is ``noomesh.cluster.placement`` (pure logic) plus the Rust
scheduler routing on ``capabilities.backends``.

What Python still needs — and what was duplicated across five modules — is
small per-backend *data*: which wire API a backend speaks, which port it is
dialed on, its health path, and a couple of placement flags. That data now
lives here, once, as open ``BackendProfile`` records:

- ``gateway.constants.BACKEND_PORTS`` / ``_providers.backend_resolver``
  derive their port maps from :func:`port_map`.
- ``cluster.backend_manager`` derives health paths and the GPU-headroom /
  inference-count sets from the profiles.
- ``cluster.cli`` derives its backend tab-completion list.
- ``factory.build_llm_client`` picks the client class from ``api_format``
  ("openai" → ``OpenAICompatClient``, anything else → ``OllamaClient``).

Adding a backend = one :func:`backend` call (see docs/models/adding-a-backend.md).
The registry is open: third-party/plugin code may register at import time.
OpenAI-compatible HTTP is the primary extension point — a new backend that
speaks ``/v1/chat/completions`` needs nothing but a profile with
``api_format="openai"``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class BackendProfile:
    """Per-backend-type metadata. Pure data — no I/O, no hooks required.

    ``default_port`` is the port *Python* dials the backend on directly
    (mesh/collab URL construction). ``None`` means Python never builds a
    URL from a port for this backend (it is reached via the node-agent or
    dedicated config instead) — keep it ``None`` unless a Python consumer
    genuinely dials it, because callers treat "no port" as "skip".
    """

    name: str
    api_format: str = "openai"          # "openai" | "ollama" | "tei"
    default_port: Optional[int] = None  # port Python dials directly, or None
    health_path: str = "/health"        # readiness probe path on default_port
    needs_gpu_headroom: bool = False    # require free-VRAM check before placement
    counts_as_inference: bool = False   # counts against max_backends_per_node (LRU eviction)
    provisionable: bool = False         # Go node-agent has a container spec (noo cluster up <name>)
    description: str = ""


_REGISTRY: Dict[str, BackendProfile] = {}


def backend(name: str, **fields) -> BackendProfile:
    """Create and register a :class:`BackendProfile`. Re-registering a name
    replaces the previous profile (last writer wins — lets deployments
    override a built-in)."""
    profile = BackendProfile(name=name, **fields)
    _REGISTRY[name] = profile
    return profile


def register(profile: BackendProfile) -> BackendProfile:
    """Register an already-constructed profile."""
    _REGISTRY[profile.name] = profile
    return profile


def get_profile(name: str) -> Optional[BackendProfile]:
    return _REGISTRY.get(name)


def profiles() -> Tuple[BackendProfile, ...]:
    """All registered profiles, in registration order."""
    return tuple(_REGISTRY.values())


def api_format(name: str, default: str = "ollama") -> str:
    p = _REGISTRY.get(name)
    return p.api_format if p else default


def port_map() -> Dict[str, int]:
    """name → default_port for backends Python dials directly.
    Mirrors the historical ``gateway.constants.BACKEND_PORTS`` shape."""
    return {p.name: p.default_port for p in _REGISTRY.values()
            if p.default_port is not None}


def gpu_headroom_backends() -> set:
    return {p.name for p in _REGISTRY.values() if p.needs_gpu_headroom}


def inference_backends() -> set:
    return {p.name for p in _REGISTRY.values() if p.counts_as_inference}


def provisionable_backends() -> Tuple[str, ...]:
    return tuple(p.name for p in _REGISTRY.values() if p.provisionable)


# ── Built-in profiles ────────────────────────────────────────────────
# Ports/paths must match the cluster contract: Go node-agent BackendPorts
# (node-agent-go/internal/docker/client.go) and the Rust gateway's
# backend_health table (gateway-rust/src/routes/cluster.rs).

backend(
    "vllm", api_format="openai", default_port=8000, health_path="/health",
    needs_gpu_headroom=True, counts_as_inference=True, provisionable=True,
    description="vLLM OpenAI server — CUDA-only Tier-1 GPU engine",
)
backend(
    "llamacpp", api_format="openai", default_port=8085, health_path="/v1/models",
    needs_gpu_headroom=True, counts_as_inference=True, provisionable=True,
    description="llama.cpp server — GPU or CPU, the small-node engine",
)
backend(
    "ollama", api_format="ollama", default_port=11434, health_path="/api/tags",
    counts_as_inference=True, provisionable=True,
    description="Ollama — native API; the darwin/Metal and easy-CPU path",
)
backend(
    "airllm", api_format="openai", counts_as_inference=True, provisionable=True,
    description="AirLLM layered offload (node-agent dials it at 8000; "
                "Python never builds its URL from a port)",
)
backend(
    "embedding", api_format="tei", provisionable=True,
    description="HuggingFace TEI embedder (mesh-routed; TLS via stunnel)",
)
backend(
    "reranker", api_format="tei", provisionable=True,
    description="HuggingFace TEI reranker (mesh-routed via node-agent /rerank)",
)
# Referenced by backend_manager's GPU-headroom check and placement override
# warnings; the node-agent has no container spec for these (operator-run /
# external only), so they are not provisionable.
backend(
    "tgi", api_format="openai", needs_gpu_headroom=True,
    description="Text Generation Inference — external/operator-run only",
)
backend(
    "sglang", api_format="openai", needs_gpu_headroom=True,
    description="SGLang — external/operator-run only",
)


__all__ = [
    "BackendProfile",
    "backend",
    "register",
    "get_profile",
    "profiles",
    "api_format",
    "port_map",
    "gpu_headroom_backends",
    "inference_backends",
    "provisionable_backends",
]
