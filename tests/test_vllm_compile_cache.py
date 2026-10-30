# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The compose vLLM engines keep their compile caches on a named volume
(followup i305), as the agent's noo-vllm does.

vLLM compiles (torch.compile, Triton) on its first requests after every start,
and the caches lived in the container layer, so each recreate paid ~25 s on the
first chat. Each compose engine mounts its own plain named volume at vLLM's
cache root and points every cache env var under it, the same paths the agent
sets (node-agent-go/internal/docker/backends.go).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE = yaml.safe_load((REPO_ROOT / "docker-compose.cluster.yml").read_text())
BACKENDS_GO = (REPO_ROOT / "node-agent-go" / "internal" / "docker" / "backends.go").read_text()
CACHE_GO = (REPO_ROOT / "node-agent-go" / "internal" / "docker" / "compile_cache.go").read_text()

TARGET = "/root/.cache/vllm"
CACHE_ENV = {
    "VLLM_CACHE_ROOT": TARGET,
    "TRITON_CACHE_DIR": f"{TARGET}/triton",
    "TORCHINDUCTOR_CACHE_DIR": f"{TARGET}/inductor",
    "FLASHINFER_WORKSPACE_BASE": f"{TARGET}/flashinfer",
}
ENGINES = {"vllm": "vllm-compile-cache", "vllm-secondary": "vllm-secondary-compile-cache"}


def _env(service: dict) -> dict[str, str]:
    env = service.get("environment") or []
    if isinstance(env, dict):
        return {k: str(v) for k, v in env.items()}
    return dict(e.split("=", 1) for e in env)


def test_each_compose_engine_mounts_its_compile_cache_volume():
    volumes = COMPOSE["volumes"]
    for name, vol in ENGINES.items():
        mounts = COMPOSE["services"][name].get("volumes") or []
        assert f"{vol}:{TARGET}" in mounts, f"{name}: no {vol} at {TARGET} in {mounts}"
        assert vol in volumes, f"{vol} is not declared under top-level volumes"
        # A plain named volume, not a data-root bind: nothing for onboard to
        # create and no host root for the data-root policy.
        assert not (volumes[vol] or {}).get("driver_opts"), f"{vol} must be a plain named volume"


def test_each_compose_engine_points_every_cache_at_the_volume():
    for name in ENGINES:
        env = _env(COMPOSE["services"][name])
        for key, want in CACHE_ENV.items():
            assert env.get(key) == want, f"{name}: {key}={env.get(key)!r}, want {want!r}"
        assert "XDG_CACHE_HOME" not in env, f"{name}: XDG_CACHE_HOME moves the HF cache off its mount"


def test_compose_and_agent_use_the_same_paths():
    assert f'VLLMCompileCacheTarget = "{TARGET}"' in CACHE_GO
    for key, want in CACHE_ENV.items():
        suffix = want[len(TARGET):]
        expr = "VLLMCompileCacheTarget" + (f' + "{suffix}"' if suffix else "")
        assert re.search(rf'"{key}":\s+{re.escape(expr)},', BACKENDS_GO), f"agent vllm spec lacks {key}: {expr}"
    assert re.search(r"\{Source: VLLMCompileCacheVolume, Target: VLLMCompileCacheTarget, Volume: true\}", BACKENDS_GO)
