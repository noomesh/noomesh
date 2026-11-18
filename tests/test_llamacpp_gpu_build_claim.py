# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The claim that the shipped llamacpp image has no GPU build is the
Dockerfile's truth (noomesh-internal i545 45/46), and three places act on it:
noo-cli (`place` swaps gpu to cpu), the gateway (the fit puts llamacpp in the
CPU pool) and the node agent (no GPU device, N_GPU_LAYERS=0). Adding a CUDA
build to docker/Dockerfile.llamacpp fails this until all three flip, so no
layer calls a GPU llamacpp placement CPU-bound (or the reverse) by stale
assumption, and the three can never disagree."""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

CLAIMS = {
    "noo-cli": ("noo-cli/src/commands/cluster_tune.rs",
                r"pub const LLAMACPP_HAS_GPU_BUILD: bool = (true|false);"),
    "gateway": ("gateway-rust/src/placement_fit.rs",
                r"pub const LLAMACPP_HAS_GPU_BUILD: bool = (true|false);"),
    "node agent": ("node-agent-go/internal/docker/backends.go",
                   r"(?m)^const LlamacppHasGPUBuild = (true|false)$"),
}


def _claim(where: str) -> bool:
    path, pattern = CLAIMS[where]
    found = re.findall(pattern, (REPO / path).read_text())
    assert len(found) == 1, f"{where}: expected one llamacpp GPU-build constant in {path}, found {found}"
    return found[0] == "true"


def _dockerfile_builds_gpu() -> bool:
    text = (REPO / "docker/Dockerfile.llamacpp").read_text()
    return bool(re.search(r"-DGGML_(CUDA|HIP|VULKAN|METAL)=ON", text))


def test_the_cli_claim_matches_the_dockerfile():
    assert _claim("noo-cli") == _dockerfile_builds_gpu(), (
        "noo-cli LLAMACPP_HAS_GPU_BUILD disagrees with docker/Dockerfile.llamacpp: "
        "update the constant (and the place/verify/status wording) with the image"
    )


def test_the_cli_gateway_and_agent_claims_all_match_the_dockerfile():
    want = _dockerfile_builds_gpu()
    got = {where: _claim(where) for where in CLAIMS}
    assert all(v == want for v in got.values()), (
        f"docker/Dockerfile.llamacpp builds GPU support: {want}; the claims say {got}. "
        "Flip noo-cli's and the gateway's LLAMACPP_HAS_GPU_BUILD and the agent's "
        "LlamacppHasGPUBuild together with the image"
    )
