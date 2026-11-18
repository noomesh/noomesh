# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""Whether a GPU llama.cpp build exists is the Dockerfiles' truth
(noomesh-internal i545 45/46; the CUDA image since 0.6.28), and three places
act on it: noo-cli (`place`), the gateway (the fit's pool) and the node agent
(the image, the GPU device, N_GPU_LAYERS). Each takes llamacpp as cpu on a
node that cannot use the GPU build (no NVIDIA GPU, no nvidia runtime, compute
capability below 6.0) and, with the claim true, as placed on one that can.
Dropping -DGGML_CUDA=ON from docker/Dockerfile.llamacpp-cuda fails this until
all three flip back, so the three can never disagree."""
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


def _builds_gpu(path: str) -> bool:
    text = "\n".join(l for l in (REPO / path).read_text().splitlines() if not l.lstrip().startswith("#"))
    return bool(re.search(r"-DGGML_(CUDA|HIP|VULKAN|METAL)=ON", text))


def _dockerfile_builds_gpu() -> bool:
    """A GPU llama.cpp build exists: the CUDA image's Dockerfile builds the
    CUDA backend (since 0.6.28). The CPU image never does."""
    return _builds_gpu("docker/Dockerfile.llamacpp-cuda")


def test_the_cuda_dockerfile_builds_cuda_and_the_cpu_one_does_not():
    assert _builds_gpu("docker/Dockerfile.llamacpp-cuda"), "Dockerfile.llamacpp-cuda lost -DGGML_CUDA=ON"
    assert not _builds_gpu("docker/Dockerfile.llamacpp"), "the CPU image must stay a CPU build"


def test_the_cli_claim_matches_the_dockerfile():
    assert _claim("noo-cli") == _dockerfile_builds_gpu(), (
        "noo-cli LLAMACPP_HAS_GPU_BUILD disagrees with docker/Dockerfile.llamacpp-cuda: "
        "update the constant (and the place/verify/status wording) with the image"
    )


def test_the_cli_gateway_and_agent_claims_all_match_the_dockerfile():
    want = _dockerfile_builds_gpu()
    got = {where: _claim(where) for where in CLAIMS}
    assert all(v == want for v in got.values()), (
        f"docker/Dockerfile.llamacpp-cuda builds GPU support: {want}; the claims say {got}. "
        "Flip noo-cli's and the gateway's LLAMACPP_HAS_GPU_BUILD and the agent's "
        "LlamacppHasGPUBuild together with the image"
    )


MIN_CAPS = {
    "noo-cli": ("noo-cli/src/commands/cluster_tune.rs", r'pub const LLAMACPP_MIN_COMPUTE_CAP: &str = "([0-9.]+)";'),
    "gateway": ("gateway-rust/src/placement_fit.rs", r'pub const LLAMACPP_MIN_COMPUTE_CAP: &str = "([0-9.]+)";'),
    "node agent": ("node-agent-go/internal/docker/llamacpp_gpu.go", r'(?m)^const LlamacppMinComputeCap = "([0-9.]+)"$'),
}


def test_the_min_compute_cap_is_the_cuda_images_lowest_arch_in_all_three():
    """Where llamacpp runs on the GPU is decided by the same floor in the CLI,
    the gateway's fit and the agent: the lowest compute capability the CUDA
    image carries code for (its CUDA_ARCHITECTURES; PTX only runs forward, so
    nothing below the lowest arch can run)."""
    text = (REPO / "docker/Dockerfile.llamacpp-cuda").read_text()
    archs = re.search(r'^ARG CUDA_ARCHITECTURES="([^"]+)"', text, re.M).group(1).split(";")
    lowest = min(int(a.split("-")[0]) for a in archs)
    want = f"{lowest // 10}.{lowest % 10}"
    got = {}
    for where, (path, pattern) in MIN_CAPS.items():
        found = re.findall(pattern, (REPO / path).read_text())
        assert len(found) == 1, f"{where}: {found}"
        got[where] = found[0]
    assert set(got.values()) == {want}, f"the image's lowest arch is {want}; the floors say {got}"
