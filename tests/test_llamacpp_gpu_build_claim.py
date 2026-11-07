# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""noo-cli's claim that the shipped llamacpp image has no GPU build is the
Dockerfile's truth (noomesh-internal i545 45/46). Adding a CUDA build to
docker/Dockerfile.llamacpp fails this until the claim flips, so `place`,
`status` and `verify` never call a GPU llamacpp placement CPU-bound (or the
reverse) by stale assumption."""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _claim() -> bool:
    src = (REPO / "noo-cli/src/commands/cluster_tune.rs").read_text()
    m = re.search(r"pub const LLAMACPP_HAS_GPU_BUILD: bool = (true|false);", src)
    assert m, "LLAMACPP_HAS_GPU_BUILD not found in cluster_tune.rs"
    return m.group(1) == "true"


def _dockerfile_builds_gpu() -> bool:
    text = (REPO / "docker/Dockerfile.llamacpp").read_text()
    return bool(re.search(r"-DGGML_(CUDA|HIP|VULKAN|METAL)=ON", text))


def test_the_cli_claim_matches_the_dockerfile():
    assert _claim() == _dockerfile_builds_gpu(), (
        "noo-cli LLAMACPP_HAS_GPU_BUILD disagrees with docker/Dockerfile.llamacpp: "
        "update the constant (and the place/verify/status wording) with the image"
    )
