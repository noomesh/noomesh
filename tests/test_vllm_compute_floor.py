# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The vLLM compute floor is a property of the pinned vLLM image.

The vLLM image is built on one CUDA, and each CUDA supports GPUs from some
compute capability up: CUDA 13 dropped compute < 7.5 (Pascal, Volta), so the
v0.25.0 image cannot start on a Tesla P40 (6.1). The gateway (placement advice,
place refusal), the CLI (onboarding, the `vllm compute` verify row) and the
agent (its start refusal) each declare the floor once, next to what they know
of the image. This test ties all three to the image the stack pins:

- the vLLM image tag read from docker-compose.cluster.yml (both vLLM services)
  and the agent's backends.go must be one tag;
- FLOORS below must know that tag (image tag -> its CUDA -> the lowest compute
  capability that CUDA supports): bumping the image without revisiting the
  floor fails here;
- every language's (tag, CUDA, floor) constants must equal the table's row.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# vLLM image tag -> (the CUDA the image is built on, the lowest GPU compute
# capability that CUDA supports). Read the CUDA from the image (torch.version.cuda
# in the container) and the floor from NVIDIA's CUDA release notes.
FLOORS = {
    "v0.25.0": ("13.0", "7.5"),
}

COMPOSE = ROOT / "docker-compose.cluster.yml"
BACKENDS_GO = ROOT / "node-agent-go/internal/docker/backends.go"

# Where each language declares (tag, CUDA, floor), and how to read each one.
DECLARED = {
    "gateway": (
        ROOT / "gateway-rust/src/routes/cluster.rs",
        r'pub\(crate\) const VLLM_IMAGE_TAG: &str = "([^"]+)";',
        r'pub\(crate\) const VLLM_IMAGE_CUDA: &str = "([^"]+)";',
        r'pub\(crate\) const VLLM_MIN_COMPUTE_CAP: &str = "([^"]+)";',
    ),
    "cli": (
        ROOT / "noo-cli/src/vllm_floor.rs",
        r'pub\(crate\) const VLLM_IMAGE_TAG: &str = "([^"]+)";',
        r'pub\(crate\) const VLLM_IMAGE_CUDA: &str = "([^"]+)";',
        r'pub\(crate\) const VLLM_MIN_COMPUTE_CAP: &str = "([^"]+)";',
    ),
    "agent": (
        BACKENDS_GO,
        r'\n\tVllmImageTag\s+= "([^"]+)"',
        r'\n\tVllmImageCUDA\s+= "([^"]+)"',
        r'\n\tVllmMinComputeCap\s+= "([^"]+)"',
    ),
}


def _one(pattern: str, text: str, where: str) -> str:
    found = re.findall(pattern, text)
    assert len(found) == 1, f"{where}: expected exactly one match of {pattern!r}, found {found}"
    return found[0]


def pinned_vllm_tag() -> str:
    """The vLLM image tag the stack pins, the same in compose and the agent."""
    compose = COMPOSE.read_text()
    tags = set(re.findall(r"image: \$\{VLLM2?_IMAGE:-vllm/vllm-openai:(v[0-9][^@$}\s]*)", compose))
    go = re.findall(r'"\$\{VLLM_IMAGE:-vllm/vllm-openai:(v[0-9][^@$}"]*)\}"', BACKENDS_GO.read_text())
    assert tags, "docker-compose.cluster.yml: no vLLM image tag found"
    assert len(go) == 1, f"backends.go: expected one vLLM image default, found {go}"
    tags.add(go[0])
    assert len(tags) == 1, f"the vLLM image tag differs between compose and the agent: {sorted(tags)}"
    return tags.pop()


def test_vllm_compute_floor_matches_the_pinned_image_everywhere():
    tag = pinned_vllm_tag()
    assert tag in FLOORS, (
        f"the vLLM image moved to {tag}: add it to FLOORS (its CUDA, and the lowest compute "
        f"capability that CUDA supports), then set every language's constants to that row"
    )
    cuda, floor = FLOORS[tag]
    for lang, (path, tag_re, cuda_re, floor_re) in DECLARED.items():
        text = path.read_text()
        where = f"{lang} ({path.relative_to(ROOT)})"
        assert _one(tag_re, text, where) == tag, f"{where}: declares a different vLLM image tag than the pinned {tag}"
        assert _one(cuda_re, text, where) == cuda, f"{where}: the CUDA of {tag} is {cuda}"
        assert _one(floor_re, text, where) == floor, f"{where}: the compute floor of {tag} (CUDA {cuda}) is {floor}"
