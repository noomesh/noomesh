# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A CLI-side deploy-slice change must never strand a pinned stack (host8,
2026-09-02: the trellion-intel service gained its own image name, stack tag
v0.2.5 had never built it, every start/restart died at pull).

The fallback is three pieces that have to agree: the compose reference honours
NOO_INTEL_IMAGE, lib-dist.sh defines resolve_intel_image (which sets it when
the tag has no dedicated image), and BOTH compose consumers that start the
intel overlay call it. This pins all three."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_compose_intel_image_honours_the_override():
    # The service is its own overlay the earlier change.
    block = (REPO / "docker-compose.trellion-intel.yml").read_text()
    assert "  trellion-intel:" in block
    m = re.search(r"^\s*image:\s*(.+)$", block, re.M)
    assert m, "trellion-intel must declare its own image"
    assert m.group(1).startswith("${NOO_INTEL_IMAGE:-"), m.group(1)
    assert "/trellion-intel:" in m.group(1)


def test_lib_dist_defines_the_resolver():
    lib = (REPO / "scripts/lib-dist.sh").read_text()
    assert "resolve_intel_image()" in lib
    assert 'export NOO_INTEL_IMAGE="${NOO_IMAGE_PREFIX}/trellion:${NOO_IMAGE_TAG}${NOO_IMAGE_DIGEST_TRELLION:-}"' in lib


def test_both_launchers_call_the_resolver():
    for script in ("scripts/noomesh-start.sh", "scripts/noomesh-restart.sh"):
        text = (REPO / script).read_text()
        assert "resolve_intel_image" in text, f"{script} must call resolve_intel_image"
        assert "lib-dist.sh" in text, f"{script} must source lib-dist.sh"
