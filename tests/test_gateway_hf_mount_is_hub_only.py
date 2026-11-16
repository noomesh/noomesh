# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The gateway reads the controller's HF cache for the `hf` artifact manifest
(i675 F13) through HF_CACHE_DIR/hub, read-only, and nothing wider.

HF_CACHE_DIR is an HF_HOME: huggingface_hub writes `token` and
`stored_tokens` at its root, one level ABOVE hub/. The gateway is the
web-facing process; mounting the HF_HOME would let it read the token. The
route (gateway-rust/src/routes/artifacts.rs `hf_hub_dir`) reads only hub/,
and the mount gives it nothing else.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE = REPO_ROOT / "docker-compose.cluster.yml"
ARTIFACTS_RS = REPO_ROOT / "gateway-rust/src/routes/artifacts.rs"


def _gateway_volumes() -> list[str]:
    svc = yaml.safe_load(COMPOSE.read_text())["services"]["gateway"]
    return [v for v in svc.get("volumes") or [] if isinstance(v, str)]


def test_the_gateway_mounts_only_hf_cache_hub_read_only():
    hf = [v for v in _gateway_volumes() if "HF_CACHE_DIR" in v]
    assert len(hf) == 1, f"the gateway must mount the HF cache exactly once: {hf}"
    src, target, mode = hf[0].rsplit(":", 2)
    assert src.endswith("/hf-cache}/hub"), f"the source must be HF_CACHE_DIR/hub, not the HF_HOME: {src}"
    assert target == "/artifacts/hf/hub", target
    assert mode == "ro", f"the HF mount must be read-only: {hf[0]}"


def test_the_route_reads_the_hub_mount():
    src = ARTIFACTS_RS.read_text()
    assert re.search(r'"/artifacts/hf/hub"', src), "hf_hub_dir's default no longer matches the mount target"
    assert 'join("token")' not in src and "stored_tokens\")" not in src
