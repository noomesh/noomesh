# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The CLI's throwaway helper container rides the stack's own nginx image.

The bind-mount probe, the data-dir chown and `noo cluster verify`'s `du` used
to run Docker Hub's `alpine` by tag, so a default install contacted Docker
Hub. They now run the mirrored nginx (ghcr.io/noomesh/nginx, by digest), which
a default install pulls anyway as `model-cache`. These tests keep the three
facts that make that true: the image is in the default pull set, it is the
SAME lock row the stack pins (one bump moves both), and no runtime CLI code
names a Docker Hub image."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_TEXT = (ROOT / "docker-compose.cluster.yml").read_text()
HELPER_RS = (ROOT / "noo-cli/src/helper_image.rs").read_text()


def _lock_mod():
    spec = importlib.util.spec_from_file_location("slt", ROOT / "scripts/stack-lock-third-party.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


M = _lock_mod()
MODEL_CACHE = yaml.safe_load(COMPOSE_TEXT)["services"]["model-cache"]


def test_the_helper_image_is_in_the_default_pull_set():
    # The default standalone install runs profiles controller + standalone
    # (onboard pulls `--profile controller`); model-cache is in both, with no
    # further profile and no replicas: 0.
    assert set(MODEL_CACHE["profiles"]) == {"controller", "standalone"}
    assert MODEL_CACHE.get("deploy", {}).get("replicas", 1) != 0
    assert MODEL_CACHE["image"].startswith("ghcr.io/noomesh/nginx:")


def test_the_helper_rides_the_nginx_lock_row():
    assert M.HELPER_ROW == "nginx" and M.HELPER_ROW in M.THIRD_PARTY
    assert f'HELPER_LOCK_ROW: &str = "{M.HELPER_ROW}"' in HELPER_RS
    # The same compose line the lock job resolves is the one the CLI parses.
    assert M.compose_version("nginx", COMPOSE_TEXT)
    assert M.digest_var("nginx") == "NOO_IMAGE_DIGEST_NGINX"
    assert "${NOO_IMAGE_DIGEST_NGINX:-" in HELPER_RS
    lines = [l for l in COMPOSE_TEXT.splitlines() if l.strip().startswith("image: ghcr.io/noomesh/nginx:")]
    assert len(lines) == 1, "the CLI reads ONE nginx image line"
    assert re.fullmatch(r"\s*image: ghcr\.io/noomesh/nginx:[\w.-]+\$\{NOO_IMAGE_DIGEST_NGINX:-@sha256:[0-9a-f]{64}\}", lines[0])

