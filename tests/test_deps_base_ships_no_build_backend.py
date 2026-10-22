# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""deps-base ships no build backend.

The ML lock carries hatchling so the local packages build
--no-build-isolation from hashed wheels; nothing removed it afterwards, so
every image FROM deps-base (trellion, and the add-ons built on it) shipped a
build backend. trellion-intel's image asserts it does not, and its resign for
0.6.10-rc.1 failed with "the build backend leaked into the image".
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "docker/Dockerfile.deps-base"


def _ml_run() -> str:
    text = DOCKERFILE.read_text()
    start = text.index("uv pip install --system --require-hashes -r /tmp/requirements-ml.txt")
    end = text.index("\n\n", start)
    return text[start:end]


def test_hatchling_is_removed_after_the_local_builds() -> None:
    run = _ml_run()
    built = run.index("--no-build-isolation")
    removed = run.find("uninstall --system hatchling")
    assert removed > built, "hatchling must be uninstalled after the --no-build-isolation installs"
    assert "import hatchling" in run[removed:], "the RUN must prove hatchling is gone"


def test_the_lock_still_carries_the_backend_for_the_build() -> None:
    lock = (ROOT / "docker/ml-lock/requirements.txt").read_text()
    assert re.search(r"^hatchling==", lock, re.M), "the build needs hatchling hashed in the lock"
