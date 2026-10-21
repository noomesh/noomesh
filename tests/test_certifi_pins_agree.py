# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""Every image that pins certifi directly pins the version core-lock holds.

certifi carries the CA bundle Python trusts. 0.6.9 moved core-lock to
2026.10.19 for GHSA-6q48-6c7w-9gw2 (distrusted emSign intermediates), but
docker/Dockerfile.whisper pinned certifi on its own line and kept the
vulnerable 2026.7.22; the 0.6.9-rc.1 rehearsal found it in the running
noo-whisper image. A second pin that drifts from the lock is the way this
recurs, so the two are held equal here.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIN = re.compile(r"\bcertifi==([0-9][0-9.]*)")


def _core_lock_version():
    text = (ROOT / "docker/core-lock/requirements.txt").read_text()
    found = PIN.findall(text)
    assert len(found) == 1, f"core-lock should pin certifi exactly once, found {found}"
    return found[0]


def test_dockerfile_certifi_pins_match_core_lock():
    want = _core_lock_version()
    pins = {}
    for df in sorted((ROOT / "docker").glob("Dockerfile*")):
        for v in PIN.findall(df.read_text()):
            pins.setdefault(df.name, []).append(v)
    assert pins, "no Dockerfile pins certifi directly; drop this test if that is now true"
    stale = {name: vs for name, vs in pins.items() if any(v != want for v in vs)}
    assert not stale, f"certifi pins disagree with core-lock {want}: {stale}"
