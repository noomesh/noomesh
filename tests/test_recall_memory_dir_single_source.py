# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""NOO_RECALL_MEMORY_PATH is the one source of the recall-memory directory.

The stack sets it (docker-compose.trellion.yml), together with the deprecated
NOO_VIDEO_MEMORY_PATH that trellion's own config still reads;
noomesh must not carry a second default of its own (the old
/data/video-memory default split the facade from recall, pack and unpack).
The directory itself keeps its historical name, /data/video_memory.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_no_hyphen_literal_in_python_source():
    offenders = [
        str(p.relative_to(ROOT))
        for p in (ROOT / "src").rglob("*.py")
        if re.search(r"/data/video-memory", p.read_text())
    ]
    assert not offenders, offenders


def test_config_default_follows_env(monkeypatch):
    from noomesh.config import RecallMemoryConfig

    monkeypatch.delenv("NOO_VIDEO_MEMORY_PATH", raising=False)
    monkeypatch.setenv("NOO_RECALL_MEMORY_PATH", "/somewhere/else")
    assert RecallMemoryConfig().storage_dir == "/somewhere/else"
    monkeypatch.delenv("NOO_RECALL_MEMORY_PATH")
    assert RecallMemoryConfig().storage_dir == "/data/video_memory"


def test_worker_pool_passes_the_env_dir_to_the_manager():
    src = (ROOT / "src/noomesh/gateway/worker_pool.py").read_text()
    assert "_vm_dir = recall_memory_path_env()" in src
    assert "vm_config.storage_dir = _vm_dir" in src


def test_compose_sets_the_single_path_for_the_trellion_service():
    base = (ROOT / "docker-compose.trellion.yml").read_text()
    assert "NOO_RECALL_MEMORY_PATH: '/data/video_memory'" in base
    # trellion reads only the old name until its sibling change ships.
    assert "NOO_VIDEO_MEMORY_PATH: '/data/video_memory'" in base
    # trellion-intel's "inherits the base env via extends" check: moved with the
    # overlay to the add-on repo (N6).
