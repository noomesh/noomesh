# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The nvidia-exporter image needs NVML from the host driver, not CUDA (i604).

It was built on nvidia/cuda:12.2.0-base-ubuntu22.04, a tag NVIDIA never
rebuilds: its 2023 digest carried 18 fixable HIGH findings, and a newer CUDA
tag would raise the driver floor through NVIDIA_REQUIRE_CUDA. These pin the
rebase: no CUDA base (so no CUDA floor), the `utility` driver capability that
NVML needs, and nvidia-ml-py installed by exact version AND hash.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "docker/Dockerfile.nvidia-exporter"


def _text() -> str:
    return DOCKERFILE.read_text().replace("\\\n", " ")


def test_no_stage_builds_on_a_cuda_base():
    froms = re.findall(r"^FROM\s+(\S+)", DOCKERFILE.read_text(), re.M)
    assert froms, "no FROM parsed"
    assert not [f for f in froms if "cuda" in f.lower()], froms


def test_the_runtime_asks_only_for_the_nvml_capability():
    env = re.findall(r"NVIDIA_DRIVER_CAPABILITIES=(\S+)", _text())
    assert env == ["utility"], env
    assert re.findall(r"NVIDIA_VISIBLE_DEVICES=(\S+)", _text()) == ["all"]


def test_nvml_bindings_are_pinned_by_version_and_hash():
    text = _text()
    assert re.search(r"nvidia-ml-py==\d+\.\d+\.\d+ --hash=sha256:[0-9a-f]{64}", text), "nvidia-ml-py not pinned by version and hash"
    assert "--require-hashes" in text, "pip must refuse an unhashed requirement"
    assert not re.search(r"pip3? install[^\n]*\bnvidia-ml-py(?!==)", text), "an unpinned install remains"
