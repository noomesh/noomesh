# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""A hyphenated add-on name finds its overlay.

`addon_overlay pai-voice` used to build the variable name
`NOO_PAI-VOICE_PATH`, which bash refuses ("invalid variable name"), so the
overlay was silently dropped and an enabled hyphenated add-on was never
composed. The development override is `NOO_PAI_VOICE_PATH`, the same `-` → `_`
rule the gateway applies to `NOO_<ADDON>_URL`.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _overlay(name: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", f'source scripts/lib-addons.sh && addon_overlay "{name}"'],
        cwd=ROOT,
        env={"PATH": os.environ["PATH"], **env},
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_hyphenated_name_reads_the_underscore_variable(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.example-addon.yml").write_text("services: {}\n")
    r = _overlay("example-addon", {"NOO_EXAMPLE_ADDON_PATH": str(tmp_path)})
    assert "invalid variable name" not in r.stderr, r.stderr
    assert r.stdout == f"{tmp_path}/docker-compose.example-addon.yml", (r.stdout, r.stderr)


def test_an_underscored_name_still_works(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.trellion-intel.yml").write_text("services: {}\n")
    r = _overlay("trellion_intel", {"NOO_TRELLION_INTEL_PATH": str(tmp_path)})
    assert r.stdout == f"{tmp_path}/docker-compose.trellion-intel.yml", (r.stdout, r.stderr)
