# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""noo-apply refuses to downgrade noo-hostd (an earlier change second review, L3).

`hostd_generation_of` reads the `noo-hostd-generation=NN;` marker a hostd
binary carries (node-agent-go/cmd/noo-hostd/generation.go) and the hostd
block refuses a payload whose generation is lower than the installed one,
before anything is copied or installed."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
APPLIER = (REPO / "scripts/noo-apply.sh").read_text()
GO = (REPO / "node-agent-go/cmd/noo-hostd/generation.go").read_text()


def gen(path: Path) -> str:
    fn = re.search(r"(hostd_generation_of\(\) \{.*?\n\})", APPLIER, re.S).group(1)
    return subprocess.run(["bash", "-c", f'{fn}\nhostd_generation_of "{path}"'],
                          capture_output=True, text=True, check=True).stdout.strip()


def test_the_marker_is_read_and_a_missing_one_is_zero(tmp_path: Path) -> None:
    marker = re.search(r'hostdGenerationMarker = "([^"]+)"', GO).group(1)
    b = tmp_path / "hostd"
    b.write_bytes(b"\x7fELF...." + marker.encode() + b"\x00more")
    assert gen(b) == str(int(re.search(r"=(\d+);", marker).group(1)))
    old = tmp_path / "old"
    old.write_bytes(b"\x7fELF no marker")
    assert gen(old) == "0"
    assert gen(tmp_path / "absent") == "0"
    evil = tmp_path / "evil"
    evil.write_bytes(b"noo-hostd-generation=$(id);")
    assert gen(evil) == "0"


def test_the_floor_runs_before_the_install() -> None:
    block = APPLIER[APPLIER.index('if [ -f "$WORK/files/hostd-binary" ]; then'):]
    assert block.index('_hg_new" -lt "$_hg_cur"') < block.index('install -m 755 -o root -g root "$WORK/files/hostd-binary"')
