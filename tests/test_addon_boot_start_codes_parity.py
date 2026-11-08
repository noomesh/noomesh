# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The add-on boot-start codes are one list, in three byte-identical copies (i509).

`noo addons after-boot` (noo-cli) reports each after-boot start attempt to
the gateway's `POST /api/addons/{addon}/boot-start` with one of these codes,
and the gateway refuses any code it does not list. Each crate reads its own
copy with include_str! from inside its tree (a gateway include outside
gateway-rust/src is not in the image build context:
tests/test_rust_build_context_complete.py). This test keeps the copies
identical, so a code cannot be added on one side only. noo-batch skips
Python, so CI test-core is where this runs.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CANONICAL = REPO / "tests" / "fixtures" / "addon_boot_start_codes.json"
COPIES = [
    REPO / "gateway-rust" / "src" / "testdata" / "addon_boot_start_codes.json",
    REPO / "noo-cli" / "src" / "testdata" / "addon_boot_start_codes.json",
]


def test_every_copy_is_the_canonical_bytes():
    want = CANONICAL.read_bytes()
    for c in COPIES:
        assert c.is_file(), f"{c.relative_to(REPO)} is missing: copy {CANONICAL.relative_to(REPO)} there"
        assert c.read_bytes() == want, (
            f"{c.relative_to(REPO)} differs from {CANONICAL.relative_to(REPO)}; edit the canonical file and copy it to "
            + ", ".join(str(p.relative_to(REPO)) for p in COPIES)
        )


def test_the_list_is_well_formed():
    doc = json.loads(CANONICAL.read_text())
    assert doc["format"] == "noo-addon-boot-start-codes/1"
    assert doc["outcomes"] == ["started", "failed"]
    codes = doc["codes"]
    assert set(codes) == {"launcher_failed", "refused_by_guard", "still_down_after_start", "gateway_wait_timeout"}, (
        "a code was added or removed: update the plan (noomesh-internal i509), the CLI and the gateway together"
    )
    for code, why in codes.items():
        assert re.fullmatch(r"[a-z][a-z0-9_]{2,47}", code), code
        assert isinstance(why, str) and why.strip(), f"{code} has no description"
