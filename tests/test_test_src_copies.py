# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The two copies of the source-reading helper stay one file (followup 215).

The gateway is a binary crate and cannot import noo-cli's `test_src.rs`, so
it carries a copy. Two copies drift: a lexer fix in one leaves the other's
guards reading source the old way. Each crate runs every row of
tests/fixtures/test_src_cases.json; this test holds the files themselves
byte-identical, so the fix is made in both or the suite fails.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
COPIES = (REPO / "noo-cli/src/test_src.rs", REPO / "gateway-rust/src/test_src.rs")
CASES = REPO / "tests/fixtures/test_src_cases.json"


def test_both_copies_are_byte_identical() -> None:
    a, b = (p.read_bytes() for p in COPIES)
    assert len(a) > 5000, "the helper shrank to nothing; this check would pass on two empty files"
    assert a == b, "edit noo-cli/src/test_src.rs and gateway-rust/src/test_src.rs together"


def test_both_copies_run_the_shared_cases() -> None:
    rows = json.loads(CASES.read_text())["cases"]
    assert len(rows) >= 6
    for p in COPIES:
        text = p.read_text()
        assert 'include_str!("../../tests/fixtures/test_src_cases.json")' in text, p
        assert "fn every_shared_case_holds()" in text, p
