# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every refusal code the node applier exits with has a row in the CLI's table.

`noo cluster provision` and `noo upgrade --nodes` turn a node's applier exit
code into a stable code, a plain reason and the next command through ONE
function, `apply_refusal` in noo-cli/src/commands/provision.rs. A code the
script gains without a row there would fall back to the generic
`apply_failed_unknown_rc` text. This guard reads the script's own `exit N`
set (and noo-fetch.sh's gzip refusal, 69) and the table's `N => Some(` arms,
and holds them equal. The Rust unit tests check the rows themselves.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
APPLIER = (REPO / "scripts" / "noo-apply.sh").read_text()
FETCHER = (REPO / "scripts" / "noo-fetch.sh").read_text()
PROVISION = (REPO / "noo-cli" / "src" / "commands" / "provision.rs").read_text()


def _code_lines(src: str) -> list[str]:
    return [line for line in src.splitlines() if not line.lstrip().startswith("#")]


def script_refusal_codes() -> set[int]:
    """`exit N` outside comments; 0 is success and 1 is set -e's generic failure."""
    codes = {int(n) for line in _code_lines(APPLIER) for n in re.findall(r"\bexit (\d+)", line)}
    codes |= {int(n) for line in _code_lines(FETCHER) for n in re.findall(r"\breturn (69)\b", line)}
    return {c for c in codes if c > 1}


def table_codes() -> set[int]:
    start = PROVISION.index("pub(crate) fn apply_refusal(rc: i64) -> ApplyRefusal {")
    end = PROVISION.index("\n}\n", start)
    body = PROVISION[start:end]
    return {int(n) for n in re.findall(r"^\s*(\d+) => Some\(ApplyRefusal \{", body, re.M)}


def test_the_script_codes_were_read():
    codes = script_refusal_codes()
    assert {65, 75, 76, 77} <= codes, codes


def test_every_script_refusal_has_a_row():
    missing = script_refusal_codes() - table_codes()
    assert not missing, f"applier exit codes with no row in apply_refusal: {sorted(missing)}"


def test_no_row_for_a_code_the_scripts_never_exit_with():
    stale = table_codes() - script_refusal_codes()
    assert not stale, f"apply_refusal rows for codes no script exits with: {sorted(stale)}"
