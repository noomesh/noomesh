# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every `noo onboard --only <section>` in the docs names a section onboard has.

`--only security` appeared in four docs and a followup's roll order, and it
is not a section (`noo-cli/src/onboard/mod.rs` VALID): an operator following
the doc got a refusal mid-roll. The PKI and every service leaf are the
`enrollment` step; secret-store keys are `secrets`.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _valid_sections() -> set[str]:
    src = (ROOT / "noo-cli/src/onboard/mod.rs").read_text()
    m = re.search(r"const VALID: \[&str; \d+\] = \[(.*?)\];", src, re.S)
    assert m, "VALID not found in onboard/mod.rs — the parse broke"
    found = set(re.findall(r'"([a-z]+)"', m.group(1)))
    assert {"secrets", "enrollment", "services"} <= found, found
    return found


def test_every_documented_only_section_exists() -> None:
    valid = _valid_sections()
    bad: list[str] = []
    seen = 0
    assert (ROOT / "docs").is_dir(), "docs/ is missing — the scan has nothing to check"
    # The records are kept outside this repository; skip their
    # roots when absent, loudly. docs/ is never optional.
    for root in ("internal/followups", "internal/proposals"):
        if not (ROOT / root).is_dir():
            print(f"{root} not present, SKIPPED (records are kept outside this repository)")
    for root in ("docs", "internal/followups", "internal/proposals"):
        if not (ROOT / root).is_dir():
            continue
        for f in (ROOT / root).rglob("*.md"):
            for n, line in enumerate(f.read_text().splitlines(), 1):
                for sec in re.findall(r"noo onboard --only ([a-z][a-z,]*)", line):
                    seen += 1
                    for s in sec.split(","):
                        if s not in valid:
                            bad.append(f"{f.relative_to(ROOT)}:{n}: --only {s}")
    assert seen >= 3, f"only {seen} `--only` uses found — the scan broke"
    assert not bad, "not onboard sections (valid: " + ", ".join(sorted(valid)) + "):\n" + "\n".join(bad)
