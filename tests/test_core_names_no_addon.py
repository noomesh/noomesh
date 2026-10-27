# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Core never names an add-on (operator rule: add-ons are puzzle pieces).

The first third-party add-on's name already appears in core, mostly in
comments and test fixtures written before the rule had a guard (the counts
are in tests/fixtures/addon_name_mentions_baseline.json, per file, in lines).
This is a ratchet: no file may mention it on more lines than the baseline
records, and a file the baseline does not list may not mention it at all.
Lowering a count is always allowed; then lower the baseline too. A fixture
add-on in core uses an obviously fictional name (`rhaddon`,
`example-addon`).

Old code: nothing stopped a new mention (i239 section 10 added the add-on
runtime inputs without one, and this test keeps it so)."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve().relative_to(REPO).as_posix()
BASELINE = REPO / "tests" / "fixtures" / "addon_name_mentions_baseline.json"
# Spelled in parts so this file does not match itself.
NAMES = ("pai" + "[-_]" + "voice", "persona" + "plex")


def _counts() -> dict[str, int]:
    out = subprocess.run(
        ["git", "grep", "-c", "-i", "-E", "|".join(NAMES), "--", "."],
        cwd=REPO, capture_output=True, text=True,
    )
    assert out.returncode in (0, 1), out.stderr
    counts = {}
    for line in out.stdout.splitlines():
        path, n = line.rsplit(":", 1)
        if path != SELF:
            counts[path] = int(n)
    return counts


def test_no_new_mention_of_an_addon_name_in_core() -> None:
    base = json.loads(BASELINE.read_text())
    grown = {p: (n, base.get(p, 0)) for p, n in _counts().items() if n > base.get(p, 0)}
    assert not grown, (
        "core names an add-on (lines now, baseline): "
        + ", ".join(f"{p} {n}>{b}" for p, (n, b) in sorted(grown.items()))
        + ". Use a fictional fixture name (rhaddon) instead."
    )


def test_the_runtime_input_contract_names_none() -> None:
    pat = re.compile("|".join(NAMES), re.I)
    for rel in (
        "noo-cli/src/addons/resources.rs",
        "noo-cli/src/commands/addon_resources.rs",
        "docs/reference/addon-resources.schema.json",
        "tests/fixtures/addons/rhaddon/resources.json",
        "tests/fixtures/addons/rhaddon/docker-compose.yml",
        "tests/test_addon_resources_launcher.py",
    ):
        assert not pat.search((REPO / rel).read_text()), rel
