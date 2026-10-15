# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Core ships no licensed add-on's files (N6).

Add-ons are puzzle pieces: a licensed add-on's compose overlay (and anything
else core once carried for it) travels in the add-on's own signed bundle and
is materialised under `<install root>/addons/<name>/` by `noo addons
enable|upgrade`. A file named for one of them reappearing in this tree is the
regression this guards: the overlay would ship in the public slice again and
drift from the add-on's release.

Read from `git ls-files`, the tree that ships, so a scratch file in a
checkout does not trip it. tests/ and docs/ may name add-ons (fixtures and
prose); nothing else may.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# The licensed add-ons, in every spelling a file name has used.
ADDON_NAME = re.compile(r"evolve|trellion[-_]intel", re.IGNORECASE)

# Exact paths allowed to keep an add-on in their name, each with its reason.
ALLOWED = {
    # The frozen Alembic chain (no new revisions since 046): the revision that
    # created the add-on's database role. Renaming a shipped revision file
    # rewrites history every existing database has already applied.
    "src/noomesh/db/migrations/versions/034_evolve_role.py",
}

EXEMPT_TOPS = ("tests/", "docs/")


def _tracked() -> list[str]:
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True)
    return [p for p in out.stdout.decode().split("\0") if p]


def offending(paths: list[str]) -> list[str]:
    return sorted(
        p for p in paths
        if ADDON_NAME.search(p) and not p.startswith(EXEMPT_TOPS) and p not in ALLOWED
    )


def test_the_read_found_the_tree():
    paths = _tracked()
    assert len(paths) > 500, f"git ls-files returned {len(paths)} paths: the read broke"
    assert "docker-compose.cluster.yml" in paths


def test_no_licensed_addon_file_ships_in_core():
    bad = offending(_tracked())
    assert not bad, (
        "core tracks files named for a licensed add-on; they travel in the add-on's signed bundle "
        f"(N6), not here: {bad}"
    )


def test_every_allowed_path_still_exists():
    paths = set(_tracked())
    stale = sorted(ALLOWED - paths)
    assert not stale, f"allowlist entries that no longer exist (remove them): {stale}"


def test_the_matcher_bites():
    planted = [
        "docker-compose.evolve.yml",
        "docker-compose.trellion-intel.yml",
        "Dockerfile.trellion-intel",
        "evolve.routes.json",
        "scripts/check-evolve-overlay-parity.sh",
        "configs/trellion_intel/x.yml",
        "tests/fixtures/evolve.yml",
        "docs/addons/evolve.md",
        "docker-compose.trellion.yml",
    ]
    assert offending(planted) == sorted(planted[:6])
