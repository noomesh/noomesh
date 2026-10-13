# SPDX-License-Identifier: AGPL-3.0-only
"""The CLA gate is declared in three places that cannot see each other:

  internal/noomesh/licensing/cla.yml   the kit master
  .github/workflows/cla.yml            this repo's copy (ships to noomesh/noomesh)
  trellion/.github/workflows/cla.yml   the sibling's copy (ships to personifai/trellion)

They must be byte-identical except for the one job-level repo guard, and each
guard must name ITS public repo: the private source repos have no CLA_PAT, so an
unguarded copy would fail every PR there, and a copy guarded with the wrong
name would run the gate in the wrong place (or never). The CLA URL it cites
must point at a CLA.md that the sync / snapshot really publishes.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
KIT = REPO / "internal/noomesh/licensing/cla.yml"
OWN = REPO / ".github/workflows/cla.yml"
# PAI_TRELLION_CHECKOUT points the comparison at a worktree of the sibling.
SIBLING = Path(os.environ.get("PAI_TRELLION_CHECKOUT", REPO.parent / "trellion")) / ".github/workflows/cla.yml"

OWN_PUBLIC = "noomesh/noomesh"
SIBLING_PUBLIC = "personifai/trellion"
GUARD = re.compile(r"^    if: github\.repository == '([^']+)'$", re.M)
SPDX = "# SPDX-License-Identifier: AGPL-3.0-only"


def _guard(text: str) -> str:
    found = GUARD.findall(text)
    assert len(found) == 1, f"expected exactly one job-level repo guard, found {found}"
    return found[0]


def _normalised(text: str) -> str:
    return GUARD.sub("    if: github.repository == '<public>'", text)


def test_kit_and_repo_copy_carry_the_noomesh_guard():
    assert _guard(KIT.read_text()) == OWN_PUBLIC
    assert _guard(OWN.read_text()) == OWN_PUBLIC


def test_kit_and_repo_copy_are_identical():
    assert KIT.read_text() == OWN.read_text()


def test_guard_is_on_the_job_not_a_step():
    """A step-level guard would leave the job running (and failing on the
    missing secret) in the private repo; only a job-level `if` skips it."""
    text = OWN.read_text()
    job = text[text.index("\njobs:\n"):]
    head = job.split("steps:", 1)[0]
    assert GUARD.search(head), "the repo guard must sit between `cla:` and `steps:`"


def test_workflow_is_the_pull_request_target_gate():
    text = OWN.read_text()
    assert "pull_request_target:" in text and "issue_comment:" in text
    assert "contributor-assistant/github-action@" in text
    assert "secrets.CLA_PAT" in text
    assert "branch: 'cla-signatures'" in text
    # founders and bots stay allowlisted
    allow = re.search(r"allowlist: '([^']*)'", text).group(1).split(",")
    for who in ("personifai-llc", "richard-raithel", "dependabot[bot]", "github-actions[bot]"):  # leak-ok: public GitHub handles of the founders
        assert who in allow


def test_cla_url_points_at_the_published_cla_on_main():
    text = OWN.read_text()
    url = re.search(r"path-to-document: '([^']+)'", text).group(1)
    assert url == "https://github.com/${{ github.repository }}/blob/cla-v1.0/CLA.md"
    # CLA.md is at the repo root of the source and sync-to-oss.sh does not exclude it
    assert (REPO / "CLA.md").is_file()
    sync = (REPO / "scripts/sync-to-oss.sh").read_text()
    assert not re.search(r'^\s*"/?CLA\.md"\s*$', sync, re.M)
    # both publish paths use main
    assert "push \"$url\" main:main" in (REPO / "scripts/lib-snapshot.sh").read_text()


def test_header_matches_the_repo_licence():
    assert OWN.read_text().startswith(SPDX + "\n")
    assert KIT.read_text().startswith(SPDX + "\n")


def test_snapshot_requires_the_workflow():
    snap = (REPO / "scripts/snapshot.sh").read_text()
    assert ".github/workflows/cla.yml" in snap


def test_sibling_copy_differs_only_by_its_guard():
    if not SIBLING.is_file():
        pytest.skip(f"no sibling checkout at {SIBLING}; trellion's own test checks its copy")
    text = SIBLING.read_text()
    assert _guard(text) == SIBLING_PUBLIC
    assert _normalised(text) == _normalised(KIT.read_text())


def test_the_cla_action_is_pinned_and_the_allowlist_is_exactly_the_verified_accounts():
    """A tag can move; a SHA cannot. And an allowlisted handle that is not one
    of ours (a typo, a stranger's account) skips the CLA for whoever holds it:
    2026-10-09 the list named one handle that is no GitHub user at all and
    another that is an unrelated account outside the orgs."""
    for path in (OWN, KIT):
        text = path.read_text()
        assert re.search(r"uses: contributor-assistant/github-action@[0-9a-f]{40}\b", text), path
        allow = re.search(r"allowlist: '([^']*)'", text).group(1).split(",")
        assert sorted(allow) == sorted(["personifai-llc", "richard-raithel", "dependabot[bot]", "github-actions[bot]"]), allow  # leak-ok: public GitHub handles of the founders
