# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A dropped connection to GitHub must not read as a missing release asset.

On 2026-09-20 one TLS handshake to api.github.com failed mid-release and
the stack build died reporting `noo-cli-v0.5.46 does not publish
noo-x86_64-unknown-linux-gnu` — an asset that was published and still is.
`||` collapses every failure into one sentence, so a transport error, an
expired token, a rate limit and a genuinely absent file all accuse the
release. The re-run passed unchanged, which is the tell.

The refusal itself is correct — never run an unverifiable signing binary.
What was wrong is the cause it named, and that it gave up on the first
try for a network call to a third party.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github/workflows/images-release.yml"


def _step() -> str:
    text = WORKFLOW.read_text()
    i = text.index("Fetch and verify the signing CLI")
    j = text.index("\n      - name:", i)
    return text[i:j]


def test_the_download_is_retried_before_it_fails_a_release() -> None:
    step = _step()
    assert "for attempt in" in step, "a network call in a release must be retried"
    assert "sleep" in step, "retries must back off, not hammer"


def test_a_transport_failure_is_not_reported_as_a_missing_asset() -> None:
    step = _step()
    # The two causes must produce DIFFERENT sentences, and the transport one
    # must say what to do about it.
    assert "does not publish" in step, "a genuinely missing asset must still say so"
    assert "not a missing asset" in step, (
        "a transport failure must say it is NOT a missing asset — that wording "
        "is what sends the reader to the network instead of the release"
    )
    assert "Re-run this job" in step, "the transport case must name the remedy"
    # It distinguishes them by ASKING, not by guessing from the exit code.
    assert "gh release view" in step and "assets" in step, (
        "the two causes must be separated by checking whether the release "
        "lists the asset, not inferred"
    )


def test_the_refusal_still_refuses() -> None:
    """Retrying must not turn a genuine failure into a pass."""
    step = _step()
    # Every path out of the loop that is not a successful download exits 1.
    assert re.search(r"exit 1\s*\n\s*done", step), (
        "a download that never succeeds must still fail the job"
    )
    assert "unverifiable signing binary" in step
