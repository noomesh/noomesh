# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A development signing key never ships in a release (i163 part A).

`noo addons trust-key <name> <pubkey> --dev --expires <dur>` trusts a
temporary key for one add-on on one mesh. Three things keep it out of a
release, and this file pins the two that live in workflow and docs text
rather than in Rust (the Rust half, `addon_lock::refuse_dev_in_release` and
`security addon-lock verify`'s refusal of a dev-signed lock, is unit-tested
in noo-cli):

1. The signed stack lock is assembled from image digest rows and two header
   lines only. It never records a key of any kind, and the lock job reads no
   add-on lock, trust section or noomesh.yaml it could take one from.
2. The add-on resign dispatch sends the add-on repositories the stack tag and
   the lock digest, nothing else: each add-on re-signs with its OWN release
   key, verified with `security addon-lock verify` (which refuses a dev key).
3. The `verify` usage that add-on release workflows call names `--dev-key`,
   so a release lane can hand it the development keys it must refuse.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github/workflows/images-release.yml"
USAGE_RS = REPO / "noo-cli/src/usage.rs"

# Anything that would let a key (development or not) reach the stack lock.
KEY_SOURCES = ("noomesh.yaml", "addon_trust", "dev_keys", "addon-lock", "trust-key", "--dev")


def _job(name: str) -> str:
    text = WORKFLOW.read_text()
    i = text.index(f"\n  {name}:\n")
    m = re.search(r"\n  [a-z][a-z0-9-]*:\n", text[i + 1 :])
    return text[i : i + 1 + m.start()] if m else text[i:]


def _step(job: str, title: str) -> str:
    i = job.index(f"- name: {title}")
    j = job.find("\n      - name:", i)
    return job[i:] if j < 0 else job[i:j]


def test_the_stack_lock_is_digest_rows_and_headers_only() -> None:
    step = _step(_job("lock"), "Assemble + sign stack-$TAG.lock")
    assembled = [l.strip() for l in step.splitlines() if '> "stack-$TAG.lock"' in l]
    assert len(assembled) == 1, f"expected one line that writes the lock, found {assembled}"
    line = assembled[0]
    assert line == '{ echo "# stack $TAG"; echo "# mesh-migration-head $head"; cat digests/* | sort; } > "stack-$TAG.lock"', (
        "the stack lock must be built from the tag line, the migration head and image digest rows only; "
        f"anything else could carry a key into a signed release: {line}"
    )


def test_the_lock_job_reads_no_addon_trust_or_key() -> None:
    job = _job("lock")
    # Comments may name what is forbidden; the commands may not.
    code = "\n".join(l for l in job.splitlines() if not l.strip().startswith("#"))
    for word in KEY_SOURCES:
        assert word not in code, f"the stack lock job mentions {word!r}: a release must never read an add-on key"


def test_the_addon_dispatch_sends_the_tag_and_lock_digest_only() -> None:
    job = _job("addon-dispatch")
    payload = re.search(r'"client_payload":\{([^}]*)\}', job)
    assert payload, "the dispatch payload was not found; the guard cannot read what is sent"
    keys = re.findall(r'"([a-z_]+)":', payload.group(1))
    assert keys == ["tag", "lock_digest"], f"the add-on dispatch must send only the tag and lock digest, sends {keys}"


def test_release_verification_can_be_told_which_keys_are_development_keys() -> None:
    text = USAGE_RS.read_text()
    row = next(l for l in text.splitlines() if '&["security", "addon-lock", "verify"]' in l)
    assert "[--dev-key <pubkey>]..." in row, row
