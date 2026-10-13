#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A PR that names a prerequisite cannot merge before it.

On 2026-09-05, #1188 (retire the SSH gate lane) listed three prerequisites
in its own body — the rails that had to exist before the transport it
deletes could go. Two agents agreed it must merge last, said so twice, and
recorded it in the tracker. It merged third anyway, before #1197, leaving
dev in a state where a freshly enrolled node had no way to receive a fleet
secret.

Nobody was careless. The constraint lived in a message thread between two
sessions, and a third session merging a green PR could not have known. That
is the defect: **the PR was green while carrying an unstated precondition**,
and green is precisely the signal a merger is entitled to trust.

So the constraint moves into the PR body, where anyone can see it, and into
a check, so nobody has to have been in the conversation.

    Blocked by #1197
    blocked-by: #1197, #1198

A blocker that is OPEN fails. A blocker that is CLOSED WITHOUT MERGING also
fails — otherwise the escape hatch is to close the blocker, which satisfies
the letter of "not open" while removing the thing that was required.

Runs in `preflight`, which is cheap and always reports. No-ops on push: a
push has no PR body, and the ordering question is already settled by then.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

# "Blocked by #123", "blocked-by: #123, #124". Deliberately narrow: a
# mention of "#123" alone is a reference, not a dependency, and treating
# every cross-reference as a merge gate would make the check unusable.
# Up to three leading spaces: markdown's limit for a paragraph. Four or
# more is an indented code block, which is documentation of the syntax
# rather than a use of it.
PATTERN = re.compile(r"^ {0,3}blocked[ -]by:?\s*(.+)$", re.IGNORECASE | re.MULTILINE)
FENCE = re.compile(r"^ {0,3}(```|~~~).*?^ {0,3}\1", re.DOTALL | re.MULTILINE)
NUMBER = re.compile(r"#(\d+)")


def blockers(body: str) -> list[int]:
    """Prerequisite numbers named in the body, ignoring code samples.

    A fenced block showing what the syntax LOOKS like is documentation, not
    a dependency. This check failed its own PR on exactly that: the body
    documented `Blocked by #1197` in a code fence and the parser read it as
    a live prerequisite. A tool that cannot describe itself without
    triggering itself is one people route around.
    """
    out: list[int] = []
    for line in PATTERN.findall(FENCE.sub("", body or "")):
        # Stop at the first sentence end so prose after the list is ignored.
        out.extend(int(n) for n in NUMBER.findall(line.split(".")[0]))
    return sorted(set(out))


def state_of(repo: str, number: int) -> tuple[str, bool]:
    """(state, merged) for a PR, via the API the CI token already has."""
    raw = subprocess.run(
        ["gh", "api", f"repos/{repo}/pulls/{number}",
         "--jq", '{state: .state, merged: .merged}'],
        capture_output=True, text=True,
    )
    if raw.returncode != 0:
        # An unreadable blocker is not a pass. A number that names nothing,
        # or a PR in a repo this token cannot see, is a body we cannot act
        # on — say so rather than wave it through.
        return ("unreadable", False)
    d = json.loads(raw.stdout)
    return (d["state"], bool(d["merged"]))


def main() -> int:
    body = os.environ.get("PR_BODY", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not body or not repo:
        print("check-blocked-by: no PR body (push event) — nothing to check")
        return 0

    wanted = blockers(body)
    if not wanted:
        print("check-blocked-by: ok (no `Blocked by #N` line)")
        return 0

    bad: list[str] = []
    for n in wanted:
        state, merged = state_of(repo, n)
        if merged:
            print(f"  #{n}: merged")
            continue
        if state == "closed":
            bad.append(
                f"#{n} was CLOSED WITHOUT MERGING — closing a blocker does not "
                f"satisfy it; the thing this PR needs still does not exist"
            )
        elif state == "unreadable":
            bad.append(f"#{n} could not be read — is that number right?")
        else:
            bad.append(f"#{n} is still open")

    if bad:
        print("check-blocked-by: FAIL — this PR names prerequisites that are not merged:")
        for b in bad:
            print(f"  - {b}")
        print(
            "\nMerge them first, or remove the `Blocked by` line if it is no longer true.\n"
            "This check exists because #1188 merged ahead of the rails it named, and the\n"
            "ordering was only ever written in a conversation."
        )
        return 1

    print(f"check-blocked-by: ok ({len(wanted)} prerequisite(s) merged)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
