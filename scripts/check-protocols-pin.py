#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The trellion-protocols build context is the commit trellion pins.

    check-protocols-pin.py TRELLION_DIR PROTOCOLS_DIR

trellion depends on trellion-protocols pinned by full commit SHA in its
pyproject.toml. deps-base resolves that dependency to a local build context
(uv --overrides, like trellion itself, so the build needs no credentials).
A local checkout can sit on any commit, so this refuses a context that is not
the pinned one. A trellion with no such pin (older than the separation)
passes: the context is then unused.

Exit 0 = matches (or no pin); 1 = mismatch or cannot verify.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Any owner: the repository moved organisations once, and the
# old owner-specific pattern then matched nothing, which read as "no pin".
PIN = re.compile(
    r'"trellion-protocols @ git\+https://github\.com/[A-Za-z0-9._-]+/trellion-protocols\.git@([0-9a-f]{40})"'
)


def head_sha(repo: Path) -> str | None:
    git = repo / ".git"
    if not git.is_dir():
        return None
    head = (git / "HEAD").read_text().strip()
    if not head.startswith("ref: "):
        return head
    ref = head[5:]
    loose = git / ref
    if loose.is_file():
        return loose.read_text().strip()
    packed = git / "packed-refs"
    if packed.is_file():
        for line in packed.read_text().splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == ref:
                return parts[0]
    return None


def main(trellion: str, protocols: str) -> int:
    m = PIN.search((Path(trellion) / "pyproject.toml").read_text())
    if not m:
        if "trellion-protocols" in (Path(trellion) / "pyproject.toml").read_text():
            print(
                "trellion names trellion-protocols but its pin is not "
                '"trellion-protocols @ git+https://github.com/<owner>/trellion-protocols.git@<40-hex sha>"',
                file=sys.stderr,
            )
            return 1
        print("trellion pins no trellion-protocols commit; the build context is unused")
        return 0
    want = m.group(1)
    got = head_sha(Path(protocols))
    if got is None:
        print(
            f"cannot verify the trellion-protocols build context: no git checkout at {protocols} "
            "(a worktree's .git is a pointer the build cannot follow). Use a clone checked out at "
            f"{want} (TRELLION_PROTOCOLS_PATH).",
            file=sys.stderr,
        )
        return 1
    if got != want:
        print(
            f"trellion pins trellion-protocols@{want} but the build context is at {got}. "
            f"Check out {want} in the trellion-protocols clone (TRELLION_PROTOCOLS_PATH, "
            "default ../trellion-protocols).",
            file=sys.stderr,
        )
        return 1
    print(f"trellion-protocols build context is the pinned commit {want}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
