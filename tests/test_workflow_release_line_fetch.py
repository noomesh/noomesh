# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The release-line guards fetch the promotion branch WITHOUT `--tags`.

On a tag-push run, actions/checkout recreates the pushed annotated tag as a
lightweight one, and a later `git fetch --tags` refuses to clobber it and
exits 1 — silently under `--quiet`. The guard then misread that as "origin/
staging does not exist" and refused stack-v0.2.89-rc.1 and its console build
(2026-10-04). The tag being built is already present; only the branch is needed.
"""
import re
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"


def test_no_release_line_guard_fetches_tags():
    offenders = []
    for wf in sorted(WORKFLOWS.glob("*.yml")):
        for n, line in enumerate(wf.read_text().splitlines(), 1):
            if re.search(r"git fetch\b.*\+refs/heads/\$line", line) and "--tags" in line:
                offenders.append(f"{wf.name}:{n}: {line.strip()}")
    assert not offenders, "a guard fetch with --tags fails on tag-push runs:\n  " + "\n  ".join(offenders)


def test_the_guards_exist_where_expected():
    for name in ("images-release.yml", "publish-web.yml"):
        text = (WORKFLOWS / name).read_text()
        assert re.search(r'git fetch --quiet origin "\+refs/heads/\$line', text), name
