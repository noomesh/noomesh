# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""No tracked file may match one of the repo's own .gitignore rules.

A tracked file that an ignore rule matches is invisible to a fresh checkout's
`git add -A`. The public repo and the trellion snapshot are both made by
copying a tree into a new repo and committing it, so such a file is silently
LEFT OUT. It happened: `models/` (meant for 17 GB of weights) matched
`docs/models/weight-cache.md` and a UI mock fixture, and the end-to-end sync
trial found ten dead doc links in the staged repo that no test had seen.

Only the repo's own `.gitignore` files are consulted (`--exclude-per-directory`),
never `--exclude-standard`: that also reads the machine's global excludes file
and `.git/info/exclude`, which made this test pass or fail depending on whose
checkout ran it.
"""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_no_tracked_file_is_ignored_by_the_repos_own_gitignore():
    if not (ROOT / ".git").exists():
        return  # an exported tree: nothing is tracked, nothing to check
    r = subprocess.run(
        ["git", "ls-files", "-ci", "--exclude-per-directory=.gitignore"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    swallowed = sorted(p for p in r.stdout.splitlines() if p)
    assert not swallowed, (
        "tracked files matched by .gitignore would be dropped by a fresh `git add -A`:\n  "
        + "\n  ".join(swallowed)
        + "\nNarrow the ignore rule or add a `!` re-include."
    )


def test_the_check_bites(tmp_path):
    """A repo whose ignore rule swallows a tracked path must be reported."""
    def git(*a):
        return subprocess.run(["git", *a], cwd=tmp_path, capture_output=True, text=True, check=True).stdout
    git("init", "-q", "-b", "main")
    (tmp_path / "docs" / "models").mkdir(parents=True)
    (tmp_path / "docs" / "models" / "a.md").write_text("x\n")
    git("add", "-f", "docs/models/a.md")
    (tmp_path / ".gitignore").write_text("models/\n")
    out = git("ls-files", "-ci", "--exclude-per-directory=.gitignore").split()
    assert out == ["docs/models/a.md"]
    (tmp_path / ".gitignore").write_text("models/\n!docs/models/\n")
    assert git("ls-files", "-ci", "--exclude-per-directory=.gitignore").split() == []
