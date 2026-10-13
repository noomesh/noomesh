# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A repo script acts on the checkout the CALLER is in, not the one it lives in.

`Path(__file__).parent.parent` names the tree the SCRIPT is in. Invoked from
a worktree by a relative path — `../../scripts/docs-check.py` — that
is the MAIN CLONE, so the script reads and writes the wrong tree while
reporting success. It bit on 2026-09-19 resolving a conflict in a worktree:
the regeneration landed in the main clone, the worktree's conflict stayed
unresolved, and the command said it had worked.

`scripts/cargo-docker.sh` learned this on 2026-08-13, where the same shape
produced a confident "0 tests matched" against code that was never built.
Its fix — `git rev-parse` follows $PWD — is the one these scripts now use.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
GUARDED = ["docs-check.py"]


def test_the_guarded_scripts_resolve_their_root_from_the_caller() -> None:
    for name in GUARDED:
        src = (REPO / "scripts" / name).read_text()
        assert "_repo_root()" in src, f"{name} must resolve its root via _repo_root()"
        assert "--show-toplevel" in src, f"{name}: _repo_root must follow $PWD via git"
        # The script-relative form must not be what the module-level constant
        # binds to — that is the bug.
        for const in ("ROOT = Path(__file__)", "REPO = Path(__file__)"):
            assert const not in src, f"{name}: {const} is the cross-tree trap"


def test_a_script_run_from_another_checkout_acts_on_that_checkout(tmp_path: Path) -> None:
    """Stand in a different git tree; the script must act on THAT tree.

    Built as a real git repo with the expected layout, so `_repo_root`'s
    "does this look like my repo" check passes and the script proceeds.
    """
    other = tmp_path / "other"
    (other / "scripts").mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=other, check=True)
    script = REPO / "scripts" / "docs-check.py"
    # The marker _repo_root() looks for: scripts/<this script's name>.
    (other / "scripts" / script.name).write_text("# placeholder\n")
    # An unindexed doc here: the script must fail against THIS tree rather
    # than quietly succeeding against its own.
    (other / "docs").mkdir()
    (other / "docs" / "README.md").write_text("# docs\n")
    (other / "docs" / "orphan.md").write_text("# orphan\n")
    p = subprocess.run(
        [sys.executable, str(script)],
        cwd=other, capture_output=True, text=True,
    )
    # A traceback's `File "..."` lines name the script itself, wherever it
    # lives; what matters is the tree the script ACTED on.
    combined = "\n".join(
        ln for ln in (p.stdout + p.stderr).splitlines()
        if not ln.lstrip().startswith('File "')
    )
    assert p.returncode != 0, (
        "a run from an empty foreign checkout must not report success — "
        f"it acted on its own tree instead. output: {combined[:400]}"
    )
    assert str(REPO) not in combined, (
        "the script named its OWN tree while standing in another: " + combined[:400]
    )
