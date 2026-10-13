# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The mesh migration chain must be linear — exactly one head.

Two agents working in parallel both branched from `033_app_role_split` on
2026-07-31 and both numbered their migration `034`. Neither PR conflicted:
different filenames, different revision ids, no overlapping lines. Git merged
them cleanly and Alembic ended up with a forked history.

That is not a git problem, so git cannot catch it. This test can.

A fork is not immediately fatal — `migration_runner` calls `upgrade(dsn,
"heads")`, plural, which walks both branches — but it is corrosive: `upgrade
head` (singular) starts failing, the next author has to guess which parent to
revise, and a merge revision has to be hand-written later by someone who was
not there.
"""
from __future__ import annotations

import re
from pathlib import Path

VERSIONS = Path(__file__).resolve().parents[1] / "src/noomesh/db/migrations/versions"

REVISION = re.compile(r'^revision:\s*str\s*=\s*"([^"]+)"', re.M)
# down_revision is annotated two ways in this tree, and its value is a string,
# None, or a TUPLE — a tuple means an Alembic merge revision joining branches
# (031_security_posture merges 030 and 029). Parse the whole RHS and pull the
# string literals out of it rather than assuming a single quoted value.
DOWN = re.compile(r"^down_revision\s*:[^=]*=\s*(.+)$", re.M)
STRINGS = re.compile(r'"([^"]+)"')


def _chain() -> tuple[dict[str, list[str]], list[Path]]:
    """revision -> list of parent revisions (empty for the base)."""
    edges: dict[str, list[str]] = {}
    files = sorted(p for p in VERSIONS.glob("*.py") if p.name != "__init__.py")
    for path in files:
        text = path.read_text()
        rev = REVISION.search(text)
        assert rev, f"{path.name}: no `revision: str = \"...\"` found"
        down = DOWN.search(text)
        assert down, f"{path.name}: no `down_revision` assignment found"
        assert rev.group(1) not in edges, f"duplicate revision id {rev.group(1)!r}"
        edges[rev.group(1)] = STRINGS.findall(down.group(1))
    return edges, files


def test_exactly_one_head():
    """The chain must have exactly one tip.

    NOT "no forks" — branch-then-merge is legitimate Alembic and this tree
    already does it: `028_org_columns` is revised by both `029_channel_stats`
    and `030_settings`, which `031_security_posture` rejoins with a tuple
    down_revision. A fork is only a defect if nothing merges it, and that shows
    up here as a second head.
    """
    edges, _ = _chain()
    parents = {p for parent_list in edges.values() for p in parent_list}
    heads = sorted(set(edges) - parents)
    assert len(heads) == 1, (
        f"expected exactly one head, found {len(heads)}: {heads}. "
        f"Either renumber the later migration onto the earlier, or add a merge "
        f"revision with a tuple down_revision (see 031_security_posture). "
        f"Run `alembic heads` BEFORE writing a migration — a parallel branch "
        f"merges cleanly in git and still forks the chain, so git cannot warn you."
    )


def test_every_parent_exists():
    """A down_revision pointing at nothing is a chain that cannot be walked."""
    edges, _ = _chain()
    known = set(edges)
    dangling = {
        rev: [d for d in parent_list if d not in known]
        for rev, parent_list in edges.items()
        if any(d not in known for d in parent_list)
    }
    assert not dangling, f"down_revision targets that do not exist: {dangling}"


def test_base_is_unique():
    """Exactly one migration may have `down_revision = None`."""
    edges, _ = _chain()
    bases = sorted(r for r, parent_list in edges.items() if not parent_list)
    assert len(bases) == 1, f"expected one base revision, found {len(bases)}: {bases}"
