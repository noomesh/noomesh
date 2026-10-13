# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Migrations that touch a `create_all`-managed object must be guarded.

`001_baseline` and trellion's `001_memory_baseline` both call
`Base.metadata.create_all()` against the CURRENT models. On a fresh database
that produces today's schema at baseline — including columns and tables that
later migrations were written to add. An unguarded `op.add_column` /
`op.create_table` against such an object then fails with DuplicateColumn /
DuplicateTable, and the chain cannot be replayed from empty at all.

That broke fresh installs and the `sqlx-drift` CI job.

This test is deliberately cheap and static: it does not spin up Postgres. It
asserts the *shape* — a migration naming a model-declared table must either
guard with an existence check or use IF NOT EXISTS. Running the chain for real
against an empty database is the stronger check; this one is what catches the
regression at review time.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ROOT / "src/noomesh/db/migrations/versions"
MODELS = ROOT / "src/noomesh/db/models.py"

TABLENAME = re.compile(r'__tablename__\s*=\s*["\']([a-z_0-9]+)["\']')
CREATE_TABLE = re.compile(r'op\.create_table\(\s*["\']([a-z_0-9]+)["\']')
ADD_COLUMN = re.compile(r'op\.add_column\(\s*["\']([a-z_0-9]+)["\']')


def _declared_tables() -> set[str]:
    return set(TABLENAME.findall(MODELS.read_text()))


def _is_guarded(text: str) -> bool:
    """Either an inspector existence check, or IF NOT EXISTS in raw SQL."""
    return (
        "get_table_names()" in text
        or "IF NOT EXISTS" in text
        or "has_table(" in text
    )


def test_model_backed_migrations_are_guarded():
    declared = _declared_tables()
    assert declared, "no __tablename__ found — the models path is wrong"

    offenders: list[str] = []
    for path in sorted(VERSIONS.glob("*.py")):
        if path.name == "__init__.py":
            continue
        text = path.read_text()
        if _is_guarded(text):
            continue
        touched = set(CREATE_TABLE.findall(text)) | set(ADD_COLUMN.findall(text))
        clashes = sorted(touched & declared)
        if clashes:
            offenders.append(f"{path.name}: {', '.join(clashes)}")

    assert not offenders, (
        "these migrations mutate a table that `Base.metadata.create_all()` also "
        "builds, without guarding:\n  " + "\n  ".join(offenders) +
        "\n\nOn a FRESH database the baseline creates the object first and these "
        "fail with DuplicateTable/DuplicateColumn, so the chain cannot be "
        "replayed from empty. Use `ADD COLUMN IF NOT EXISTS`, or an early return "
        "on `inspect(op.get_bind()).get_table_names()`. See an earlier change."
    )


def test_baselines_are_pinned_not_create_all():
    """WP-26: no migration may build schema from the live models.

    The baselines (`001_baseline`, `002_pro_tables`, trellion's
    `001_memory_baseline`) were converted from `Base.metadata.create_all()`
    to frozen DDL. `create_all` in ANY migration reintroduces an earlier change:
    the revision would apply whatever the models say on the day it runs,
    so a fresh replay diverges from every existing install and later
    `add_column` migrations collide.
    """
    import ast

    def _calls_create_all(path: Path) -> bool:
        # AST, not substring: many migrations *mention* create_all in
        # comments explaining the old behaviour. Only a real call counts.
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "create_all"
            ):
                return True
        return False

    # Mesh env only: the memory env lives in noo-trellion, which polices its
    # own migrations — enforcing another repo's source from here just turns
    # this suite red whenever the trellion pin ships on its own schedule.
    offenders = [
        path.name
        for path in sorted(VERSIONS.glob("*.py"))
        if path.name != "__init__.py" and _calls_create_all(path)
    ]

    assert not offenders, (
        "migrations must contain frozen DDL, never Base.metadata.create_all(): "
        + ", ".join(offenders)
        + "  (pinned baselines)."
    )
