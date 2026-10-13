# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The pinned table list in 038 must not silently diverge from trellion's.

`038_trellion_role` used to import `trellion.db.MEMORY_TABLE_NAMES`. That made
the MESH migration chain — run by the gateway — require the whole trellion
package, and with it 4.5 GB of CUDA/torch in a container that runs no models
. The list is now pinned.

Pinning is safe for the reason documented in the revision: a memory table
trellion adds AFTER that backfill is created BY noo_trellion and is therefore
owned correctly from birth, so it never needs transferring. Only tables that
predate the role can be mis-owned.

What pinning cannot protect against is the pin being wrong in the other
direction — naming a table trellion never had, or dropping one it still owns
on legacy installs. This test compares the pin against the live declaration
when trellion is importable, and skips when it is not (which is exactly the
gateway's situation, and the point of the change).
"""
from __future__ import annotations

import pytest


def _load(filename: str, name: str):
    import importlib.util
    from pathlib import Path

    path = (
        Path(__file__).resolve().parents[1]
        / "src/noomesh/db/migrations/versions"
        / filename
    )
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _pinned() -> set[str]:
    return set(_load("038_trellion_role.py", "m038")._PINNED_MEMORY_TABLES)


def _transferred_by_the_mesh_chain() -> set[str]:
    """Every memory table the mesh chain assigns to `noo_trellion`.

    THREE sources, not one, and comparing against only the first is what made
    this test wrong. 038's own docstring names the other two:

    * `_PINNED_MEMORY_TABLES` — the backfill snapshot
    * `EXTRA_MEMORY_TABLES` — the two prune staging tables, which 038 handles
      explicitly because trellion did not declare them at the time
    * `039_trellion_signals_ownership.TABLES` — `entity_graph_signals`, which
      arrived in a later revision

    Trellion now DERIVES its declaration from its own metadata (noo-trellion
    #34), so all three of those names appear in `MEMORY_TABLE_NAMES` — as they
    always should have. Against the pin alone that reads as three regressions;
    against the union it reads as what it is, which is the two lists finally
    agreeing.
    """
    m038 = _load("038_trellion_role.py", "m038")
    m039 = _load("039_trellion_signals_ownership.py", "m039")
    return (
        set(m038._PINNED_MEMORY_TABLES)
        | set(m038.EXTRA_MEMORY_TABLES)
        | set(m039.TABLES)
    )


def test_038_does_not_import_trellion():
    """The whole point: the mesh chain must not need the trellion package.

    Parses the AST rather than grepping the text — the revision's own comments
    discuss the trellion import at length, and a substring check matches that
    prose and fails for the wrong reason.
    """
    import ast
    from pathlib import Path

    tree = ast.parse(
        (
            Path(__file__).resolve().parents[1]
            / "src/noomesh/db/migrations/versions/038_trellion_role.py"
        ).read_text()
    )
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)

    offenders = [m for m in imported if m == "trellion" or m.startswith("trellion.")]
    assert not offenders, (
        f"038 imports {offenders}. It is in the MESH chain, which the gateway "
        "runs — importing trellion here drags the ML stack into the gateway "
        "image."
    )


def test_pinned_list_covers_trellions_declaration():
    """Pin ⊇ trellion's tables, when trellion is available to ask.

    A table in trellion's list that the mesh chain never transfers would be
    left owned by `noo` on a legacy install — the failure the original import
    prevented. Extra names on the mesh side are harmless: the revisions skip
    tables that do not exist.

    Compared against all THREE mesh sources, not 038's pin alone. See
    `_transferred_by_the_mesh_chain`.
    """
    trellion_db = pytest.importorskip(
        "trellion.db", reason="trellion not installed — the gateway's own case"
    )
    declared = set(trellion_db.MEMORY_TABLE_NAMES)
    missing = sorted(declared - _transferred_by_the_mesh_chain())
    assert not missing, (
        f"trellion declares memory tables the mesh chain never transfers: {missing}. "
        "On a legacy install those would stay owned by `noo`. Add them to "
        "_PINNED_MEMORY_TABLES, or confirm they postdate the role (in which "
        "case they are born correctly owned and need no entry)."
    )
