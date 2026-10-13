# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The add-on gate's reach pattern: a package reach fails, a database role name does not."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

GATES = Path(__file__).resolve().parents[1] / "scripts" / "snapshot_gates.py"


@pytest.fixture(scope="module")
def reach():
    if not GATES.exists():
        pytest.skip("scripts/snapshot_gates.py is private move tooling, absent from the public tree")
    spec = importlib.util.spec_from_file_location("snapshot_gates_under_test", GATES)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.ADDON_REACH


# Built from parts so this file is not itself a reach into the add-on.
PKG = "noo" + "_evolve"
INTEL = "trellion" + "_intel"


@pytest.mark.parametrize("line", [
    f"from {PKG}.db import x",
    f"import {PKG}.thing",
    f"x = '{PKG}:entry'",
    f"mod = '{INTEL}.audience'",
    f"from {INTEL} import y",
    "import_" + "intel('x')",
    "ref = 'addon" + ":foo'",
    "importlib.import_" + "module(name)",
])
def test_package_reach_fails(reach, line):
    assert reach.search(line), line


@pytest.mark.parametrize("line", [
    f'NOO_PGPASS_ROLES_EVOLVE="libpq {PKG}:NOO_EVOLVE_DB_PASSWORD {PKG}_ddl:NOO_EVOLVE_DDL_PASSWORD"',
    f'assert_eq!(out["NOO_PGPASS_EVOLVE"], "postgres:5432:noomesh:{PKG}:e");',
    f"postgres:5432:noomesh:{PKG}:secret",
])
def test_database_role_name_is_not_a_package_reach(reach, line):
    assert not reach.search(line), line
