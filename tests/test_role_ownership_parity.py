# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Role provisioning exists twice and must agree.

`gateway-rust/src/role_provision.rs` reproduces what Alembic revisions 033
(`noo_app`), 034 (`noo_evolve`) and 038 (`noo_trellion`) did. The Rust copy is
what actually runs now — the sqlx path never executes those revisions — but
the Python ones are still the reference, still runnable, and still what
`--check` replays to generate the baseline.

Two lists have to stay in step, and neither has a natural forcing function:

  * which tables `noo_evolve` owns   (034 EVOLVE_TABLES)
  * which tables `noo_trellion` owns (038 _PINNED_MEMORY_TABLES + EXTRA)

If they drift, a fresh install silently leaves tables owned by `noo` that
should belong to a system role. Nothing fails at boot; it surfaces later as a
permission error in whichever container was supposed to own the table.

Read as text rather than imported: this must hold where the Rust crate cannot
be built and where trellion is not installed.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RUST = REPO / "gateway-rust" / "src" / "role_provision.rs"
V = REPO / "src" / "noomesh" / "db" / "migrations" / "versions"


def _rust_list(name: str) -> set[str]:
    src = RUST.read_text()
    m = re.search(rf"const {name}:\s*&\[&str\]\s*=\s*&\[(.*?)\];", src, re.DOTALL)
    assert m, f"{name} not found in {RUST}"
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def _py_tuple(path: Path, name: str) -> set[str]:
    src = path.read_text()
    m = re.search(rf"^{name}\s*=\s*\((.*?)\)", src, re.DOTALL | re.MULTILINE)
    assert m, f"{name} not found in {path}"
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def test_evolve_owned_tables_agree() -> None:
    rust = _rust_list("EVOLVE_TABLES")
    py = _py_tuple(V / "034_evolve_role.py", "EVOLVE_TABLES")
    assert rust == py, (
        "noo_evolve owned-table lists disagree:\n"
        f"  only in Rust:   {sorted(rust - py)}\n"
        f"  only in Python: {sorted(py - rust)}"
    )


def test_trellion_owned_tables_agree() -> None:
    """Three Python sources, not two — 039 is the one that gets forgotten.

    An earlier cut of the Rust list came from 038 alone and silently left
    `entity_graph_signals` owned by `noo` on every fresh install.
    """
    rust = _rust_list("TRELLION_TABLES")
    py = (
        _py_tuple(V / "038_trellion_role.py", "_PINNED_MEMORY_TABLES")
        | _py_tuple(V / "038_trellion_role.py", "EXTRA_MEMORY_TABLES")
        | _py_tuple(V / "039_trellion_signals_ownership.py", "TABLES")
    )
    assert rust == py, (
        "noo_trellion owned-table lists disagree:\n"
        f"  only in Rust:   {sorted(rust - py)}\n"
        f"  only in Python: {sorted(py - rust)}"
    )


def test_no_migration_assigns_ownership_the_rust_list_misses() -> None:
    """Scan every revision for `ALTER TABLE … OWNER TO noo_<role>`.

    The parity tests above only compare lists this file already knows to read.
    A future migration that assigns ownership from a NEW constant would pass
    them while still drifting. This one finds the statements themselves.
    """
    rust_tables = _rust_list("TRELLION_TABLES") | _rust_list("EVOLVE_TABLES")
    # Constants referenced by an ALTER … OWNER TO loop, resolved per file.
    missing: dict[str, set[str]] = {}
    for path in sorted(V.glob("*.py")):
        src = path.read_text()
        if "OWNER TO" not in src:
            continue
        # Any tuple of table-name literals in a file that assigns ownership to
        # a noo_* role. Deliberately broad — over-collecting only makes the
        # check stricter, and every name here really is a table.
        if not re.search(r"OWNER TO \{?\w*(TRELLION|EVOLVE)\w*\}?", src):
            continue
        names = set(re.findall(r'^\s*"([a-z_][a-z0-9_]*)",\s*$', src, re.MULTILINE))
        gap = names - rust_tables
        if gap:
            missing[path.name] = gap
    assert not missing, (
        "migrations assign ownership for tables the Rust provisioner does not "
        f"list: {missing}\nAdd them to role_provision.rs, or the sqlx path "
        "leaves them owned by `noo` on every fresh install."
    )


def test_rust_never_alters_an_existing_roles_password() -> None:
    """The outage class this port exists to end.

    role_provision.py finishes with an unconditional
    `ALTER ROLE … WITH PASSWORD` whenever NOO_DB_SCHEMA_ONLY is unset, so any
    replay of the chain against a live cluster resets all three credentials.
    The Rust side must only ever CREATE.
    """
    src = RUST.read_text()
    assert "CREATE ROLE" in src, "roles are never created — provisioning does nothing"
    offenders = [
        line.strip()
        for line in src.splitlines()
        if "ALTER ROLE" in line and not line.strip().startswith("//")
    ]
    assert not offenders, (
        "role_provision.rs contains ALTER ROLE:\n  "
        + "\n  ".join(offenders)
        + "\nRole passwords are cluster-global. Rotation is an operator action "
        "(`noo security secrets resync`), never a side effect of migrating."
    )


def test_runtime_role_is_not_granted_create() -> None:
    """`noo_app` must not be able to add tables — RLS and the

    "owns zero tables" invariant both depend on it.
    """
    src = RUST.read_text()
    bad = [
        line.strip()
        for line in src.splitlines()
        if re.search(r"GRANT\s+CREATE", line) and not line.strip().startswith("//")
    ]
    assert not bad, f"GRANT CREATE found in role_provision.rs: {bad}"
