# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Rust and Python must agree on who owns the mesh schema.

`NOO_MESH_MIGRATOR=sqlx` hands the mesh env from Alembic to the Rust runner.
Two independent parsers read that flag — `Engine::parse` in
gateway-rust/src/mesh_migrate.rs, and entrypoint.py before it exec()s the
gateway — and they have to reach the same answer.

The two ways they can disagree are NOT equally bad:

- Rust takes it, Python also runs Alembic  -> both migrate. On a fresh install
  they race to create the same tables and the loser dies on "already exists".
  Loud.
- Python hands it over, Rust does NOT take it -> NOBODY migrates. A fresh
  install gets an empty database and the gateway starts against no schema.
  Silent, and the worse of the two.

So the accepted spelling is exactly one literal, `"sqlx"`, matched after
strip+lower on both sides, and anything else leaves Alembic in charge — never
nobody. This test pins that, in the only place that can read both files.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RUST = REPO / "gateway-rust" / "src" / "mesh_migrate.rs"
ENTRYPOINT = REPO / "docker" / "entrypoint.py"


def test_entrypoint_keeps_alembic_only_on_the_exact_opt_out() -> None:
    src = ENTRYPOINT.read_text()
    assert 'NOO_MESH_MIGRATOR' in src, "entrypoint.py must consult the migrator flag"
    assert re.search(
        r'os\.environ\.get\(\s*"NOO_MESH_MIGRATOR".*?\)\s*\.strip\(\)\s*\.lower\(\)\s*!=\s*"alembic"',
        src,
        re.S,
    ), (
        "entrypoint.py must treat everything except an exact 'alembic' as "
        "'the Rust runner owns mesh', matching Engine::parse now that sqlx "
        "is the default. A looser match risks Python handing over while Rust "
        "does not take it — a fresh install with no mesh schema at all."
    )


def test_rust_opts_out_only_on_alembic() -> None:
    src = RUST.read_text()
    assert 'Some("alembic") => Self::Alembic' in src, (
        "Engine::parse must opt out on exactly \"alembic\"; if the spelling "
        "changed, entrypoint.py has to change with it"
    )
    assert "unrecognized" in src.lower(), (
        "an unrecognised value must be warned about and land on the default"
    )


def test_sqlx_is_the_default_on_both_sides() -> None:
    """Pins the post-flip default, so reverting it is also deliberate.

    `alembic` stays runnable for one release as the explicit opt-out.
    """
    rust = RUST.read_text()
    assert 'None | Some("") | Some("sqlx") => Self::Sqlx' in rust, (
        "unset must mean the sqlx engine — changing that back is its own change"
    )
