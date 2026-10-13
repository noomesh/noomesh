# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for database management.

Provides ``noo db upgrade``, ``noo db stamp``, ``noo db current``,
and ``noo db history`` subcommands.

After Phase 2 of the trellion extraction, there are TWO
Alembic environments — memory and mesh — managed by
``noomesh.db.migration_runner``. The CLI commands fan out to both.
There is no ``noo db revision``: mesh revisions are authored as SQL in
gateway-rust/src/mesh_migrate.rs; memory
revisions are authored in trellion. Alembic here is the one-release
opt-out runner only.
"""

from __future__ import annotations

import os

import typer
from rich.console import Console

console = Console()

db_app = typer.Typer(
    help="Database migrations (Alembic) — runs both memory + mesh envs",
    rich_markup_mode="rich",
)


def _get_dsn() -> str:
    """Resolve DSN from environment."""
    for key in ("PAGEINDEX_DSN", "PGVECTOR_URL", "DATABASE_URL"):
        val = os.environ.get(key)
        if val:
            return val
    console.print("[red]No database URL found.[/]  Set PAGEINDEX_DSN, PGVECTOR_URL, or DATABASE_URL.")
    raise typer.Exit(1)


@db_app.command()
def upgrade(
    revision: str = typer.Argument("heads", help="Target revision (default: heads)"),
) -> None:
    """Run database migrations on both envs (memory first, then mesh)."""
    from .migration_runner import upgrade as _upgrade

    dsn = _get_dsn()
    _upgrade(dsn, revision)
    console.print(f"[green]Both envs upgraded to {revision}[/]")


@db_app.command()
def stamp(
    revision: str = typer.Argument("head", help="Revision to stamp on each env"),
) -> None:
    """Stamp BOTH envs with the given revision (or each env's head)."""
    from .migration_runner import stamp as _stamp

    dsn = _get_dsn()
    _stamp(dsn, revision)
    console.print(f"[green]Both envs stamped at {revision}[/]")


@db_app.command()
def current() -> None:
    """Show current migration revision in both envs."""
    from .migration_runner import current as _current

    dsn = _get_dsn()
    _current(dsn, verbose=True)


@db_app.command()
def history() -> None:
    """Show migration history for both envs."""
    from .migration_runner import history as _history

    dsn = _get_dsn()
    _history(dsn, verbose=True)

