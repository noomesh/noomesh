# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Shared Alembic runner — applies the memory env then the mesh env.

Phase 2 of the trellion extraction split the single
Alembic environment into two:

- ``src/noomesh/memory/migrations/`` owns memory-domain tables and uses
  the ``alembic_version_memory`` version table.
- ``src/noomesh/db/migrations/`` owns everything else and uses
  ``alembic_version_mesh``.

The memory env runs FIRST so its tables exist by the time mesh's
``002_pro_tables.py`` adds the cross-domain FK from
``noo_temporal_edges.source_cycle_id`` to ``noo_hofstadter_loop_cycles.id``.

This module is the single entry point for both gateway startup
(``engine._run_migrations``) and manual CLI invocation
(``db_cli upgrade`` / ``stamp`` / ``current`` / ``history``).
"""
from __future__ import annotations

from pathlib import Path

import structlog
from sqlalchemy import create_engine, inspect, text

from .engine import _sync_dsn

logger = structlog.get_logger(__name__)


# Known revision ids that the legacy single-env world could be stamped at.
#
# Two classes of legacy revisions:
#
# IDENTITY: legacy revision name exists 1:1 in the new mesh history.
#   Shim stamps new alembic_version_mesh at the same revision name.
#
# BEYOND_SPLIT: legacy revision came after the split point in the OLD
#   combined env. The name doesn't match any new mesh revision, but by
#   definition the user has all the schema the new mesh HEAD would create
#   (they were ahead of where new-mesh starts). Shim stamps new mesh at
#   HEAD — no migrations need to run.
#
# Add new entries here when a user reports an unknown_legacy_revision —
# we'd rather extend this set than make every user manually-stamp.
_LEGACY_MESH_IDENTITY = {"001_baseline", "002_pro_tables"}
_LEGACY_MESH_BEYOND_SPLIT = {
    "005_channel_recipients",   # observed 2026-04-28 — pre-split combined env head
}
_LEGACY_MESH_REVISIONS = _LEGACY_MESH_IDENTITY | _LEGACY_MESH_BEYOND_SPLIT
_LEGACY_VERSION_TABLE = "alembic_version"




def _resolve_mesh_head() -> str:
    """Return the head revision of the new mesh Alembic env.

    Reads the migrations directory rather than hard-coding so adding a
    new migration doesn't require remembering to update this file too.
    """
    versions_dir = Path(__file__).resolve().parent / "migrations" / "versions"
    revisions: list[str] = []
    for f in versions_dir.glob("*.py"):
        if f.name.startswith("_"):
            continue
        # Migration files are named e.g. "004_cluster_proposals.py" and the
        # revision string inside matches the filename stem by convention.
        revisions.append(f.stem)
    if not revisions:
        # Should never happen in a real install — bail with a clear msg
        raise RuntimeError("No mesh migrations found under " + str(versions_dir))
    # Lexicographic sort works because we use NNN_ prefixes
    return sorted(revisions)[-1]


def _alembic_cfg(env_dir: Path, dsn: str):
    """Build an Alembic Config for one of the two envs.

    Args:
        env_dir: Directory containing ``alembic.ini`` (parent of ``migrations``)
        dsn: Database URL
    """
    from alembic.config import Config

    ini_path = env_dir / "alembic.ini"
    migrations_dir = env_dir / "migrations"

    if not ini_path.exists():
        raise FileNotFoundError(
            f"Alembic ini not found at {ini_path}. "
            "Has trellion been installed? `pip install -e ../trellion` from the noomesh checkout root."
        )

    cfg = Config(str(ini_path))
    cfg.set_main_option("script_location", str(migrations_dir))
    cfg.set_main_option("sqlalchemy.url", dsn)
    return cfg


def memory_cfg(dsn: str):
    """Alembic config for the memory env (lives in noo-trellion since Phase 4)."""
    import trellion.db
    base = Path(trellion.db.__file__).resolve().parent  # noo-trellion/src/trellion/db/
    return _alembic_cfg(base, dsn)


def mesh_cfg(dsn: str):
    """Alembic config for the mesh (non-memory) env."""
    base = Path(__file__).resolve().parent  # noomesh/db/
    return _alembic_cfg(base, dsn)


def all_cfgs(dsn: str) -> list:
    """Return both configs in the order they should run."""
    return [memory_cfg(dsn), mesh_cfg(dsn)]


def _shim_legacy_version_table(dsn: str) -> None:
    """One-time upgrade shim for installs from the single-Alembic world.

    Pre-Phase-2 installs have a single ``alembic_version`` table stamped at
    ``001_baseline`` or ``002_pro_tables``. After the split each env has
    its own version table — the old one is orphaned.

    On first startup post-split:
      - If ``alembic_version`` exists with a known legacy revision, stamp
        ``alembic_version_mesh`` at that revision and
        ``alembic_version_memory`` at ``001_memory_baseline`` (memory
        tables already exist from the old combined baseline).
      - Drop the legacy ``alembic_version`` to prevent future confusion.

    Idempotent: subsequent runs see no legacy table and become no-ops.
    Fresh installs hit the ``not exists`` early-return.
    """
    sync_url = _sync_dsn(dsn)
    engine = create_engine(sync_url, pool_pre_ping=True)
    try:
        # Read-side: detect whether shim is needed
        with engine.connect() as conn:
            inspector = inspect(conn)
            existing = set(inspector.get_table_names())
            if _LEGACY_VERSION_TABLE not in existing:
                return  # fresh install or already shimmed

            if "alembic_version_mesh" in existing or "alembic_version_memory" in existing:
                logger.info(
                    "migration_shim.partial_state_detected",
                    has_mesh="alembic_version_mesh" in existing,
                    has_memory="alembic_version_memory" in existing,
                )

            row = conn.execute(text("SELECT version_num FROM alembic_version")).fetchone()
            legacy_rev = row[0] if row else None

        # Decide what to stamp the new mesh env at.
        if legacy_rev in _LEGACY_MESH_IDENTITY:
            # 1:1 mapping — same name in new mesh history
            mesh_stamp = legacy_rev
        elif legacy_rev in _LEGACY_MESH_BEYOND_SPLIT:
            # Schema is at-or-beyond new-mesh HEAD; stamp at HEAD so
            # alembic upgrade is a no-op.
            mesh_stamp = _resolve_mesh_head()
            logger.info(
                "migration_shim.beyond_split_legacy",
                legacy_revision=legacy_rev,
                stamping_mesh_at=mesh_stamp,
            )
        elif (
            "alembic_version_mesh" in existing
            and "alembic_version_memory" in existing
        ):
            # Cleanup-after-manual-recovery: someone already fixed the
            # version tables by hand (UPDATE alembic_version_mesh ...)
            # but the legacy table is still hanging around. Drop it so
            # this warning doesn't fire on every startup.
            with engine.begin() as conn:
                conn.execute(text("DROP TABLE alembic_version"))
            logger.info(
                "migration_shim.legacy_table_dropped_after_manual_recovery",
                unknown_revision=legacy_rev,
                note="New env tables already present; legacy table was redundant.",
            )
            return
        else:
            logger.warning(
                "migration_shim.unknown_legacy_revision",
                revision=legacy_rev,
                note=(
                    "Add to _LEGACY_MESH_IDENTITY or _LEGACY_MESH_BEYOND_SPLIT in "
                    "migration_runner.py to auto-handle this state. Leaving legacy "
                    "table in place — investigate manually."
                ),
            )
            return

        # Write-side: single transaction stamps both new tables, drops legacy
        with engine.begin() as conn:
            conn.execute(text(
                "CREATE TABLE IF NOT EXISTS alembic_version_mesh "
                "(version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
            ))
            conn.execute(text(
                "CREATE TABLE IF NOT EXISTS alembic_version_memory "
                "(version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
            ))
            conn.execute(text("DELETE FROM alembic_version_mesh"))
            conn.execute(text("DELETE FROM alembic_version_memory"))
            conn.execute(
                text("INSERT INTO alembic_version_mesh (version_num) VALUES (:r)"),
                {"r": mesh_stamp},
            )
            conn.execute(
                text("INSERT INTO alembic_version_memory (version_num) VALUES (:r)"),
                {"r": "001_memory_baseline"},
            )
            conn.execute(text("DROP TABLE alembic_version"))
        logger.info(
            "migration_shim.applied",
            legacy_revision=legacy_rev,
            mesh_stamp=mesh_stamp,
            memory_stamp="001_memory_baseline",
        )
    finally:
        engine.dispose()


def upgrade(dsn: str, revision: str = "heads", envs: str = "all") -> None:
    """Apply the selected Alembic env(s) up to *revision*.

    envs:
      - ``"all"`` (default) — memory first, then mesh. Today's single-runner
        behavior: the gateway entrypoint applies both.
      - ``"mesh"`` — mesh env only. Used by the gateway once the trellion
        container owns the memory env (WP-T23 phase 3,
        ``NOO_MIGRATIONS_ENVS=mesh``). No ordering against the memory env
        remains: the cross-domain FK that once required waiting was deleted
       .
      - ``"memory"`` — memory env only. Used by the trellion container's
        entrypoint (``NOO_MIGRATIONS_ENVS=memory``).

    The legacy-version-table shim runs in ``all`` and ``mesh`` modes only:
    it stamps BOTH version tables inside one transaction, and the gateway is
    the side guaranteed to exist in every deployment shape. Running it from
    two containers concurrently would race its DELETE+INSERT.
    """
    from alembic import command

    if envs not in ("all", "memory", "mesh"):
        raise ValueError(f"envs must be one of all/memory/mesh, got {envs!r}")

    if envs in ("all", "mesh"):
        _shim_legacy_version_table(dsn)

    cfgs = {
        "all": lambda: all_cfgs(dsn),
        "memory": lambda: [memory_cfg(dsn)],
        "mesh": lambda: [mesh_cfg(dsn)],
    }[envs]()
    for cfg in cfgs:
        command.upgrade(cfg, revision)
    logger.info("alembic.upgraded", target=revision, envs=envs)


# `wait_for_memory_head` lived here. It existed to
# serve the cross-domain FK (0003): mesh could not add a constraint onto a
# memory-env table before trellion had created it, so the gateway blocked up
# to 180s on ANOTHER SYSTEM'S migration head at every fresh boot. The FK is
# deleted, so the wait — and the pinned copy of trellion's head it depended
# on (`_PINNED_MEMORY_HEADS`, `_memory_heads`) — deletes with it. The Rust
# runner shed its copy of all three in the same phase.

def stamp(dsn: str, revision: str = "head") -> None:
    """Stamp both envs at *revision* (per env, defaults to each env's head)."""
    from alembic import command

    _shim_legacy_version_table(dsn)
    for cfg in all_cfgs(dsn):
        command.stamp(cfg, revision)


def current(dsn: str, verbose: bool = True) -> None:
    """Show current revision in both envs."""
    from alembic import command

    for label, cfg in [("memory", memory_cfg(dsn)), ("mesh", mesh_cfg(dsn))]:
        print(f"--- {label} env ---")
        command.current(cfg, verbose=verbose)


def history(dsn: str, verbose: bool = True) -> None:
    """Show migration history for both envs."""
    from alembic import command

    for label, cfg in [("memory", memory_cfg(dsn)), ("mesh", mesh_cfg(dsn))]:
        print(f"--- {label} env ---")
        command.history(cfg, verbose=verbose)
