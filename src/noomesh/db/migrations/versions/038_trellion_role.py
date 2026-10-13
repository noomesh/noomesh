# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Scoped database role for noo-trellion (WP-T23 phase 3).

Revision ID: 038_trellion_role
Revises: 037_graph_prune_staging
Create Date: 2026-08-01

Phase 3 of the trellion service split. Phases 1-2 gave the memory
worker pool its own container; this gives it its own database identity, the
same shape as ``034_evolve_role`` did for noo-evolve.

Creates ``noo_trellion``: LOGIN, NOSUPERUSER, NOBYPASSRLS, owning exactly the
memory tables and holding no privilege on anything else. A new role starts
with no table privileges, so the scoping is by omission — nothing needs
revoking.

WHERE THE TABLE LIST COMES FROM. ``trellion.db.MEMORY_TABLE_NAMES`` is the
single source of truth and is IMPORTED, not restated here: if the system
already declares a fact, config must not restate it. A copy would drift the
moment trellion adds a table, and the failure mode is silent — the new table
keeps its old owner and trellion's own Alembic env then fails to ALTER it.

WHY OWNERSHIP AND NOT JUST DML — same reason as 034. From phase 3 the trellion
container runs the memory Alembic env on its own startup, and DDL
(``ALTER TABLE``) requires ownership. DML grants would leave migrations
failing.

WHAT THIS DELIBERATELY DOES NOT GRANT. No ``CREATE`` on schema ``public``. New
memory tables arrive by migration, not by a service self-bootstrapping schema
at runtime. Note the noo-evolve lesson (noo-evolve#7): withholding CREATE also
blocks ``CREATE INDEX`` on an owned table, and Postgres checks the privilege
BEFORE ``IF NOT EXISTS`` — so a service that indexes at boot must check before
acting rather than rely on the guard.

MESH KEEPS WORKING — verified against the live system, not assumed. The plan
was written when the gateway still connected as superuser ``noo``, for which
ownership is irrelevant. That is now STALE: the 033 ``noo_app`` cutover has
landed and the gateway connects as ``noo_app``. Re-checked on
2026-08-01: ``noo_app`` holds explicit SELECT/INSERT/UPDATE/DELETE on all 26
memory tables, and changing a table's owner does not revoke existing grants,
so the Rust read/write surface and ``routes/users.rs::erase_targets()`` are
unaffected. Do not "simplify" this by assuming superuser.

THE TWO PRUNE STAGING TABLES. ``graph_prune_staging`` and
``graph_edge_prune_staging`` (migration 037) are memory-plane by every
practical test — ``graph_prune`` is their only writer, and that action lives
with the memory worker pool — but they are NOT in ``MEMORY_TABLE_NAMES``.
Left unhandled, trellion-as-``noo_trellion`` would lose the ability to stage a
prune, which is the safety net that makes prune reversible. Rather than
restate the list here, they are handled explicitly and the fix is filed
upstream: they belong in ``MEMORY_TABLE_NAMES`` in the trellion repo, after
which the loop below covers them and this block can go.

The password is read from ``NOO_TRELLION_DB_PASSWORD``. Like 033/034 this
fails loudly rather than inventing a default. It needs a passthrough in the
GATEWAY service env allowlist (alembic runs there) — the omission of exactly
that passthrough is what crash-looped 033.

Roles are CLUSTER-GLOBAL, so this reaches the real ``noo_trellion`` even when
the chain is replayed into a throwaway database. ``NOO_DB_SCHEMA_ONLY=1``
makes an existing role untouchable — see ``db/role_provision.py``.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

from noomesh.db.role_provision import ensure_login_role, role_password


revision: str = "038_trellion_role"
down_revision: Union[str, None] = "037_graph_prune_staging"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TRELLION_ROLE = "noo_trellion"

# Memory-plane tables that trellion owns but which are not yet declared in
# MEMORY_TABLE_NAMES. See the module docstring — this is a bridge, not a list.
EXTRA_MEMORY_TABLES = (
    "graph_prune_staging",
    "graph_edge_prune_staging",
)


# The memory tables as they stood when this backfill was written
# (snapshot of trellion.db.MEMORY_TABLE_NAMES, captured 2026-08-03).
#
# PINNED rather than imported, which reverses this function's original
# design. The reasoning changed because the ownership question changed:
#
# This revision is a BACKFILL, not an ongoing mechanism. It exists to fix
# installs whose memory tables were created before noo_trellion existed and
# therefore landed owned by `noo`. Verified against Postgres 2026-08-03:
#   - a table CREATED by noo_trellion is owned by noo_trellion automatically
#   - noo_trellion CANNOT seize a table owned by noo ("must be owner of
#     table"), which is why the transfer is superuser work and stays here
#
# So a memory table trellion adds AFTER this revision is born correctly
# owned and never needs transferring. The set that can be mis-owned is
# exactly the set that existed when those legacy installs were built — this
# list. A later trellion table cannot be "left behind", which is what the
# original docstring warned about.
#
# The import cost was real: it made the mesh chain — run by the GATEWAY —
# require the whole trellion package, and with it 4.5 GB of CUDA/torch in a
# container that runs no models.
_PINNED_MEMORY_TABLES = (
    "chunk_embeddings",
    "docs",
    "edges",
    "entities",
    "entity_cluster_members",
    "entity_clusters",
    "entity_embeddings",
    "mentions",
    "page_chunks",
    "page_embeddings",
    "pages",
    "noo_context_retrievals",
    "noo_conversations",
    "noo_entities_typed",
    "noo_entries",
    "noo_feedback",
    "noo_semantic_relationships",
    "noo_temporal_edges",
    "noo_tool_executions",
    "trellion_communities",
    "trellion_concepts",
    "trellion_dag_edges",
    "trellion_episodes",
    "trellion_provenance",
    "trellion_snapshots",
    "trellion_traversal_records",
)


def _memory_tables() -> tuple[str, ...]:
    """The memory tables this backfill may transfer, plus the staging bridge.

    Does NOT import trellion — see `_PINNED_MEMORY_TABLES` above for why that
    is safe and why it was changed.
    """
    return tuple(sorted(set(_PINNED_MEMORY_TABLES) | set(EXTRA_MEMORY_TABLES)))


def upgrade() -> None:
    password = role_password(
        "NOO_TRELLION_DB_PASSWORD",
        "NOO_TRELLION_DB_PASSWORD is not set. Migration 038 creates the "
        f"{TRELLION_ROLE!r} login role and will not invent a default "
        "password for it. Set the variable (it belongs in "
        "secrets/env.sops like every other credential) and re-run. It "
        "also needs a passthrough in the GATEWAY service env allowlist in "
        "docker-compose.cluster.yml — alembic runs in the gateway "
        "container, and a missing passthrough there is what crash-looped "
        "migration 033.",
    )

    conn = op.get_bind()

    # Creates when absent; an idempotent re-run keeps the password in step with
    # the secret — EXCEPT in schema-only mode, where an existing role belongs
    # to a real cluster and must not be touched.
    ensure_login_role(
        conn,
        TRELLION_ROLE,
        password,
        attributes="LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS",
    )

    # Reaching its tables at all requires schema usage. This is NOT
    # `GRANT CREATE` — see the module docstring.
    conn.exec_driver_sql(f"GRANT USAGE ON SCHEMA public TO {TRELLION_ROLE}")

    for table in _memory_tables():
        present = conn.exec_driver_sql(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = %(t)s",
            {"t": table},
        ).scalar()
        if not present:
            # A memory table that has not been created yet (fresh install
            # ordering, or a trellion table behind a feature). Skipping is
            # correct: a later re-run assigns ownership once it exists.
            continue
        conn.exec_driver_sql(f"ALTER TABLE {table} OWNER TO {TRELLION_ROLE}")

    # Identity columns need their sequences too; ownership of a table does not
    # carry the sequence it defaults from.
    conn.exec_driver_sql(
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {TRELLION_ROLE}"
    )


def downgrade() -> None:
    """Hand the tables back to ``noo`` and drop the role.

    Ownership must move BEFORE the DROP — Postgres refuses to drop a role that
    still owns objects, and the error names only the first dependency, which
    makes it a slow thing to unpick by hand.
    """
    conn = op.get_bind()
    exists = conn.exec_driver_sql(
        "SELECT 1 FROM pg_roles WHERE rolname = %(r)s", {"r": TRELLION_ROLE}
    ).scalar()
    if not exists:
        return

    for table in _memory_tables():
        present = conn.exec_driver_sql(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = %(t)s",
            {"t": table},
        ).scalar()
        if present:
            conn.exec_driver_sql(f"ALTER TABLE {table} OWNER TO noo")

    conn.exec_driver_sql(f"REVOKE ALL ON SCHEMA public FROM {TRELLION_ROLE}")
    conn.exec_driver_sql(
        f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {TRELLION_ROLE}"
    )
    conn.exec_driver_sql(f"DROP ROLE IF EXISTS {TRELLION_ROLE}")
