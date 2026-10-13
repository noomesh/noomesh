# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""entity_graph_signals joins the noo_trellion ownership bridge.

Revision ID: 039_trellion_signals_ownership
Revises: 038_trellion_role
Create Date: 2026-08-01

038 transferred the memory-plane tables to ``noo_trellion``:
``MEMORY_TABLE_NAMES`` plus an explicit bridge for the two prune staging
tables that are memory-plane in practice but missing from the declared set.

``entity_graph_signals`` is a third table of exactly that class, found by
diffing the tables the memory Alembic env actually creates against the set
038 transferred (a scratch replay of the memory env alone creates 27 tables;
038 covered 26). It is created by trellion migration
``011_declare_entity_graph_signals``, upserted by trellion's own
``live/graph_signals.py::_store_signals``, and read by its graph signal
scorer — no mesh writer exists. Left owned by ``noo``, the first signal
refresh after trellion's engine flips to ``noo_trellion``
(``NOO_TRELLION_DATABASE_URL``) would fail with permission denied — inside
the signal refresh path, so the failure mode is silently stale graph
signals, not a crash.

Same upstream fix filed as for the staging tables: this belongs in
``MEMORY_TABLE_NAMES`` in the noo-trellion repo. Once it lands there, 038's
imported loop covers it on fresh installs and this bridge (like 038's) can
be retired together.

No password needed here — the role already exists (038 is this migration's
down_revision, so ordering is guaranteed).
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "039_trellion_signals_ownership"
down_revision: Union[str, None] = "038_trellion_role"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TRELLION_ROLE = "noo_trellion"
TABLES = ("entity_graph_signals",)


def _present(conn, table: str) -> bool:
    return bool(
        conn.exec_driver_sql(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = %(t)s",
            {"t": table},
        ).scalar()
    )


def upgrade() -> None:
    conn = op.get_bind()
    for table in TABLES:
        if _present(conn, table):
            conn.exec_driver_sql(f"ALTER TABLE {table} OWNER TO {TRELLION_ROLE}")
        # Absent = fresh-install ordering (the memory env creates it) or a
        # feature-gated table. Skipping is correct — a later re-run of the
        # mesh env will not re-visit this, but 038's re-runnable role logic
        # plus the trellion-side MEMORY_TABLE_NAMES fix are the durable
        # path; this bridge targets existing installs where the table
        # already exists.


def downgrade() -> None:
    conn = op.get_bind()
    for table in TABLES:
        if _present(conn, table):
            conn.exec_driver_sql(f"ALTER TABLE {table} OWNER TO noo")
