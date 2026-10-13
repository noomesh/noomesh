# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Partial indexes for the open (unrestored) graph-prune staging rows.

Revision ID: 037_graph_prune_staging
Revises: 036_audit_partition_definer
Create Date: 2026-07-31

`014_graph_prune_staging` already creates `graph_prune_staging` and
`graph_edge_prune_staging` along with `(staged_at)` and `(entity_id)` indexes.
This migration adds only what was missing: partial indexes on the OPEN rows.

Four queries in `routes/knowledge.rs` filter `WHERE restored_at IS NULL` — the
restore UI and the per-reason counts — and neither existing index helps them,
because a plain `(staged_at)` index cannot express the predicate. The partial
index is also much smaller: rows leave it permanently once restored.

## What this migration is NOT

An earlier draft also created the tables, on the mistaken belief that they only
existed because `gateway/heartbeat.py` issued `CREATE TABLE IF NOT EXISTS` at
runtime. They did not — migration 014 has owned them since. The runtime DDL was
redundant belt-and-braces on top of an existing migration, which is why
removing it (this PR) is safe and needs no replacement DDL.

That runtime `CREATE TABLE` is what blocked the `noo_app` cutover: the
application role has no CREATE on the schema, and `IF NOT EXISTS` does not
rescue it — Postgres checks the privilege BEFORE the existence shortcut, so it
fails even when the table is already there. Deleting it is the whole fix.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "037_graph_prune_staging"
down_revision: Union[str, None] = "036_audit_partition_definer"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_graph_prune_staging_open "
        "ON graph_prune_staging (staged_at) WHERE restored_at IS NULL"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_graph_edge_prune_staging_open "
        "ON graph_edge_prune_staging (staged_at) WHERE restored_at IS NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_graph_edge_prune_staging_open")
    op.execute("DROP INDEX IF EXISTS ix_graph_prune_staging_open")
