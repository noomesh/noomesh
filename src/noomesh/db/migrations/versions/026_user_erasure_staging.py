# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Staging table for user erasure (RTBF) — archive-then-delete recovery.

Revision ID: 026_user_erasure_staging
Revises: 025_multi_user_columns
Create Date: 2026-07-16

`noo security user erase <username>` (native Rust, routes/users.rs) removes a
user's data across every store. Before each DELETE it snapshots the affected
rows here as JSONB, so an erasure is recoverable within a retention window
(mirrors the graph_prune_staging pattern from migration 014). This is the
operator-recovery "cold tier"; exporting snapshots to the object-store cold
archive for long-term retention is a separate/optional path.

`payload` holds the deleted row as `to_jsonb(row)`. `run_id` groups one erasure
run so it can be restored or purged as a unit. `restored_at` is stamped when a
row is put back. DDL only.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "026_user_erasure_staging"
down_revision: Union[str, None] = "025_multi_user_columns"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "CREATE TABLE IF NOT EXISTS noo_user_erasure_staging ("
        "  id BIGSERIAL PRIMARY KEY,"
        "  run_id UUID NOT NULL,"
        "  username TEXT NOT NULL,"
        "  store TEXT NOT NULL,"
        "  payload JSONB NOT NULL,"
        "  staged_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "  restored_at TIMESTAMPTZ"
        ")"
    )
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_user_erasure_staging_run "
            "ON noo_user_erasure_staging (run_id)"
        )
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_user_erasure_staging_user "
            "ON noo_user_erasure_staging (username, staged_at)"
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_user_erasure_staging_user")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_user_erasure_staging_run")
    op.execute("DROP TABLE IF EXISTS noo_user_erasure_staging")
