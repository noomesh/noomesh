# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Graph-prune staging area (soft delete with 30-day selective rollback).

Entities removed by the graph_prune heartbeat action are snapshotted here
(entity row + its edges + mentions as JSONB) instead of vanishing. Rows can
be selectively restored via POST /api/v1/graph/prune/restore within the
retention window (default 30 days), after which the prune task purges them.

Embeddings and graph signals are NOT snapshotted — they regenerate via
rag_reindex / graph_signals after a restore.

Uses IF NOT EXISTS so environments where the table was lazily created by
the heartbeat action before this migration ran are not broken.

Revision ID: 014_graph_prune_staging
Revises: 013_desired_state_config
"""
from typing import Sequence, Union

from alembic import op

revision: str = "014_graph_prune_staging"
down_revision: Union[str, None] = "013_desired_state_config"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS graph_prune_staging (
            staging_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            entity_id UUID NOT NULL,
            canonical_name TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            reason TEXT NOT NULL,
            payload JSONB NOT NULL,
            staged_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            restored_at TIMESTAMPTZ,
            run_id TEXT
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS graph_prune_staging_staged_at_idx "
        "ON graph_prune_staging (staged_at)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS graph_prune_staging_entity_idx "
        "ON graph_prune_staging (entity_id)"
    )

    # Edge-tier staging (edge metabolism — GRAPH_EDGE_METABOLISM.md). Full
    # edge snapshot so a snipped/deduped edge is restorable for the same
    # retention window. Created here so the staged/restore endpoints and UI
    # work before the first graph_prune run (the heartbeat also creates it
    # lazily via CREATE TABLE IF NOT EXISTS — this makes it authoritative).
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS graph_edge_prune_staging (
            staging_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            edge_id UUID NOT NULL,
            src_entity_id UUID NOT NULL,
            rel_type TEXT NOT NULL,
            dst_entity_id UUID NOT NULL,
            confidence DOUBLE PRECISION,
            evidence_json JSONB,
            reason TEXT NOT NULL,
            staged_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            restored_at TIMESTAMPTZ,
            run_id TEXT
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS graph_edge_prune_staging_staged_at_idx "
        "ON graph_edge_prune_staging (staged_at)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS graph_edge_prune_staging_src_idx "
        "ON graph_edge_prune_staging (src_entity_id)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS graph_edge_prune_staging")
    op.execute("DROP TABLE IF EXISTS graph_prune_staging")
