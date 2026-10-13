# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Staging table for pruned temporal-graph edges — stage-then-delete, restorable.

Orphaned temporal edges (their source conversation no longer exists) can never
be attributed to anyone, so they are personal data that no erasure request can
reach. Deleting them closes that hole — but they also carry months of learned
preferences (``prefers``, ``dislikes``, ``working_on``), and the assumption that
extraction will rebuild equivalent knowledge is exactly that: an assumption.

So the prune stages before it deletes, matching what ``graph_prune`` already
does for the KG (migration 014). Neither existing staging table fits:

- ``graph_edge_prune_staging`` is shaped for the KG ``edges`` table
  (``src_entity_id``/``rel_type``/``dst_entity_id``) and its ``dst_entity_id``
  is NOT NULL. Every ``noo_temporal_edges`` row has ``object_entity_id`` NULL —
  measured 4076/4076 — so nothing would stage.
- ``noo_user_erasure_staging`` is generic JSONB but ``username`` is NOT NULL,
  and an orphan has no user. Forcing a sentinel would also pollute
  "what was erased for user X", which is a compliance record.

The payload is the WHOLE row as JSONB rather than named columns, so a restore
cannot silently drop a column added to ``noo_temporal_edges`` later — the same
class of bug as an INSERT that forgets a field.

Revision ID: 045_temporal_edge_prune_staging
Revises: 044_identity_uuid_pk
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Annotated form is required, not stylistic: tests/test_migration_single_head.py
# matches `revision: str = "..."` to build the migration graph, and a bare
# assignment makes the revision invisible to it.
revision: str = "045_temporal_edge_prune_staging"
down_revision: Union[str, None] = "044_identity_uuid_pk"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noo_temporal_edge_prune_staging",
        sa.Column("staging_id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("edge_id", postgresql.UUID(as_uuid=True), nullable=False),
        # Full row snapshot. Restoring from named columns would silently drop
        # any column added to noo_temporal_edges after this migration.
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        # Why it was pruned, so a later reviewer can tell an orphan sweep from
        # some other prune without reading the code that produced it.
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Text(), nullable=True),
        sa.Column("staged_at", sa.DateTime(timezone=True),
                  server_default=sa.text("NOW()"), nullable=False),
        sa.Column("restored_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("staging_id"),
    )
    # Partial index mirroring graph_edge_prune_staging: the only query that
    # matters is "what is still restorable", i.e. restored_at IS NULL.
    op.create_index(
        "ix_temporal_edge_prune_staging_open",
        "noo_temporal_edge_prune_staging",
        ["staged_at"],
        postgresql_where=sa.text("restored_at IS NULL"),
    )
    op.create_index(
        "ix_temporal_edge_prune_staging_run",
        "noo_temporal_edge_prune_staging",
        ["run_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_temporal_edge_prune_staging_run",
                  table_name="noo_temporal_edge_prune_staging")
    op.drop_index("ix_temporal_edge_prune_staging_open",
                  table_name="noo_temporal_edge_prune_staging")
    op.drop_table("noo_temporal_edge_prune_staging")
