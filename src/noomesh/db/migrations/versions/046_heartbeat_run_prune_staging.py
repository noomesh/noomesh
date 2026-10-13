# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Staging table for pruned heartbeat run records — stage-then-delete, restorable.

``repo::heartbeat::delete_expired_runs`` has existed and been correct since it
was written, and nothing has ever scheduled it. On this deployment that left
11,848 rows, the oldest ~140 days, of which 1,399 were already past the 90-day
cutoff .

The reason it was never simply put on a schedule is that it is a HARD delete.
``graph_prune`` (migration 014) and the temporal-edge prune (045) both stage
before they delete, precisely because the first run of a retention job is the
one nobody has reviewed. Scheduling an unstaged delete would have made 1,399
rows vanish irreversibly on the first tick, and ``noo_heartbeat_runs`` is the
only durable record that a scheduled task ever executed — losing a row makes a
task that ran indistinguishable from one that never fired (the #247 shape).

Neither existing staging table fits. ``graph_edge_prune_staging`` is shaped for
the KG ``edges`` table, and ``noo_user_erasure_staging`` has ``username`` NOT
NULL — a heartbeat run has no user, and forcing a sentinel would pollute "what
was erased for user X", which is a compliance record.

The payload is the WHOLE row as JSONB rather than named columns, so a restore
cannot silently drop a column added to ``noo_heartbeat_runs`` later — the same
class of bug as an INSERT that forgets a field. ``run_id`` is lifted out as its
own column because restore-by-id and "was this specific run pruned?" are the
two queries that actually get asked, and neither should need a JSONB probe.

Revision ID: 046_heartbeat_run_prune_staging
Revises: 045_temporal_edge_prune_staging
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Annotated form is required, not stylistic: tests/test_migration_single_head.py
# matches `revision: str = "..."` to build the migration graph, and a bare
# assignment makes the revision invisible to it.
revision: str = "046_heartbeat_run_prune_staging"
down_revision: Union[str, None] = "045_temporal_edge_prune_staging"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noo_heartbeat_run_prune_staging",
        sa.Column("staging_id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"), nullable=False),
        # The pruned run's own id. NOT a foreign key: the row it points at is
        # deleted in the same transaction that stages it, so an FK would make
        # the prune impossible rather than safe.
        sa.Column("run_id", sa.Text(), nullable=False),
        sa.Column("task_id", sa.Text(), nullable=False),
        # Full row snapshot. Restoring from named columns would silently drop
        # any column added to noo_heartbeat_runs after this migration.
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        # Why it was pruned, so a later reviewer can tell the age-based sweep
        # from some other prune without reading the code that produced it.
        sa.Column("reason", sa.Text(), nullable=False),
        # Groups everything one prune tick staged, so a restore can undo that
        # tick and only that tick.
        sa.Column("prune_run_id", sa.Text(), nullable=True),
        sa.Column("staged_at", sa.DateTime(timezone=True),
                  server_default=sa.text("NOW()"), nullable=False),
        sa.Column("restored_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("staging_id"),
    )
    # Partial index mirroring the other two staging tables: the only query that
    # matters is "what is still restorable", i.e. restored_at IS NULL. It also
    # serves the staging-side expiry sweep, which orders by staged_at.
    op.create_index(
        "ix_heartbeat_run_prune_staging_open",
        "noo_heartbeat_run_prune_staging",
        ["staged_at"],
        postgresql_where=sa.text("restored_at IS NULL"),
    )
    op.create_index(
        "ix_heartbeat_run_prune_staging_run",
        "noo_heartbeat_run_prune_staging",
        ["prune_run_id"],
    )
    # Restore-by-run_id, the operator-facing "put this execution back" path.
    op.create_index(
        "ix_heartbeat_run_prune_staging_runid",
        "noo_heartbeat_run_prune_staging",
        ["run_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_heartbeat_run_prune_staging_runid",
                  table_name="noo_heartbeat_run_prune_staging")
    op.drop_index("ix_heartbeat_run_prune_staging_run",
                  table_name="noo_heartbeat_run_prune_staging")
    op.drop_index("ix_heartbeat_run_prune_staging_open",
                  table_name="noo_heartbeat_run_prune_staging")
    op.drop_table("noo_heartbeat_run_prune_staging")
