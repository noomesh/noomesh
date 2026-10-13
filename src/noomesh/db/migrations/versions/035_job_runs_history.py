# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Durable job execution history.

Revision ID: 035_job_runs_history
Revises: 034_evolve_role
Create Date: 2026-07-31

Job history currently lives ONLY in Redis (``noo:jobs:history``), a list the
scheduler caps at 1000 entries with LPUSH + LTRIM at write time. That is fine
as a dashboard feed and useless as an audit trail: it is bounded by count
rather than time, so retention depends on throughput, and it does not survive a
Redis flush.

This table is the durable copy. It is deliberately created BEFORE anything
writes to it — the table is the long-lead item, and a schema that exists early
costs nothing while a missing one blocks whoever ports the writer.

Note what this replaces: ``noo_job_history`` was referenced by cleanup code for
months and was created by NO migration in either repo (removed in the
`old_job_records` cleanup). This is the table that reference implied but never
had. The name is deliberately different so nothing resolves against a stale
mental model of the old one.

## Why not the audit log

``noo_security_audit`` is hash-chained (``entry_hash``/``prev_hash``),
partitioned monthly, and carries ~365 rows/month of genuinely security-relevant
events — auth, config_update, user_erase. Operational job rows would dilute it
twice over: chain verification cost scales with length, and real security
events get buried in throughput. Security-RELEVANT job actions (an operator
triggering a job, a job executing a cluster action) still belong there, as one
event each — not as the full run record.

The model here is ``noo_heartbeat_runs``, which is the same shape and is proven
at ~11.6k rows.

## Not partitioned, on purpose

``scheduler_status`` reports ``history_size: 0`` today, so there is no
throughput measurement to size partitioning against. Partitioning on
``completed_at`` following the ``noo_security_audit`` pattern is the move if
volume warrants it; guessing now would bake in a shape nobody measured.

Grants are inherited: migration 033 set ALTER DEFAULT PRIVILEGES for
``noo_app`` on tables created in ``public``, so this table is reachable by the
application role without an explicit GRANT.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "035_job_runs_history"
down_revision: Union[str, None] = "034_evolve_role"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noo_job_runs",
        # Surrogate key: job_id is NOT unique over time. A re-queued or retried
        # job keeps its id, and collapsing those into one row would destroy the
        # retry history this table exists to preserve.
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=False),
                  server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("job_id", sa.Text(), nullable=False),
        sa.Column("job_type", sa.Text(), nullable=False),
        # Nullable: a job that never reached a node has no node_id, and
        # recording "" would make "unassigned" indistinguishable from a node
        # literally named "".
        sa.Column("node_id", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("retries", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        # Free-form payload so a scheduler change does not require a migration
        # to record one more field.
        sa.Column("details", sa.dialects.postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    # Retention sweeps and "recent runs" both order by completion.
    op.create_index("ix_noo_job_runs_completed_at", "noo_job_runs", ["completed_at"])
    # "show me every attempt of this job" — the retry view.
    op.create_index("ix_noo_job_runs_job_id", "noo_job_runs", ["job_id"])
    op.create_index("ix_noo_job_runs_status", "noo_job_runs", ["status"])


def downgrade() -> None:
    op.drop_index("ix_noo_job_runs_status", table_name="noo_job_runs")
    op.drop_index("ix_noo_job_runs_job_id", table_name="noo_job_runs")
    op.drop_index("ix_noo_job_runs_completed_at", table_name="noo_job_runs")
    op.drop_table("noo_job_runs")
