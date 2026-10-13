# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Agent activities — long-running pursuits the agent tracks across runs.

Revision ID: 008_agent_activities
Revises: 007_agent_decisions
Create Date: 2026-06-07

Phase 3 of the meta-loop. The first three loops were event-shaped:

  noo_heartbeat_tasks    — cron-scheduled actions (recurring, no goal)
  noo_heartbeat_runs     — each firing of a task
  noo_self_develop_log   — code-task iterations (single user request)
  noo_agent_decisions    — meta-loop autonomous actions (single decision)

None of them capture *ongoing pursuits* — multi-week research, knowledge
curation campaigns, investigation trails. Those are activities:

  - Span days or weeks
  - Decompose into many tasks / cycles / decisions
  - Have success criteria (when is it "done")
  - Should inform what the agent does when idle

This table is the activities backbone. Heartbeat tasks, self-develop
cycles, and agent decisions can all link back to a parent activity, so
the agent can answer "what am I currently pursuing?" and "what
progress has accumulated on activity X?"

Status state machine:
  active → paused → active   (operator may pause/resume)
  active → completed | abandoned   (terminal)

Kinds (stable strings — queries filter on them):
  research              — periodic research reports on a topic
  knowledge_curation    — KB cleanup / dedup / ingest campaigns
  investigation         — debugging a recurring failure pattern
  monitoring            — long-term watch of a metric / system
  user_pursuit          — user-driven multi-step project
  other                 — anything that doesn't fit above
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "008_agent_activities"
down_revision: Union[str, None] = "007_agent_decisions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noo_agent_activities",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=False),
            primary_key=True,
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="active"),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        # Plain-English criterion for completion. Both human-readable
        # (operator can review) and machine-checkable later by Phase C.
        sa.Column("success_when", sa.Text(), nullable=True),
        # Free-form progress accumulator. Suggested keys (not enforced):
        #   milestones: [{at, summary}], findings: [...], counters: {...}
        # Activities update this as related tasks complete.
        sa.Column(
            "progress",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        # Cross-references to other tables. Stored as JSONB arrays
        # rather than FKs to avoid coupling activity deletes with the
        # high-volume runs/cycles/decisions tables.
        sa.Column(
            "related_task_ids",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "related_cycle_ids",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("created_by", sa.Text(), nullable=False, server_default="user"),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        # Bumped whenever the activity gets touched (progress update,
        # related task linked, etc.). Used to identify stalled
        # activities (no activity in >N days).
        sa.Column(
            "last_activity_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    # "Show me what I'm pursuing right now."
    op.create_index(
        "ix_agent_activities_status",
        "noo_agent_activities",
        ["status", sa.text("last_activity_at DESC")],
    )
    # "Show me research activities" / "Show me investigations."
    op.create_index(
        "ix_agent_activities_kind",
        "noo_agent_activities",
        ["kind", sa.text("created_at DESC")],
    )


def downgrade() -> None:
    op.drop_index("ix_agent_activities_kind", table_name="noo_agent_activities")
    op.drop_index("ix_agent_activities_status", table_name="noo_agent_activities")
    op.drop_table("noo_agent_activities")
