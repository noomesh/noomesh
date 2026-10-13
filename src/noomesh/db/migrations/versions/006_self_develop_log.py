# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Self-develop log — durable audit of user-triggered self-development cycles.

Revision ID: 006_self_develop_log
Revises: 005_coding_tasks
Create Date: 2026-05-22

When the coordinator decides a user request requires code changes (e.g.
"add a new feature", "fix this bug"), it kicks off a *self-develop
cycle* — an iterative loop of (delegate-to-coding-task → observe-output
→ verify → decide-next-action). This table is the audit log of that
loop.

Each row is one **iteration** within a cycle. ``cycle_id`` groups
iterations belonging to the same user request; ``iteration`` orders
them. Cycle-level fields (``trigger_source``, ``goal``,
``conversation_id``) are denormalized onto every row — storage is cheap,
single-table queries are simple, and grouping is trivial.

Status state machine (per iteration):
  pending → running → completed | failed | abandoned

The cycle's effective status is the latest iteration's status; a cycle
ends when an iteration reaches ``completed`` or ``abandoned``.

This is the foundation for closed-loop self-evolution: future autonomy
actions that invoke `noo_coding_task` will write to this same table,
distinguished by ``trigger_source`` (``user_message`` vs ``autonomy``
vs ``heartbeat``).
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "006_self_develop_log"
down_revision: Union[str, None] = "005_coding_tasks"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noo_self_develop_log",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=False),
            primary_key=True,
        ),
        # Cycle grouping — all iterations of one user-triggered loop share this.
        sa.Column(
            "cycle_id",
            sa.dialects.postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column("iteration", sa.Integer(), nullable=False, server_default="1"),
        # Provenance (cycle-level, denormalized onto each iteration row).
        sa.Column("trigger_source", sa.Text(), nullable=False),  # user_message | autonomy | heartbeat
        sa.Column("trigger_actor", sa.Text(), nullable=True),    # user id, channel, condition name
        sa.Column("conversation_id", sa.Text(), nullable=True),
        sa.Column("goal", sa.Text(), nullable=False, server_default=""),
        # This iteration's action.
        sa.Column("action_type", sa.Text(), nullable=False),     # invoke_claude_code | analyze_failure | verify | abandon
        sa.Column(
            "action_input",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        # Link to coding task (when action_type=invoke_claude_code).
        sa.Column("coding_task_id", sa.Text(), nullable=True),
        # Outcome of this iteration.
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("observations", sa.Text(), nullable=True),     # what was observed (errors, test output)
        sa.Column(
            "files_touched",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "verification",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("next_decision", sa.Text(), nullable=True),    # retry|iterate|done|abandon + reason
        # Timing.
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    # Fetch all iterations of a cycle in order.
    op.create_index(
        "ix_self_develop_log_cycle",
        "noo_self_develop_log",
        ["cycle_id", "iteration"],
    )
    # "What's running / recently active?"
    op.create_index(
        "ix_self_develop_log_status_started",
        "noo_self_develop_log",
        ["status", sa.text("started_at DESC")],
    )
    # "Show me recent cycles by source."
    op.create_index(
        "ix_self_develop_log_trigger_created",
        "noo_self_develop_log",
        ["trigger_source", sa.text("created_at DESC")],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_self_develop_log_trigger_created", table_name="noo_self_develop_log"
    )
    op.drop_index(
        "ix_self_develop_log_status_started", table_name="noo_self_develop_log"
    )
    op.drop_index("ix_self_develop_log_cycle", table_name="noo_self_develop_log")
    op.drop_table("noo_self_develop_log")
