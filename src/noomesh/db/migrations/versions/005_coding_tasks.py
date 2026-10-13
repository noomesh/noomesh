# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Coding tasks — persist Claude Code subprocess state across gateway restarts.

Revision ID: 005_coding_tasks
Revises: 004_cluster_proposals
Create Date: 2026-05-03

CodingTaskManager previously kept its task dict in-memory only, so a
gateway restart wiped all in-flight task state and `noo_coding_status`
queries against pre-restart task IDs returned "Task not found." The Rust
GET routes at `/api/coding/tasks` already query this table — adding
the table + Python writer closes the loop.

State machine: pending → running → completed | failed
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "005_coding_tasks"
down_revision: Union[str, None] = "004_cluster_proposals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noo_coding_tasks",
        # 12-char hex (uuid4().hex[:12]) — matches CodingTask.id default
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("channel", sa.Text(), nullable=False, server_default=""),
        sa.Column("conversation_id", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("result", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("elapsed_seconds", sa.Float(), nullable=True),
        sa.Column(
            "files_edited",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_noo_coding_tasks_status_started",
        "noo_coding_tasks",
        ["status", "started_at"],
    )
    op.create_index(
        "ix_noo_coding_tasks_conversation",
        "noo_coding_tasks",
        ["conversation_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_noo_coding_tasks_conversation", table_name="noo_coding_tasks")
    op.drop_index("ix_noo_coding_tasks_status_started", table_name="noo_coding_tasks")
    op.drop_table("noo_coding_tasks")
