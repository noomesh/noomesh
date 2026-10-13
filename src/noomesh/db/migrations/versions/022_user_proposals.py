# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""User-management proposals (agent-initiated, human-approved).

Revision ID: 022_user_proposals
Revises: 021_kb_teams
Create Date: 2026-07-11

The agent cannot mutate accounts directly: internal callers of the users
admin API are redirected here. A proposal row records the requested
action; a logged-in operator (JWT with admin/write) approves or denies
via the dashboard or CLI, and approval executes the action. Passwords
are never stored — approve-create generates one and returns it to the
approver once. DDL only.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "022_user_proposals"
down_revision: Union[str, None] = "021_kb_teams"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noo_user_proposals",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("payload", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("requested_by", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decided_by", sa.Text(), nullable=True),
        sa.Column("result", sa.dialects.postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("noo_user_proposals")
