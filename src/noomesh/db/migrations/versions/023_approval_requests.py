# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Backing table for the exec-approval queue.

Revision ID: 023_approval_requests
Revises: 022_user_proposals
Create Date: 2026-07-11

The Rust gateway's /api/approval/* CRUD has queried this table since the
2026-03-31 port, but no migration ever created it — so approvals were
never persistable and blocking HIGH-risk requests could only time out.
Columns match the Rust handlers' queries exactly (request_id/tool_name/
risk_level/reason/status/created_at/resolved_by/resolved_at). The Python
ExecApprovalManager now mirrors its in-memory queue here so decisions
made from any process (dashboard, CLI) reach the blocked caller.
DDL only.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "023_approval_requests"
down_revision: Union[str, None] = "022_user_proposals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noo_approval_requests",
        sa.Column("request_id", sa.Text(), primary_key=True),
        sa.Column("tool_name", sa.Text(), nullable=False),
        sa.Column("risk_level", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("resolved_by", sa.Text(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_noo_approval_requests_status",
                    "noo_approval_requests", ["status"])


def downgrade() -> None:
    op.drop_index("ix_noo_approval_requests_status")
    op.drop_table("noo_approval_requests")
