# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Cluster proposals — Tier 2 of agent-driven node enrollment.

Revision ID: 004_cluster_proposals
Revises: 003_refresh_tokens
Create Date: 2026-04-27

Pending state for nodes the agent wants to add but a human hasn't
approved yet. Decisions can come from the dashboard, a Google Chat
card-button, or a Telegram inline-keyboard tap — same row, different
``decided_via``.

Status state machine:
  pending → approved → executed | failed
  pending → rejected

After ``approved``, an executor (Phase 4) runs the actual playbook
and flips status to ``executed`` (with ``execution_log``) or
``failed`` (with the error in ``execution_log``).
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "004_cluster_proposals"
down_revision: Union[str, None] = "003_refresh_tokens"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noo_cluster_proposals",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("host", sa.Text(), nullable=False),
        sa.Column("user_name", sa.Text(), nullable=False),  # `user` is reserved
        sa.Column("role", sa.Text(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("proposed_by", sa.Text(), nullable=False),
        sa.Column(
            "proposed_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("decided_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("decided_by", sa.Text(), nullable=True),
        sa.Column("decided_via", sa.Text(), nullable=True),
        sa.Column("executed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("execution_log", sa.Text(), nullable=True),
        sa.Column(
            "metadata",
            sa.dialects.postgresql.JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.create_index(
        "ix_cluster_proposals_status", "noo_cluster_proposals", ["status"]
    )
    op.create_index(
        "ix_cluster_proposals_proposed_at",
        "noo_cluster_proposals",
        [sa.text("proposed_at DESC")],
    )


def downgrade() -> None:
    op.drop_index("ix_cluster_proposals_proposed_at", table_name="noo_cluster_proposals")
    op.drop_index("ix_cluster_proposals_status", table_name="noo_cluster_proposals")
    op.drop_table("noo_cluster_proposals")
