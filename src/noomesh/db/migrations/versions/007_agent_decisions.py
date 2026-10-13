# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Agent decisions — audit log of meta-loop autonomous actions.

Revision ID: 007_agent_decisions
Revises: 006_self_develop_log
Create Date: 2026-05-26

Phase 1 of the meta-loop (``agent_self_check`` action) is
observation-only — it scans audit tables and emits a digest. Phase 2
sub-pieces (auto-retry, escalation notify, engine escalate,
auto-disable, self-edit) each take autonomous action when their
respective env var is set:

  - NOO_AGENT_AUTORETRY=1
  - NOO_AGENT_ESCALATE_NOTIFY=1
  - NOO_AGENT_ENGINE_ESCALATE=1
  - NOO_AGENT_AUTODISABLE=1
  - NOO_AGENT_SELF_EDIT=1

This table is where each autonomous action records WHAT it did, WHY,
and WHAT HAPPENED. Two reasons:

1. **Cooldowns** — Phase 2a/2b/2e use queries against this table to
   decide "have I already acted on this in the last N hours?" to
   prevent flapping. Without persistence, a restart wipes the cooldown
   and the loop fires the same action repeatedly.

2. **Operator visibility** — when something goes sideways, the audit
   tells the story: "the meta-loop disabled task X at T1 after 5
   consecutive failures; here are the failures, here's the
   notification I sent, here's the operator's reactivation at T2."

State machine per row:
  pending → success | failure  (terminal)

Decision types (stable strings — queries filter on them):
  auto_retry, escalate_notify, engine_escalate, auto_disable,
  self_edit, observed (digest-only, no action taken).
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "007_agent_decisions"
down_revision: Union[str, None] = "006_self_develop_log"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noo_agent_decisions",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=False),
            primary_key=True,
        ),
        # All decisions made within a single agent_self_check run share
        # this id, so the digest can link to its decisions and we can
        # group "what did the loop do at 8am today?" cleanly.
        sa.Column(
            "scan_id",
            sa.dialects.postgresql.UUID(as_uuid=False),
            nullable=False,
        ),
        sa.Column(
            "scan_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        # Which Phase 2 piece (or 'observed' for Phase 1 digest-only).
        sa.Column("decision_type", sa.Text(), nullable=False),
        # Human-readable description of what we found.
        sa.Column("finding", sa.Text(), nullable=False),
        # Human-readable description of the action (or 'deferred' if
        # the relevant Phase 2 gate was off).
        sa.Column("action_taken", sa.Text(), nullable=True),
        # What was acted upon: heartbeat_task / self_develop_cycle /
        # security_event / coding_task / pattern.
        sa.Column("target_kind", sa.Text(), nullable=True),
        sa.Column("target_id", sa.Text(), nullable=True),
        # Action-specific data (cooldown windows, retry counts,
        # escalation thresholds at time of decision, etc.).
        sa.Column(
            "metadata",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        # Outcome of the action.
        sa.Column("outcome", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("outcome_detail", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    # "What did the loop do during this self-check run?"
    op.create_index(
        "ix_agent_decisions_scan",
        "noo_agent_decisions",
        ["scan_id", "created_at"],
    )
    # Cooldown queries: "Have I acted on heartbeat_task X recently?"
    op.create_index(
        "ix_agent_decisions_target",
        "noo_agent_decisions",
        ["target_kind", "target_id", sa.text("created_at DESC")],
    )
    # Cross-cutting: "Show me all auto-disable decisions in the last week."
    op.create_index(
        "ix_agent_decisions_type_time",
        "noo_agent_decisions",
        ["decision_type", sa.text("created_at DESC")],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_agent_decisions_type_time", table_name="noo_agent_decisions"
    )
    op.drop_index("ix_agent_decisions_target", table_name="noo_agent_decisions")
    op.drop_index("ix_agent_decisions_scan", table_name="noo_agent_decisions")
    op.drop_table("noo_agent_decisions")
