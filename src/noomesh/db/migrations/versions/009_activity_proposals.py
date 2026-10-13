# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Activity proposals — agent's suggestions for activities to create.

Revision ID: 009_activity_proposals
Revises: 008_agent_activities
Create Date: 2026-06-07

Phase C-1 of the meta-loop. The agent watches recurring patterns
(repeat-offender heartbeat tasks, recurring failures, repeated
topics) and writes PROPOSALS — not activities directly. Operator
reviews and accepts/rejects via dashboard, OR Phase C-3 auto-creates
high-confidence proposals.

Why a proposals table and not just direct creation:
- **Human in the loop**: the first cut of pattern inference will get
  some wrong. Proposals let the operator see "what the agent noticed"
  without contaminating the activities table with low-quality entries.
- **Suppression**: rejecting a proposal can mark "do not propose this
  pattern again" — gives a learning signal.
- **Confidence tracking**: as the same pattern fires repeatedly, the
  proposal accumulates trigger_count, eventually meeting Phase C-3's
  auto-create threshold.

State machine:
  pending → accepted (becomes activity) | rejected (suppressed)
  pending → expired (no decision in 7+ days, auto-cleared)
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "009_activity_proposals"
down_revision: Union[str, None] = "008_agent_activities"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noo_activity_proposals",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=False),
            primary_key=True,
        ),
        # Stable identifier for the pattern (e.g. "repeat_offender:cluster_health")
        # — same pattern = same key. Phase C-1 uses this for dedup; multiple
        # detections of the same pattern just bump trigger_count instead of
        # creating duplicate proposals.
        sa.Column("pattern_key", sa.Text(), nullable=False, unique=True),
        # Which pattern detector fired this. Stable strings:
        #   'repeat_offender_task' — heartbeat task fails N+ in window
        #   'stalled_self_develop' — same goal text repeats across cycles
        #   'recurring_security_event' — same audit event spikes daily
        sa.Column("pattern_type", sa.Text(), nullable=False),
        # What the proposed activity would look like.
        sa.Column("proposed_name", sa.Text(), nullable=False),
        sa.Column("proposed_kind", sa.Text(), nullable=False),
        sa.Column("proposed_description", sa.Text(), nullable=False),
        sa.Column("proposed_success_when", sa.Text(), nullable=True),
        # Number of times this pattern has been detected. Grows on each
        # scan that matches; used by Phase C-3 to decide auto-create.
        sa.Column("trigger_count", sa.Integer(), nullable=False, server_default="1"),
        # When the pattern was first/last detected. Last is what
        # "freshness" checks look at.
        sa.Column(
            "first_detected_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_detected_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        # Raw data the detector saw (for the operator to inspect what
        # triggered the proposal). Free-form JSONB.
        sa.Column(
            "evidence",
            sa.dialects.postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        # State
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        # If accepted, the activity_id we created. If rejected, NULL.
        sa.Column(
            "resulting_activity_id",
            sa.dialects.postgresql.UUID(as_uuid=False),
            nullable=True,
        ),
        sa.Column("decided_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("decided_by", sa.Text(), nullable=True),  # 'user' | 'agent' | 'auto'
        sa.Column("decision_note", sa.Text(), nullable=True),
    )
    # Pending proposals ranked by trigger_count (auto-create candidates).
    op.create_index(
        "ix_activity_proposals_pending",
        "noo_activity_proposals",
        ["status", sa.text("trigger_count DESC"), sa.text("last_detected_at DESC")],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_activity_proposals_pending", table_name="noo_activity_proposals"
    )
    op.drop_table("noo_activity_proposals")
