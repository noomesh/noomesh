# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Security-posture store + merge the 029 branch (Part 2).

Revision ID: 031_security_posture
Revises: 030_settings, 029_channel_stats
Create Date: 2026-07-18

Two things:

1. **Merge** the concurrent 029 branch — ``029_channel_stats`` and
   ``029_channel_team_links`` both revise ``028_org_columns`` (two heads;
   ``030_settings`` descends from the latter). This migration lists BOTH heads
   as ``down_revision`` so alembic re-linearises to a single head.

2. Create ``noo_security_posture`` — the DB-authoritative store for the
   *app-tier* security gates (multi-user, auth, cluster-strict, exec-approval,
   node-agent-privileged). At boot the gateway loads these and overrides the
   env, so a customer's posture lives in the DB (operator-managed, audited,
   restart-to-apply) rather than a hand-edited ``.env``. Bootstrap-tier gates
   (TLS, secrets — needed before the DB is reachable) stay in the secrets
   backend and are NOT here. ``requires_restart`` documents that a change only
   takes effect on the next gateway restart (the gates are read-once).
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "031_security_posture"
down_revision: Union[str, Sequence[str], None] = ("030_settings", "029_channel_stats")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "CREATE TABLE IF NOT EXISTS noo_security_posture ("
        "  key TEXT PRIMARY KEY,"
        "  value TEXT NOT NULL,"
        "  requires_restart BOOLEAN NOT NULL DEFAULT TRUE,"
        "  updated_by TEXT,"
        "  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"
        ")"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS noo_security_posture")
