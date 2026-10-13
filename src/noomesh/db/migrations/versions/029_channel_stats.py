# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Persist per-channel send/recv/error counters.

Revision ID: 029_channel_stats
Revises: 028_org_columns
Create Date: 2026-07-17

The ChannelManager tracked ``received``/``sent``/``errors`` counters in an
in-memory dict (``ChannelManager._stats``) that reset to zero on every gateway
restart, so the dashboard's per-channel activity numbers were meaningless
across restarts. This table gives those counters a durable home: the manager
seeds its in-memory counters from here on startup and flushes the absolute
values back on a periodic loop (see ``ChannelManager.start_stats_persistence``).

One row per channel; the counters are cumulative-since-first-seen totals.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "029_channel_stats"
down_revision: Union[str, None] = "028_org_columns"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "CREATE TABLE IF NOT EXISTS noo_channel_stats ("
        "  channel TEXT PRIMARY KEY,"
        "  received BIGINT NOT NULL DEFAULT 0,"
        "  sent BIGINT NOT NULL DEFAULT 0,"
        "  errors BIGINT NOT NULL DEFAULT 0,"
        "  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"
        ")"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS noo_channel_stats")
