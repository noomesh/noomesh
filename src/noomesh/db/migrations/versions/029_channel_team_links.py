# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Space→team links — shared team channels (PR5c).

Revision ID: 029_channel_team_links
Revises: 028_org_columns
Create Date: 2026-07-17

Maps a group channel context (e.g. a Google Chat space `spaces/AAQA…`) to a
team. When an inbound message arrives in a linked space, the ingress owns the
conversation as `user_id = 'team:<name>'` instead of the individual sender, so
every member of that team (anyone granted the `team:<name>` KB role) sees the
space's memory via the team read tier (PR5b-2). DMs stay per-individual.

PK is (channel, channel_space_id). `team` references a `noo_kb_teams.name`
(loose — no FK, teams are a small operator-managed registry).
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "029_channel_team_links"
down_revision: Union[str, None] = "028_org_columns"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "CREATE TABLE IF NOT EXISTS noo_channel_team_links ("
        "  channel TEXT NOT NULL,"
        "  channel_space_id TEXT NOT NULL,"
        "  team TEXT NOT NULL,"
        "  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "  created_by TEXT,"
        "  PRIMARY KEY (channel, channel_space_id)"
        ")"
    )
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_channel_team_links_team "
            "ON noo_channel_team_links (team)"
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_channel_team_links_team")
    op.execute("DROP TABLE IF EXISTS noo_channel_team_links")
