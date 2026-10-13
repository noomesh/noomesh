# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Admin-toggnable behavioral settings (feature flags in the DB).

Revision ID: 030_settings
Revises: 029_channel_team_links
Create Date: 2026-07-18

`noo_settings` is the DB override layer for BEHAVIORAL feature flags (autonomy,
features, governance, ops) that today live only in env vars. The read helper
(`noomesh.settings.flag`) resolves DB value → env default → hard default, so
an empty table changes nothing (env stays the bootstrap default). Admins toggle
these from the UI (`PUT /api/settings/flags`, audited); changes hot-reload via a
short TTL cache — no restart.

NOT for security-posture gates (multi-user, auth, TLS): those are managed
separately (`noo_security_posture`, operator-only, restart-to-apply) so the app
UI can never weaken the security boundary.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "030_settings"
down_revision: Union[str, None] = "029_channel_team_links"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "CREATE TABLE IF NOT EXISTS noo_settings ("
        "  key TEXT PRIMARY KEY,"
        "  value TEXT NOT NULL,"
        "  category TEXT NOT NULL DEFAULT 'general',"
        "  updated_by TEXT,"
        "  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"
        ")"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS noo_settings")
