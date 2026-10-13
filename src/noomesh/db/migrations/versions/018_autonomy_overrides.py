# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""DB-backed autonomy location overrides.

Revision ID: 018_autonomy_overrides
Revises: 017_kb_role_admin
Create Date: 2026-07-09

Moves autonomy builtin-location overrides from the YAML overlay to an
editable table (runtime-editable business config tier). Precedence at
the loop: builtin defaults ← YAML overlay ← DB override (DB wins). The
toggle API writes here for builtin locations, so a dashboard toggle
persists without touching config files.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "018_autonomy_overrides"
down_revision: Union[str, None] = "017_kb_role_admin"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noo_autonomy_overrides",
        sa.Column("name", sa.Text(), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("check_interval_seconds", sa.Integer(), nullable=True),
        sa.Column("config", sa.dialects.postgresql.JSONB(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_by", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("noo_autonomy_overrides")
