# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Team registry for KB roles.

Revision ID: 021_kb_teams
Revises: 020_noo_users_column_defaults
Create Date: 2026-07-11

Makes teams first-class instead of bare strings inside grants. A row here
registers ``team:<name>`` as a valid KB role: grant and provenance-rule
mutations validate team roles against this table, so a typo like
``team:reserch`` becomes an error instead of a silently-empty audience.
Membership stays in ``noo_kb_role_grants`` (a user is "in" a team when
their grant includes the team role); document membership stays in
``docs.metadata->'roles'``. DDL only — no seed data.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "021_kb_teams"
down_revision: Union[str, None] = "020_noo_users_column_defaults"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noo_kb_teams",
        sa.Column("name", sa.Text(), primary_key=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("created_by", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("noo_kb_teams")
