# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Org/tenant (org_id) column on noo_prompt_skill_stats (PR5b).

Revision ID: 028_org_columns
Revises: 027_org_boundary
Create Date: 2026-07-17

Companion to trellion 008_org_columns. Adds `org_id` to the one mesh-owned
per-tenant store (`noo_prompt_skill_stats`) and backfills to the single-org
`default`, so the org read filter is a no-op today. The org entity + user/team
membership landed in 027_org_boundary. DDL + bounded backfill; mirrors
025_multi_user_columns.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "028_org_columns"
down_revision: Union[str, None] = "027_org_boundary"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE noo_prompt_skill_stats ADD COLUMN IF NOT EXISTS org_id text")
    op.execute("UPDATE noo_prompt_skill_stats SET org_id = 'default' WHERE org_id IS NULL")
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_pss_org "
            "ON noo_prompt_skill_stats (org_id) WHERE org_id IS NOT NULL"
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_pss_org")
    op.execute("ALTER TABLE noo_prompt_skill_stats DROP COLUMN IF EXISTS org_id")
