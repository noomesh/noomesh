# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Org/tenant entity + user membership (PR5 org boundary — foundation).

Revision ID: 027_org_boundary
Revises: 026_user_erasure_staging
Create Date: 2026-07-16

Introduces the org as the top tenant boundary above users and teams. This is
the foundation slice: the `noo_orgs` entity + `noo_users.org_id` membership +
`noo_kb_teams.org_id` (teams belong to an org). The per-store `org_id` columns
and the org-scoped read filter land in the next slice (PR5b), paired with the
team memory tier and space→team mapping.

Every existing user/team is assigned to a seeded `default` org so a single-org
deployment is unchanged (one org, everyone in it). No read scoping yet, so this
is behavior-preserving. DDL + a bounded backfill of the (small) users/teams
tables.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "027_org_boundary"
down_revision: Union[str, None] = "026_user_erasure_staging"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "CREATE TABLE IF NOT EXISTS noo_orgs ("
        "  id TEXT PRIMARY KEY,"
        "  name TEXT NOT NULL,"
        "  description TEXT,"
        "  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),"
        "  created_by TEXT"
        ")"
    )
    # Seed the single-org default so existing users/teams have a home.
    op.execute(
        "INSERT INTO noo_orgs (id, name, description, created_by) "
        "VALUES ('default', 'Default', 'Seeded org for the single-org deployment', 'migration') "
        "ON CONFLICT (id) DO NOTHING"
    )
    # Membership columns (nullable; backfilled to default).
    op.execute("ALTER TABLE noo_users ADD COLUMN IF NOT EXISTS org_id TEXT")
    op.execute("ALTER TABLE noo_kb_teams ADD COLUMN IF NOT EXISTS org_id TEXT")
    op.execute("UPDATE noo_users SET org_id = 'default' WHERE org_id IS NULL")
    op.execute("UPDATE noo_kb_teams SET org_id = 'default' WHERE org_id IS NULL")
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_noo_users_org "
            "ON noo_users (org_id) WHERE org_id IS NOT NULL"
        )
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_noo_kb_teams_org "
            "ON noo_kb_teams (org_id) WHERE org_id IS NOT NULL"
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_noo_kb_teams_org")
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_noo_users_org")
    op.execute("ALTER TABLE noo_kb_teams DROP COLUMN IF EXISTS org_id")
    op.execute("ALTER TABLE noo_users DROP COLUMN IF EXISTS org_id")
    op.execute("DROP TABLE IF EXISTS noo_orgs")
