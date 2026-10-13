# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""DB-backed KB role administration.

Revision ID: 017_kb_role_admin
Revises: 016_node_config_gpu_override
Create Date: 2026-07-09

Moves KB role configuration from YAML to editable database tables (the
"runtime-editable business config belongs in the DB" tier):

- ``noo_kb_role_grants`` — extra KB roles granted to a user beyond the
  automatic defaults (user:<sub>, company, system). This is where teams
  and orgs live: grant ["team:research", "org:acme"] to members.
- ``noo_kb_source_rules`` — provenance→roles mapping rules, editable at
  runtime. DB rules take precedence over the kb.source_roles YAML
  section (which remains as seed/fallback).
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "017_kb_role_admin"
down_revision: Union[str, None] = "016_node_config_gpu_override"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noo_kb_role_grants",
        sa.Column("username", sa.Text(), primary_key=True),
        sa.Column("roles", sa.dialects.postgresql.JSONB(), nullable=False,
                  server_default="[]"),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_by", sa.Text(), nullable=True),
    )
    op.create_table(
        "noo_kb_source_rules",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("match", sa.Text(), nullable=False),
        sa.Column("roles", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_by", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("noo_kb_source_rules")
    op.drop_table("noo_kb_role_grants")
