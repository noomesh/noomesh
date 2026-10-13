# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""DB-backed custom autonomy location definitions.

Revision ID: 019_autonomy_custom_locations
Revises: 018_autonomy_overrides
Create Date: 2026-07-09

Completes the autonomy YAML→DB consolidation: custom location
DEFINITIONS (name, type, conditions, actions, intervals) move to an
editable table. The YAML autonomy.locations section becomes read-only
seed — first UI touch of a YAML-defined custom lazily migrates it here.
No API path writes YAML anymore.

Note: custom locations currently have no generic evaluator in the Rust
loop (pre-existing — they were decorative in YAML too); this migration
is about a single writable store, not about making them execute.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "019_autonomy_custom_locations"
down_revision: Union[str, None] = "018_autonomy_overrides"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noo_autonomy_locations",
        sa.Column("name", sa.Text(), primary_key=True),
        sa.Column("definition", sa.dialects.postgresql.JSONB(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_by", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("noo_autonomy_locations")
