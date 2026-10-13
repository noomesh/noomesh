# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Server-side defaults for noo_users NOT NULL columns.

Revision ID: 020_noo_users_column_defaults
Revises: 019_autonomy_custom_locations
Create Date: 2026-07-10

``disabled`` and ``failed_login_count`` are NOT NULL but had no
defaults, so any INSERT that omitted them failed with a
NotNullViolation — `noo security user create` was broken this way
(found 2026-07-10 while provisioning the first read-scope user).
DDL-only: adds defaults, touches no data.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "020_noo_users_column_defaults"
down_revision: Union[str, None] = "019_autonomy_custom_locations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "noo_users", "disabled",
        server_default=sa.text("false"),
        existing_type=sa.Boolean(),
        existing_nullable=False,
    )
    op.alter_column(
        "noo_users", "failed_login_count",
        server_default=sa.text("0"),
        existing_type=sa.Integer(),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "noo_users", "disabled",
        server_default=None,
        existing_type=sa.Boolean(),
        existing_nullable=False,
    )
    op.alter_column(
        "noo_users", "failed_login_count",
        server_default=None,
        existing_type=sa.Integer(),
        existing_nullable=False,
    )
