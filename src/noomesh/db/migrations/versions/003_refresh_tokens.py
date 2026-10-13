# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Refresh tokens — short-lived JWT access + long-lived refresh-cookie auth.

Revision ID: 003_refresh_tokens
Revises: 002_pro_tables
Create Date: 2026-04-27

Backs the access+refresh auth flow that replaces the long-lived single-JWT
pattern. Stores refresh-token *hashes* (sha256) — never the raw tokens —
plus issuance / expiry / revocation metadata.

Schema:
  - ``id`` UUID PK
  - ``user_id`` text — username from the JWT ``sub`` claim
  - ``token_hash`` text — sha256 hex of the raw refresh token
  - ``issued_at`` timestamptz default NOW()
  - ``expires_at`` timestamptz — when this refresh token can no longer mint
  - ``revoked_at`` timestamptz nullable — set on logout / rotation
  - ``last_used_at`` timestamptz nullable — set on each successful refresh
  - ``user_agent`` text nullable — UA from the originating request
  - ``ip_address`` text nullable
  - ``rotated_from`` UUID nullable — the previous refresh token this one
    replaced (rotation chain for audit + theft detection: if a `revoked`
    token is presented, it's likely been stolen and used elsewhere)

Indexes:
  - ``token_hash`` (unique, lookup)
  - ``user_id, expires_at`` (cleanup + "log out everywhere" queries)
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "003_refresh_tokens"
down_revision: Union[str, None] = "002_pro_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noo_refresh_tokens",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column(
            "issued_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.Text(), nullable=True),
        sa.Column(
            "rotated_from",
            sa.dialects.postgresql.UUID(as_uuid=False),
            sa.ForeignKey("noo_refresh_tokens.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "uq_noo_refresh_tokens_token_hash",
        "noo_refresh_tokens",
        ["token_hash"],
        unique=True,
    )
    op.create_index(
        "ix_noo_refresh_tokens_user_expires",
        "noo_refresh_tokens",
        ["user_id", "expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_noo_refresh_tokens_user_expires", table_name="noo_refresh_tokens")
    op.drop_index("uq_noo_refresh_tokens_token_hash", table_name="noo_refresh_tokens")
    op.drop_table("noo_refresh_tokens")
