# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Per-consumer request quota on service keys.

Revision ID: 015_service_key_quota
Revises: 014_graph_prune_staging
Create Date: 2026-07-06

Adds a per-key requests-per-minute cap to ``noo_service_keys`` so a single
consumer (noo-trading, codex, …) can't monopolise the shared compute surface.
``rpm_limit`` is nullable — NULL means "no per-consumer cap" (the global
per-IP limiter still applies). The Rust gateway reads it during key resolution
and enforces a Redis token bucket keyed by consumer name at the external
inference door; the MCP hub enforces the same bucket at ``/mcp/external``.

The ``mcp`` scope (added to the CLI vocabulary in the same change) is stored in
the existing ``scopes`` jsonb — no schema change needed for it.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "015_service_key_quota"
down_revision: Union[str, None] = "014_graph_prune_staging"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # BIGINT (not INT) so it decodes cleanly as Rust i64 in the gateway's
    # sqlx query — sqlx maps INT4↔i32 / INT8↔i64 strictly, and a width
    # mismatch would make every service-key resolution silently fail.
    # IF NOT EXISTS: `001_baseline`'s create_all builds noo_service_keys
    # from the current model, which already declares this column, so on a
    # fresh database a plain ADD COLUMN fails with DuplicateColumn.
    op.execute(
        "ALTER TABLE noo_service_keys ADD COLUMN IF NOT EXISTS "
        "rpm_limit BIGINT"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE noo_service_keys DROP COLUMN IF EXISTS rpm_limit")
