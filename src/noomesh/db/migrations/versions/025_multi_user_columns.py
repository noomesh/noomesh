# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Nullable multi-user (user_id) column on noo_prompt_skill_stats.

Revision ID: 025_multi_user_columns
Revises: 024_audit_integrity_hash
Create Date: 2026-07-16

Option-value schema prep for the multi-user program (PR3b-lite). Adds a **nullable**
``user_id`` (convention: NULL = shared/global) while the deployment is still
single-user, so a future decision to isolate per-user skill stats is a
read-filter flip rather than a migration.

The evolution tables (``noo_rl_arms``, ``noo_ga_generations``,
``noo_hofstadter_loop_cycles``) already carry a nullable ``persona_id`` — that
is their tenant key; activating it (write + the RL arm uniqueness change to
``(persona_id, state_bucket, action_id)``) is the org-boundary phase (PR5), not
this columns-only prep. The trellion graph/temporal/video stores get their
``user_id`` columns in the trellion repo's migration 007_multi_user_columns.

**No behavior change:** nullable, no default, nothing reads/writes it; the index
is partial on non-NULL rows. DDL only. Mirrors 024_audit_integrity_hash.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "025_multi_user_columns"
down_revision: Union[str, None] = "024_audit_integrity_hash"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE noo_prompt_skill_stats ADD COLUMN IF NOT EXISTS user_id text")
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_pss_user_id "
            "ON noo_prompt_skill_stats (user_id) WHERE user_id IS NOT NULL"
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_pss_user_id")
    op.execute("ALTER TABLE noo_prompt_skill_stats DROP COLUMN IF EXISTS user_id")
