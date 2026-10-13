# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Bind a service key to a Mesh user, so MCP calls carry that user's identity.

Revision ID: 040_service_key_user
Revises: 039_trellion_signals_ownership
Create Date: 2026-08-01

``noo_service_keys.consumer`` is free-form text naming a *program*
("noo-trading", "codex"). That is the right unit for a machine integration
and stays the default: ``user_id`` is NULLABLE and existing rows keep NULL,
which preserves today's behaviour exactly (the MCP door dispatches as the
operator via cluster-HMAC).

The new column names the *person* a key acts for. When set, the MCP hub
mints a short-lived per-user JWT for that subject instead of using the
shared cluster-HMAC actor, so the caller's ``noo_users`` scopes and KB roles
apply to every tool call — a read-scope user gets read-scope behaviour over
MCP, matching what they get on the dashboard.

ON DELETE CASCADE, not SET NULL: a key issued for a deleted user must stop
working, not silently degrade into an operator-tier key. That is also what
``noo security user erase`` needs — the account and its credentials go
together.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "040_service_key_user"
down_revision: Union[str, None] = "039_trellion_signals_ownership"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # IF NOT EXISTS throughout: ``ServiceKey`` in db/models.py declares this
    # column, so on a FRESH database ``001_baseline``'s
    # ``Base.metadata.create_all()`` has already built it by the time this
    # revision runs. An unguarded add_column fails with DuplicateColumn and
    # the chain cannot be replayed from empty.
    op.execute(
        "ALTER TABLE noo_service_keys "
        "ADD COLUMN IF NOT EXISTS user_id VARCHAR(128)"
    )
    # Postgres has no ADD CONSTRAINT IF NOT EXISTS — check the catalog.
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'fk_noo_service_keys_user'
            ) THEN
                ALTER TABLE noo_service_keys
                    ADD CONSTRAINT fk_noo_service_keys_user
                    FOREIGN KEY (user_id) REFERENCES noo_users(username)
                    ON DELETE CASCADE;
            END IF;
        END $$;
        """
    )
    # Partial: only user-bound keys are ever looked up by user.
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_noo_service_keys_user "
        "ON noo_service_keys (user_id) WHERE user_id IS NOT NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_noo_service_keys_user")
    op.execute(
        "ALTER TABLE noo_service_keys "
        "DROP CONSTRAINT IF EXISTS fk_noo_service_keys_user"
    )
    op.execute("ALTER TABLE noo_service_keys DROP COLUMN IF EXISTS user_id")
