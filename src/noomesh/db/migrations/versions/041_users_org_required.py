# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every user belongs to an org — backfill, then enforce.

Migration ``027_org_boundary`` seeded the ``default`` org and ran
``UPDATE noo_users SET org_id = 'default' WHERE org_id IS NULL``. That was a
one-time backfill with nothing behind it: user creation never set ``org_id``
at all (``repo/users.rs::create`` inserted username, hashed_password, scopes,
disabled, failed_login_count and omitted the column), so **every account
created after 027 landed org-less**.

Observed 2026-08-02: a user had a NULL ``org_id`` on a database where 027
had long since run.

An org-less user is not a cosmetic gap. Org-scoped reads filter on
``org_id``, so those rows are invisible to them — the account exists, can
authenticate, and silently sees nothing that is org-scoped. That is a quiet
access-control failure, which is worse than a loud one.

This migration closes the loop the original backfill left open:

1. Backfill again, for accounts created since 027.
2. Make the column NOT NULL, so a future insert that forgets fails loudly
   instead of producing another invisible account.

The insert itself is fixed in the same change (``repo/users.rs``), which is
what makes step 2 safe rather than a trap: NOT NULL without a working default
would break account creation outright.

Revision ID: 041_users_org_required
Revises: 040_service_key_user
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "041_users_org_required"
down_revision: Union[str, None] = "040_service_key_user"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Matches 027's seeded org and the existing runtime fallback in
# routes/users.rs. Kept as a literal rather than a lookup: if the seeded org
# is somehow absent, we want the FK-less insert to still place the user
# somewhere nameable rather than fail the migration.
_DEFAULT_ORG = "default"


def upgrade() -> None:
    conn = op.get_bind()

    # Ensure the fallback org exists before pointing anyone at it. 027 seeds
    # it, but a database restored from a partial dump may not have it, and a
    # NOT NULL pointing at a nonexistent org id is a worse end state than a
    # visible extra row.
    conn.execute(
        sa.text(
            "INSERT INTO noo_orgs (id, name, description, created_by) "
            "VALUES (:id, 'Default', "
            "'Seeded org for the single-org deployment', 'migration') "
            "ON CONFLICT (id) DO NOTHING"
        ),
        {"id": _DEFAULT_ORG},
    )

    result = conn.execute(
        sa.text(
            "UPDATE noo_users SET org_id = :org WHERE org_id IS NULL"
        ),
        {"org": _DEFAULT_ORG},
    )
    # Surfaced deliberately: a non-zero count here means accounts were created
    # org-less since 027, which is the defect this migration exists for.
    print(f"[041] backfilled org_id on {result.rowcount} org-less user(s)")

    op.alter_column(
        "noo_users",
        "org_id",
        existing_type=sa.Text(),
        nullable=False,
        server_default=_DEFAULT_ORG,
    )


def downgrade() -> None:
    # Only the constraint is reversed. The backfilled org_id values are left
    # in place: reverting the schema should not re-create invisible accounts.
    op.alter_column(
        "noo_users",
        "org_id",
        existing_type=sa.Text(),
        nullable=True,
        server_default=None,
    )
