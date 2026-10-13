# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Mint stable UUIDs for users and orgs. Phase A of an earlier change.

Identity today is a NAME used as a primary key: ``noo_users.username`` and
``noo_orgs.id``. Every cross-domain row references a user by a ``text``
principal string, so renaming a user or an org orphans every reference in all
three domains at once — mesh, trellion (memory), and noo-evolve (pro).

That is the blocker for splitting schema ownership three ways. A UUID is the
stable key those domains can carry without any of them owning the others'
tables.

**This migration only mints the values.** The primary keys stay on
``username`` / ``id``, no other table changes, nothing reads the new columns
yet. Phase B carries the UUIDs into the domain tables, phase C flips the PKs.
Splitting it this way means each step is independently revertible, and this
one is a pure addition — downgrade drops two columns nothing depends on.

Deliberately NOT done here:

- **No foreign keys.** an earlier change keeps cross-domain links FK-free so the
  envs can migrate and deploy independently; an FK to ``noo_users`` would
  recreate exactly the coupling the split removes. Integrity is enforced at
  write time instead.
- **No PK flip.** That is phase C, and it must re-verify that nothing has
  added an inbound FK in the meantime. Verified empty on 2026-08-02; a new
  one would turn the flip from safe into breaking.

``gen_random_uuid()`` is a Postgres 13+ builtin — confirmed available on the
live database without the pgcrypto extension.

Revision ID: 042_identity_uuids
Revises: 041_users_org_required
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "042_identity_uuids"
down_revision: Union[str, None] = "041_users_org_required"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # IF NOT EXISTS, not op.add_column: `noo_users` and `noo_orgs` are
    # model-backed, so on a FRESH database `Base.metadata.create_all()` builds
    # them before this revision runs. An unguarded ADD COLUMN then fails with
    # DuplicateColumn and the chain cannot be replayed from empty — the exact
    # case `tests/test_migrations_guard_create_all.py` pins, and the same
    # pattern `027_org_boundary` uses for `org_id`.
    #
    # NOT NULL with a DEFAULT is safe on a populated table: Postgres fills
    # existing rows in one pass, and gen_random_uuid() is evaluated per row so
    # every account gets a distinct value.
    op.execute(
        "ALTER TABLE noo_users ADD COLUMN IF NOT EXISTS user_uuid uuid "
        "NOT NULL DEFAULT gen_random_uuid()"
    )
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_noo_users_uuid "
        "ON noo_users (user_uuid)"
    )
    op.execute(
        "ALTER TABLE noo_orgs ADD COLUMN IF NOT EXISTS org_uuid uuid "
        "NOT NULL DEFAULT gen_random_uuid()"
    )
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_noo_orgs_uuid "
        "ON noo_orgs (org_uuid)"
    )


def downgrade() -> None:
    # Safe to drop: phase A is additive and nothing reads these columns yet.
    # Once phase B backfills domain tables from them, dropping would strand
    # those references — so this downgrade stops being reversible in practice
    # after B lands, which is why B is a separate revision.
    op.execute("DROP INDEX IF EXISTS ux_noo_orgs_uuid")
    op.execute("ALTER TABLE noo_orgs DROP COLUMN IF EXISTS org_uuid")
    op.execute("DROP INDEX IF EXISTS ux_noo_users_uuid")
    op.execute("ALTER TABLE noo_users DROP COLUMN IF EXISTS user_uuid")
