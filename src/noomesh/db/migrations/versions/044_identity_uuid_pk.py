# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Make the UUIDs the primary keys. an earlier change.

Phases A and B minted ``user_uuid``/``org_uuid`` and carried the user UUID into
the mesh-owned tables. This flips the primary keys, so identity stops being a
NAME. Today renaming a user or an org orphans every reference in all three
domains at once, because the name IS the key.

``username`` and ``noo_orgs.id`` are KEPT as unique attributes — they are how
operators refer to accounts and orgs, and `'default'` is a value people
recognise. Only their role as the key changes.

## An FK appeared between the plan and this revision

an earlier change recorded "zero foreign keys to noo_users, verified 2026-08-02",
and required re-verifying before the flip because a new one would turn it from
safe into breaking. That is exactly what happened:
``040_service_key_user`` added

    fk_noo_service_keys_user
      FOREIGN KEY (user_id) REFERENCES noo_users(username) ON DELETE CASCADE

The original verification was run against the LIVE database, which had not yet
applied 040 — the migration existed in the repo but not in that schema.
Checking a schema precondition against a database that lags the chain gives a
false answer. Verify against the chain, or against a database known to be at
head.

So a naive ``DROP CONSTRAINT noo_users_pkey`` fails outright:

    ERROR: cannot drop constraint noo_users_pkey ... because other objects
    depend on it
    DETAIL: constraint fk_noo_service_keys_user depends on index noo_users_pkey

The FK is intra-env (both tables are mesh-owned), so it is legitimate and is
PRESERVED rather than dropped — an earlier change's FK-free rule is about
CROSS-domain links, which is a different thing. The sequence below drops it
only long enough to move the key out from under it, then puts it back
pointing at the same column, now backed by a real UNIQUE constraint.

Verified end to end on a throwaway database before writing: the flip
succeeds, ``ON CONFLICT (username)`` in ``repo::users::create`` still
resolves, and the service-key ON DELETE CASCADE still removes dependent rows
(0 orphans after deleting a user).

Revision ID: 044_identity_uuid_pk
Revises: 043_domain_user_uuid
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "044_identity_uuid_pk"
down_revision: Union[str, None] = "043_domain_user_uuid"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# FKs that reference noo_users(username) and must be re-pointed around the
# flip. Listed explicitly rather than discovered dynamically: a migration that
# silently drops and recreates whatever constraints it happens to find is a
# migration that can silently lose one.
_USERNAME_FKS = [
    (
        "noo_service_keys",
        "fk_noo_service_keys_user",
        "FOREIGN KEY (user_id) REFERENCES noo_users(username) ON DELETE CASCADE",
    ),
]


def _fail_on_unknown_fks(conn) -> None:
    """Refuse to run if an FK we do not know about references these tables.

    The whole failure mode this migration exists around is "an FK appeared
    since the plan was written". Detecting that and stopping is far better
    than dropping it with CASCADE and discovering later that something lost
    its referential integrity.
    """
    known = {name for _, name, _ in _USERNAME_FKS}
    rows = conn.execute(
        sa.text(
            "SELECT conname, conrelid::regclass::text FROM pg_constraint "
            "WHERE contype = 'f' AND confrelid IN "
            "('noo_users'::regclass, 'noo_orgs'::regclass)"
        )
    ).fetchall()
    unknown = [(c, t) for c, t in rows if c not in known]
    if unknown:
        raise RuntimeError(
            "044 refuses to flip the primary key: unexpected foreign key(s) "
            f"reference noo_users/noo_orgs — {unknown}. Another migration "
            "added them after this one was written. Add them to _USERNAME_FKS "
            "(so they are dropped and recreated around the flip) and re-run. "
            "Dropping them blindly would silently lose referential integrity."
        )


def _pk_column(conn, table: str) -> str | None:
    """Name of the single column the table's primary key covers, if any."""
    row = conn.execute(
        sa.text(
            # to_regclass(:t), NOT :t::regclass — the `::` cast collides with
            # SQLAlchemy's `:param` syntax, so the bind is never substituted
            # and Postgres receives a literal ":t::regclass" (syntax error at
            # or near ":"). to_regclass also returns NULL for a missing table
            # instead of raising, which is the behaviour wanted here.
            "SELECT a.attname FROM pg_index i "
            "JOIN pg_attribute a ON a.attrelid = i.indrelid "
            " AND a.attnum = ANY(i.indkey) "
            "WHERE i.indrelid = to_regclass(:t) AND i.indisprimary"
        ),
        {"t": table},
    ).fetchone()
    return row[0] if row else None


def upgrade() -> None:
    conn = op.get_bind()
    _fail_on_unknown_fks(conn)

    # On a FRESH database `create_all()` builds these tables from the models,
    # which already declare the UUID primary keys — so the flip is already
    # done and re-running it would fail on DROP CONSTRAINT. Skip per table
    # rather than assume which path built the schema. Same class of problem
    # `tests/test_migrations_guard_create_all.py` pins for ADD COLUMN.
    users_needs_flip = _pk_column(conn, "noo_users") == "username"
    orgs_needs_flip = _pk_column(conn, "noo_orgs") == "id"
    if not users_needs_flip and not orgs_needs_flip:
        print("[044] primary keys already on the UUIDs — nothing to flip")
        return

    # Postgres has no ADD CONSTRAINT IF NOT EXISTS, hence the DO blocks: a
    # real UNIQUE constraint is required because an FK can only reference a
    # PK or a UNIQUE constraint, and after the flip the PK no longer covers
    # username. Phase A's unique INDEX is not sufficient for that.
    for table, constraint, column in (
        ("noo_users", "uq_noo_users_username", "username"),
        ("noo_orgs", "uq_noo_orgs_slug", "id"),
    ):
        op.execute(
            f"DO $$ BEGIN "
            f"  IF NOT EXISTS (SELECT 1 FROM pg_constraint "
            f"                 WHERE conname = '{constraint}') THEN "
            f"    ALTER TABLE {table} ADD CONSTRAINT {constraint} "
            f"      UNIQUE ({column}); "
            f"  END IF; "
            f"END $$;"
        )

    for table, name, _ in _USERNAME_FKS:
        op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name}")

    if users_needs_flip:
        op.execute("ALTER TABLE noo_users DROP CONSTRAINT noo_users_pkey")
        op.execute("ALTER TABLE noo_users ADD PRIMARY KEY (user_uuid)")
    if orgs_needs_flip:
        op.execute("ALTER TABLE noo_orgs DROP CONSTRAINT noo_orgs_pkey")
        op.execute("ALTER TABLE noo_orgs ADD PRIMARY KEY (org_uuid)")

    for table, name, definition in _USERNAME_FKS:
        op.execute(f"ALTER TABLE {table} ADD CONSTRAINT {name} {definition}")


def downgrade() -> None:
    for table, name, _ in _USERNAME_FKS:
        op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {name}")

    op.execute("ALTER TABLE noo_orgs DROP CONSTRAINT noo_orgs_pkey")
    op.execute("ALTER TABLE noo_orgs ADD PRIMARY KEY (id)")
    op.execute("ALTER TABLE noo_users DROP CONSTRAINT noo_users_pkey")
    op.execute("ALTER TABLE noo_users ADD PRIMARY KEY (username)")

    op.execute("ALTER TABLE noo_orgs DROP CONSTRAINT IF EXISTS uq_noo_orgs_slug")
    op.execute(
        "ALTER TABLE noo_users DROP CONSTRAINT IF EXISTS uq_noo_users_username"
    )

    for table, name, definition in _USERNAME_FKS:
        op.execute(f"ALTER TABLE {table} ADD CONSTRAINT {name} {definition}")
