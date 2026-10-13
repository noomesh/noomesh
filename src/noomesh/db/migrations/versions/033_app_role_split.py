# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Create the non-superuser application role (RLS prerequisite).

Revision ID: 033_app_role_split
Revises: 032_backend_placement_role
Create Date: 2026-07-29

The gateway currently connects as ``noo``, which is superuser, has
``rolbypassrls``, and owns every table. Any Row-Level Security policy written
against that role is a no-op three times over — it would appear in
``pg_policies`` and filter nothing. See an earlier change.

This migration creates ``noo_app``: LOGIN, NOSUPERUSER, NOBYPASSRLS, owning
nothing, holding only DML grants. ``noo`` keeps ownership and continues to run
migrations, so DDL authority and application authority are separated.

IMPORTANT — this migration does NOT switch the gateway over. Changing
``DATABASE_URL`` is a deliberate operator step (see the runbook section in
an earlier change), because a gateway started against a role with incomplete grants
fails closed. Creating the role is safe and idempotent; using it is a decision.

The password is read from ``NOO_APP_DB_PASSWORD``. The migration fails loudly
rather than inventing a default — a predictable password on a login role is
worse than a failed migration.

ROLES ARE CLUSTER-GLOBAL. Everything else this chain does is scoped to one
database; ``CREATE ROLE`` is not. A tool that replays the chain into a
throwaway database still reaches the real ``noo_app``, which is how a baseline
build reset the live credential on 2026-08-04. ``NOO_DB_SCHEMA_ONLY=1`` makes
this migration leave an EXISTING role untouched — see ``db/role_provision.py``.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

from noomesh.db.role_provision import ensure_login_role, role_password, schema_only


revision: str = "033_app_role_split"
down_revision: Union[str, None] = "032_backend_placement_role"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "noo_app"
APP_ROLE_ATTRS = "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"


def upgrade() -> None:
    password = role_password(
        "NOO_APP_DB_PASSWORD",
        "NOO_APP_DB_PASSWORD is not set. Migration 033 creates the "
        f"{APP_ROLE!r} login role and will not invent a default password "
        "for it. Set the variable (it belongs in secrets/env.sops like "
        "every other credential) and re-run.",
    )

    conn = op.get_bind()

    # Creates when absent; in schema-only mode an existing role is left exactly
    # as found, password and attributes included.
    created = ensure_login_role(
        conn, APP_ROLE, password, attributes=APP_ROLE_ATTRS
    )

    if not created and not schema_only():
        # Reassert the attributes that make RLS effective, in case the role
        # predates this migration or was altered by hand. Skipped in
        # schema-only mode for the same reason the password is: these are
        # cluster-global writes against somebody else's role.
        conn.exec_driver_sql(
            f"ALTER ROLE {APP_ROLE} NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE"
        )

    # DML only — no ownership, no DDL. Migrations keep running as the owner.
    conn.exec_driver_sql(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}")
    conn.exec_driver_sql(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public "
        f"TO {APP_ROLE}"
    )
    conn.exec_driver_sql(
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE}"
    )
    # Tables created by later migrations must be reachable too, otherwise the
    # gateway breaks the next time anyone adds a table.
    conn.exec_driver_sql(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {APP_ROLE}"
    )
    conn.exec_driver_sql(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        f"GRANT USAGE, SELECT ON SEQUENCES TO {APP_ROLE}"
    )


def downgrade() -> None:
    conn = op.get_bind()
    conn.exec_driver_sql(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        f"REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM {APP_ROLE}"
    )
    conn.exec_driver_sql(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        f"REVOKE USAGE, SELECT ON SEQUENCES FROM {APP_ROLE}"
    )
    conn.exec_driver_sql(
        f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {APP_ROLE}"
    )
    conn.exec_driver_sql(f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {APP_ROLE}")
    conn.exec_driver_sql(f"REVOKE USAGE ON SCHEMA public FROM {APP_ROLE}")
    # The role itself is deliberately NOT dropped: if the gateway is still
    # pointed at it, dropping it takes production down. Removing the role is an
    # operator action once DATABASE_URL no longer references it.
