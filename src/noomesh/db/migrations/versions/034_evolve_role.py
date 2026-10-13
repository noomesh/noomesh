# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Scoped database role for noo-evolve.

Revision ID: 034_evolve_role
Revises: 033_app_role_split
Create Date: 2026-07-31

noo-evolve connects to the shared Postgres as ``noo`` — superuser, with
``rolbypassrls``, and full access to all 81 tables. It needs five:

    noo_ga_genomes, noo_ga_generations,
    noo_rl_arms, noo_rl_experiences,
    noo_hofstadter_loop_cycles

This creates ``noo_evolve``: LOGIN, NOSUPERUSER, NOBYPASSRLS, owning exactly
those five and holding no privilege on anything else. A new role starts with
no table privileges, so the scoping is by omission — nothing needs revoking.

WHY OWNERSHIP AND NOT JUST DML. The obvious move is to point noo-evolve at
``noo_app`` from 033. It does not work: noo-evolve runs ``create_all()`` on
every startup and, right after it, ``ALTER TABLE ... ADD COLUMN IF NOT EXISTS
persona_id`` on three of these tables. ALTER TABLE requires ownership, which
``noo_app`` does not have. That call is wrapped in try/except, so it would not
crash — it would log ``evolve_tables_bootstrap_failed`` on every boot and
silently stop applying schema changes. Ownership makes the existing bootstrap
work as written.

WHAT THIS DELIBERATELY DOES NOT GRANT. No ``CREATE`` on schema ``public``.
noo-evolve can alter and own its five tables but cannot create new ones, so
``create_all()`` adding a SIXTH table would fail (loudly, in that same
warning). That is the intended pressure: new evolve tables should arrive by
migration, which is the direction agreed for this service, rather than by a
service self-bootstrapping schema at runtime.

MESH KEEPS WORKING. These tables are shared — noo-evolve's ``ga_store``
issues ``UPDATE noo_ga_genomes`` (the in-tree gateway/ga_store.py copy was
removed with the pro extraction) and ``db/models_pro.py`` models all five. The
gateway connects as ``noo`` (superuser), which is unaffected by ownership.
``noo_app`` also retains the DML granted in 033; changing a table's owner does
not revoke existing grants.

The password is read from ``NOO_EVOLVE_DB_PASSWORD``. Like 033, this fails
loudly rather than inventing a default — a predictable password on a login
role is worse than a failed migration.

Roles are CLUSTER-GLOBAL, so this reaches the real ``noo_evolve`` even when
the chain is replayed into a throwaway database. ``NOO_DB_SCHEMA_ONLY=1``
makes an existing role untouchable — see ``db/role_provision.py``.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

from noomesh.db.role_provision import ensure_login_role, role_password


revision: str = "034_evolve_role"
down_revision: Union[str, None] = "033_app_role_split"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

EVOLVE_ROLE = "noo_evolve"

# The complete set. Derived by enumerating __tablename__ across the noo-evolve
# source; its only other reference to a mesh table (`noo_cluster_status`) is
# inside a prompt string, not a query — everything else routes through the
# gateway over HTTP.
EVOLVE_TABLES = (
    "noo_ga_genomes",
    "noo_ga_generations",
    "noo_rl_arms",
    "noo_rl_experiences",
    "noo_hofstadter_loop_cycles",
)


def upgrade() -> None:
    password = role_password(
        "NOO_EVOLVE_DB_PASSWORD",
        "NOO_EVOLVE_DB_PASSWORD is not set. Migration 034 creates the "
        f"{EVOLVE_ROLE!r} login role and will not invent a default "
        "password for it. Set the variable (it belongs in "
        "secrets/env.sops like every other credential) and re-run. It "
        "also needs a passthrough in docker-compose.pro.yml — the "
        "container env is an explicit ${VAR} allowlist.",
    )

    conn = op.get_bind()

    # Creates when absent; an idempotent re-run keeps the password in step with
    # the secret — EXCEPT in schema-only mode, where an existing role belongs
    # to a real cluster and must not be touched.
    ensure_login_role(
        conn,
        EVOLVE_ROLE,
        password,
        attributes="LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS",
    )

    # Reaching its tables at all requires schema usage. This is NOT
    # `GRANT CREATE` — see the module docstring.
    conn.exec_driver_sql(f"GRANT USAGE ON SCHEMA public TO {EVOLVE_ROLE}")

    for table in EVOLVE_TABLES:
        present = conn.exec_driver_sql(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = %(t)s",
            {"t": table},
        ).scalar()
        if not present:
            # Pro tables only exist where the pro overlay has run. Skipping is
            # correct: create_all() will make it, and a later re-run of this
            # migration assigns ownership.
            continue
        conn.exec_driver_sql(f"ALTER TABLE {table} OWNER TO {EVOLVE_ROLE}")

    # Identity columns need their sequences too; ownership of a table does not
    # carry the sequence it defaults from.
    conn.exec_driver_sql(
        f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {EVOLVE_ROLE}"
    )


def downgrade() -> None:
    conn = op.get_bind()
    exists = conn.exec_driver_sql(
        "SELECT 1 FROM pg_roles WHERE rolname = %(r)s", {"r": EVOLVE_ROLE}
    ).scalar()
    if not exists:
        return

    # Hand the tables back before dropping the role — Postgres refuses to drop
    # a role that still owns objects.
    for table in EVOLVE_TABLES:
        present = conn.exec_driver_sql(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = %(t)s",
            {"t": table},
        ).scalar()
        if present:
            conn.exec_driver_sql(f"ALTER TABLE {table} OWNER TO noo")

    conn.exec_driver_sql(f"REVOKE ALL ON SCHEMA public FROM {EVOLVE_ROLE}")
    conn.exec_driver_sql(
        f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {EVOLVE_ROLE}"
    )
    conn.exec_driver_sql(f"DROP ROLE IF EXISTS {EVOLVE_ROLE}")
