# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Let noo_app create audit partitions without CREATE on the schema.

Revision ID: 036_audit_partition_definer
Revises: 035_job_runs_history
Create Date: 2026-07-31

`gateway-rust/src/audit_partition.rs` creates the next monthly partition of
``noo_security_audit`` at runtime with raw DDL. That works today only because
the gateway connects as ``noo``, a superuser — the very thing migration 033
exists to stop.

Granting ``CREATE ON SCHEMA public`` to ``noo_app`` would unblock it and defeat
the point: the role could then create *any* table. Instead this adds a
SECURITY DEFINER function that runs as its owner (``noo``) and can create
exactly one shape of object.

Hardening, because SECURITY DEFINER is a privilege-escalation primitive if
written carelessly:

- ``SET search_path`` is pinned. Without it a caller can prepend a schema and
  hijack any unqualified name the body resolves.
- The partition NAME is constructed inside the function from integer year/month
  arguments. The caller never supplies an identifier, so there is nothing to
  inject and no way to point it at another parent table.
- Arguments are range-checked; a bad month raises rather than building a
  nonsense partition.
- EXECUTE is revoked from PUBLIC and granted only to ``noo_app``.

The function is idempotent (``IF NOT EXISTS``) and returns whether it created
anything, matching what the Rust caller already reports.

AMENDED 2026-08-05 (mesh-schema move): the function body is now
LAYOUT-AGNOSTIC — unqualified references, pinned path
pg_catalog, mesh, public. On the legacy layout `mesh` does not exist and
Postgres skips it, so behavior is unchanged there; on the new layout the
parent table lives in schema mesh and resolves. Installs that already ran
036 keep their old function and keep working; only fresh replays read this
text, and a fresh replay emitting a different body than the sqlx baseline
is exactly the divergence the equivalence gate flagged.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "036_audit_partition_definer"
down_revision: Union[str, None] = "035_job_runs_history"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

APP_ROLE = "noo_app"

_FUNCTION = """
CREATE OR REPLACE FUNCTION public.noo_ensure_audit_partition(p_year int, p_month int)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = mesh, public, pg_catalog
AS $fn$
DECLARE
    v_name  text;
    v_start date;
    v_end   date;
BEGIN
    IF p_year < 2000 OR p_year > 2999 THEN
        RAISE EXCEPTION 'year out of range: %', p_year;
    END IF;
    IF p_month < 1 OR p_month > 12 THEN
        RAISE EXCEPTION 'month out of range: %', p_month;
    END IF;

    -- Name is BUILT here, never passed in: the caller cannot name an
    -- arbitrary table or re-parent the partition.
    v_name  := format('noo_security_audit_%s_%s',
                      to_char(p_year, 'FM0000'), to_char(p_month, 'FM00'));
    v_start := make_date(p_year, p_month, 1);
    v_end   := (v_start + interval '1 month')::date;

    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = v_name) THEN
        RETURN false;
    END IF;

    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF noo_security_audit '
        'FOR VALUES FROM (%L) TO (%L)', v_name, v_start, v_end);
    RETURN true;
END;
$fn$;
"""


def upgrade() -> None:
    op.execute(_FUNCTION)
    op.execute(
        "REVOKE ALL ON FUNCTION public.noo_ensure_audit_partition(int, int) FROM PUBLIC"
    )
    op.execute(
        f"GRANT EXECUTE ON FUNCTION public.noo_ensure_audit_partition(int, int) "
        f"TO {APP_ROLE}"
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS public.noo_ensure_audit_partition(int, int)")
