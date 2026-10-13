# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Convert noo_security_audit to a partitioned table (in place, data-preserving).

Revision ID: 010_partition_security_audit
Revises: 009_activity_proposals
Create Date: 2026-06-11

The ORM model (``db/models.py::SecurityAudit``) declares
``postgresql_partition_by="RANGE (timestamp)"`` with a composite
``(id, timestamp)`` primary key — so *fresh* installs create the table
partitioned. Databases created before that model change have a plain
(unpartitioned) table, and both partition-lifecycle implementations
(``gateway/audit_archive.py`` and the Rust
``audit_partition.rs::ensure_current_and_next`` startup hook) fail every
boot with::

    ERROR: "noo_security_audit" is not partitioned

This migration converts such databases in place:

1. Skip entirely if the table is already partitioned (relkind = 'p') —
   fresh installs are a no-op.
2. Rename the plain table (and its colliding index/constraint names)
   to ``noo_security_audit_unpart``.
3. Recreate ``noo_security_audit`` as ``PARTITION BY RANGE (timestamp)``
   with the model's exact columns + composite PK.
4. Create monthly partitions spanning the existing data's month range
   plus the current and next month (the Rust startup hook maintains
   future months from there).
5. Copy all rows across and drop the old table.

Everything runs inside one plpgsql DO block so the conversion is a
single transaction — either the fully-converted table exists with all
rows, or nothing changed.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "010_partition_security_audit"
down_revision: Union[str, None] = "009_activity_proposals"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


UPGRADE_SQL = r"""
DO $$
DECLARE
    kind        char;
    first_month date;
    last_month  date;
    m           date;
    part_name   text;
BEGIN
    SELECT c.relkind INTO kind
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relname = 'noo_security_audit'
      AND n.nspname = current_schema();

    -- Absent (baseline will create it partitioned) or already partitioned.
    IF kind IS NULL OR kind = 'p' THEN
        RETURN;
    END IF;

    ALTER TABLE noo_security_audit RENAME TO noo_security_audit_unpart;

    -- Index/constraint relation names are schema-global and don't follow
    -- a table rename — move them aside so the new parent can reuse them.
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'noo_security_audit_pkey') THEN
        ALTER INDEX noo_security_audit_pkey RENAME TO noo_security_audit_unpart_pkey;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'ix_noo_security_audit_ts') THEN
        ALTER INDEX ix_noo_security_audit_ts RENAME TO ix_noo_security_audit_unpart_ts;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'ix_noo_security_audit_event_type') THEN
        ALTER INDEX ix_noo_security_audit_event_type RENAME TO ix_noo_security_audit_unpart_et;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'ix_noo_security_audit_severity') THEN
        ALTER INDEX ix_noo_security_audit_severity RENAME TO ix_noo_security_audit_unpart_sev;
    END IF;

    -- Mirror of db/models.py::SecurityAudit (partition key must be part
    -- of the primary key on a partitioned table).
    CREATE TABLE noo_security_audit (
        id          uuid                     NOT NULL,
        "timestamp" timestamptz              NOT NULL DEFAULT NOW(),
        event_type  varchar(64)              NOT NULL,
        severity    varchar(16)              NOT NULL,
        actor       varchar(256)             NOT NULL,
        resource    varchar(512)             NOT NULL,
        outcome     varchar(64)              NOT NULL,
        details     jsonb,
        request_id  varchar(32),
        CONSTRAINT noo_security_audit_pkey PRIMARY KEY (id, "timestamp")
    ) PARTITION BY RANGE ("timestamp");

    CREATE INDEX ix_noo_security_audit_ts         ON noo_security_audit ("timestamp");
    CREATE INDEX ix_noo_security_audit_event_type ON noo_security_audit (event_type);
    CREATE INDEX ix_noo_security_audit_severity   ON noo_security_audit (severity);

    -- Monthly partitions: existing data's range + current + next month.
    SELECT date_trunc('month', COALESCE(min("timestamp"), now()))::date
      INTO first_month
      FROM noo_security_audit_unpart;
    SELECT GREATEST(
               date_trunc('month', COALESCE(max("timestamp"), now())),
               date_trunc('month', now()) + interval '1 month'
           )::date
      INTO last_month
      FROM noo_security_audit_unpart;

    m := first_month;
    WHILE m <= last_month LOOP
        part_name := 'noo_security_audit_' || to_char(m, 'YYYY_MM');
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF noo_security_audit '
            'FOR VALUES FROM (%L) TO (%L)',
            part_name, m, (m + interval '1 month')::date
        );
        m := (m + interval '1 month')::date;
    END LOOP;

    INSERT INTO noo_security_audit
        (id, "timestamp", event_type, severity, actor, resource, outcome,
         details, request_id)
    SELECT id, "timestamp", event_type, severity, actor, resource, outcome,
           details, request_id
    FROM noo_security_audit_unpart;

    DROP TABLE noo_security_audit_unpart;

    RAISE NOTICE 'noo_security_audit converted to partitioned table';
END $$;
"""


DOWNGRADE_SQL = r"""
DO $$
DECLARE
    kind char;
BEGIN
    SELECT c.relkind INTO kind
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relname = 'noo_security_audit'
      AND n.nspname = current_schema();

    -- Only revert a partitioned table back to a plain one.
    IF kind IS NULL OR kind <> 'p' THEN
        RETURN;
    END IF;

    ALTER TABLE noo_security_audit RENAME TO noo_security_audit_part;
    ALTER INDEX noo_security_audit_pkey RENAME TO noo_security_audit_part_pkey;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'ix_noo_security_audit_ts') THEN
        ALTER INDEX ix_noo_security_audit_ts RENAME TO ix_noo_security_audit_part_ts;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'ix_noo_security_audit_event_type') THEN
        ALTER INDEX ix_noo_security_audit_event_type RENAME TO ix_noo_security_audit_part_et;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'ix_noo_security_audit_severity') THEN
        ALTER INDEX ix_noo_security_audit_severity RENAME TO ix_noo_security_audit_part_sev;
    END IF;

    CREATE TABLE noo_security_audit (
        id          uuid         NOT NULL,
        "timestamp" timestamptz  NOT NULL DEFAULT NOW(),
        event_type  varchar(64)  NOT NULL,
        severity    varchar(16)  NOT NULL,
        actor       varchar(256) NOT NULL,
        resource    varchar(512) NOT NULL,
        outcome     varchar(64)  NOT NULL,
        details     jsonb,
        request_id  varchar(32),
        CONSTRAINT noo_security_audit_pkey PRIMARY KEY (id, "timestamp")
    );

    CREATE INDEX ix_noo_security_audit_ts         ON noo_security_audit ("timestamp");
    CREATE INDEX ix_noo_security_audit_event_type ON noo_security_audit (event_type);
    CREATE INDEX ix_noo_security_audit_severity   ON noo_security_audit (severity);

    INSERT INTO noo_security_audit
        (id, "timestamp", event_type, severity, actor, resource, outcome,
         details, request_id)
    SELECT id, "timestamp", event_type, severity, actor, resource, outcome,
           details, request_id
    FROM noo_security_audit_part;

    DROP TABLE noo_security_audit_part;
END $$;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
