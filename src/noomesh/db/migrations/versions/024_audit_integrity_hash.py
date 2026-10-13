# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tamper-evidence columns for the security audit log.

Revision ID: 024_audit_integrity_hash
Revises: 023_approval_requests
Create Date: 2026-07-12

`noo_security_audit` had no integrity protection — the app role that inserts
rows can also UPDATE/DELETE them (or a bug/SQL-injection could), so the trail
was not trustworthy. This adds a per-row keyed hash (`entry_hash`) computed by
BOTH writers (Rust gateway `audit_event`/`audit_auth` and Python `audit_log`)
over the row's content with a dedicated HMAC key (`NOO_AUDIT_HMAC_KEY`). Any
in-place modification of a row is then detectable by recomputation
(`audit_log.verify_audit_integrity` / `noo security audit-verify`), even by an
actor with SQL access but not the HMAC key.

`prev_hash` is reserved for the follow-on hash-CHAIN (deletion/reorder
detection), which requires a single sealing writer or a periodic checkpoint —
tracked separately. Prevention (INSERT-only role) also remains a follow-on: it
needs the audit table owned by a separate role from the app + a distinct
lifecycle role for partition management (see audit_archive.py). DDL only.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op


revision: str = "024_audit_integrity_hash"
down_revision: Union[str, None] = "023_approval_requests"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ADD COLUMN on the partitioned parent cascades to all partitions.
    op.execute("ALTER TABLE noo_security_audit ADD COLUMN IF NOT EXISTS entry_hash text")
    op.execute("ALTER TABLE noo_security_audit ADD COLUMN IF NOT EXISTS prev_hash text")


def downgrade() -> None:
    op.execute("ALTER TABLE noo_security_audit DROP COLUMN IF EXISTS prev_hash")
    op.execute("ALTER TABLE noo_security_audit DROP COLUMN IF EXISTS entry_hash")
