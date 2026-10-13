# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Named service keys for the external inference boundary (/api/external/*).

Revision ID: 011_service_keys
Revises: 010_partition_security_audit
Create Date: 2026-06-14

Replaces the single anonymous ``NOO_SERVICE_API_KEY`` env credential with
per-consumer named keys so external systems (noo-trading, noo-trellion, …)
that call the gateway's ``/api/external/*`` inference surface can be
attributed and audited. The Rust gateway auth layer hashes the presented
bearer, looks up an ``active`` row here, and resolves the caller's
``consumer`` + ``scopes`` (which it stamps onto every ``noo_external_requests``
audit row). Issuance is via ``noo security service-key`` (Python CLI);
enforcement is in Rust.

Stores ``sha256(key)`` — never the raw key (mirrors ``noo_refresh_tokens``).

Schema:
  - ``id`` UUID PK
  - ``consumer`` text — service name, e.g. ``noo-trading``
  - ``key_hash`` text — sha256 hex of the raw service key (unique)
  - ``scopes`` jsonb — allowed operations; default all four. A key lacking
    e.g. ``rerank`` → 403 on ``/api/external/rerank`` and ``kind:"rerank"``
  - ``active`` bool — false = revoked (Rust picks it up on cache refresh)
  - ``note`` text nullable — free-form ("issued for trading memory v1")
  - ``created_at`` timestamptz default NOW()
  - ``last_used_at`` timestamptz nullable — best-effort, set on use

Indexes:
  - ``key_hash`` (unique, the auth lookup)
  - ``consumer`` (list / "show this consumer's keys")

Back-compat (historical): the env ``NOO_SERVICE_API_KEY`` kept working as a
bootstrap key attributed to consumer ``"legacy"`` until a real named key was
issued. noo-trading got one on 2026-06-14; the env key was removed from auth
and compose on 2026-08-03, so ``"legacy"`` can no longer appear in new
``noo_external_requests`` rows (historical rows are left as they are).
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "011_service_keys"
down_revision: Union[str, None] = "010_partition_security_audit"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_DEFAULT_SCOPES = "'[\"chat\", \"embeddings\", \"rerank\", \"classify\"]'::jsonb"


def upgrade() -> None:
    # `001_baseline` runs `Base.metadata.create_all()` against the CURRENT
    # models, which declare this table, so on a FRESH database it already
    # exists by the time this migration runs and a plain create_table fails
    # with DuplicateTable — the chain could not be replayed from empty.
    # Guard rather than drop the definition: the create_table below stays the
    # authoritative description of the schema AT THIS REVISION, which is what a
    # reader walking the history needs.
    from sqlalchemy import inspect as _sa_inspect
    if "noo_service_keys" in _sa_inspect(op.get_bind()).get_table_names():
        return

    op.create_table(
        "noo_service_keys",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column("consumer", sa.Text(), nullable=False),
        sa.Column("key_hash", sa.Text(), nullable=False),
        sa.Column(
            "scopes",
            sa.dialects.postgresql.JSONB(),
            server_default=sa.text(_DEFAULT_SCOPES),
            nullable=False,
        ),
        sa.Column(
            "active",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("last_used_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.create_index(
        "uq_noo_service_keys_key_hash",
        "noo_service_keys",
        ["key_hash"],
        unique=True,
    )
    op.create_index(
        "ix_noo_service_keys_consumer",
        "noo_service_keys",
        ["consumer"],
    )


def downgrade() -> None:
    op.drop_index("ix_noo_service_keys_consumer", table_name="noo_service_keys")
    op.drop_index("uq_noo_service_keys_key_hash", table_name="noo_service_keys")
    op.drop_table("noo_service_keys")
