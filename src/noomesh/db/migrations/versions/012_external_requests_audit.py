# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Per-request audit/usage log for the external inference boundary.

Revision ID: 012_external_requests_audit
Revises: 011_service_keys
Create Date: 2026-06-14

Today the gateway's inference proxy writes nothing to Postgres — external
``/api/external/*`` traffic is invisible except Loki logs, with no per-call
attribution or usage accounting. This table closes that gap: a middleware
scoped to ``/api/external/*`` (Rust) writes one row per call, attributed to
the named consumer resolved from ``noo_service_keys``. This is the
"do we see external requests" view, surfaced via ``GET /api/external/usage``
— distinct from ``/api/jobs`` (which is Redis-backed *background tasks*,
not inference).

Schema (envelope + usage):
  - ``id`` UUID PK
  - ``ts`` timestamptz default NOW()
  - ``consumer`` text — resolved service name (or ``"legacy"`` for the env key)
  - ``endpoint`` text — e.g. ``/api/external/embeddings``
  - ``kind`` text nullable — chat | embedding | rerank | classify
  - ``model`` text nullable — requested/resolved model
  - ``backend`` text nullable — backend the request was served by (vllm/tei/…)
  - ``units`` jsonb nullable — usage: ``{prompt_tokens,completion_tokens,
    total_tokens}`` (chat), ``{inputs,tokens}`` (embeddings),
    ``{documents}`` (rerank). Null when not cheaply available (e.g. streamed chat)
  - ``status_code`` int — HTTP status returned to the consumer
  - ``latency_ms`` int nullable — gateway-observed wall time
  - ``trace_id`` text nullable — caller's ``options.trace_id`` or a generated id
  - ``error`` text nullable — short error summary on non-2xx

Indexes:
  - ``consumer, ts`` (per-consumer usage / billing queries)
  - ``ts`` (time-range scans + retention pruning)

Volume note: this can grow quickly. If it does, convert to a
RANGE(ts)-partitioned table following the ``noo_security_audit`` pattern
(see migration 010) and prune/archive old partitions — deferred until needed.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "012_external_requests_audit"
down_revision: Union[str, None] = "011_service_keys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # `001_baseline` runs `Base.metadata.create_all()` against the CURRENT
    # models, which declare this table, so on a FRESH database it already
    # exists by the time this migration runs and a plain create_table fails
    # with DuplicateTable — the chain could not be replayed from empty.
    # Guard rather than drop the definition: the create_table below stays the
    # authoritative description of the schema AT THIS REVISION, which is what a
    # reader walking the history needs.
    from sqlalchemy import inspect as _sa_inspect
    if "noo_external_requests" in _sa_inspect(op.get_bind()).get_table_names():
        return

    op.create_table(
        "noo_external_requests",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=False), primary_key=True),
        sa.Column(
            "ts",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("consumer", sa.Text(), nullable=False),
        sa.Column("endpoint", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=True),
        sa.Column("model", sa.Text(), nullable=True),
        sa.Column("backend", sa.Text(), nullable=True),
        sa.Column("units", sa.dialects.postgresql.JSONB(), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("trace_id", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_noo_external_requests_consumer_ts",
        "noo_external_requests",
        ["consumer", "ts"],
    )
    op.create_index(
        "ix_noo_external_requests_ts",
        "noo_external_requests",
        ["ts"],
    )


def downgrade() -> None:
    op.drop_index("ix_noo_external_requests_ts", table_name="noo_external_requests")
    op.drop_index(
        "ix_noo_external_requests_consumer_ts", table_name="noo_external_requests"
    )
    op.drop_table("noo_external_requests")
