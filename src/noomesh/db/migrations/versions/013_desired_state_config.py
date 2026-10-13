# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Desired-state node & backend configuration.

Postgres becomes the authoritative *desired* state for node data roots and
backend placements; NATS KV stays the *observed* state; node-agents pull
and reconcile. Motivated by the 2026-07-03 incident chain — four outages
caused by desired config living in scattered per-node .env files and image
ENVs with nothing to reconcile against.


Creates empty tables; seed your cluster's desired state afterwards with
`noo cluster seed` (reads the gitignored config/cluster-seed.yaml) or
per-node via `noo cluster set-config` / `noo cluster place`.

Revision ID: 013_desired_state_config
Revises: 012_external_requests_audit
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "013_desired_state_config"
down_revision: Union[str, None] = "012_external_requests_audit"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "noo_node_config",
        sa.Column("node_id", sa.Text(), primary_key=True),
        sa.Column("ip_address", sa.Text(), nullable=True),
        sa.Column("ssh_user", sa.Text(), nullable=True),
        sa.Column("tier", sa.Integer(), nullable=True),
        sa.Column("data_root", sa.Text(), nullable=True),
        sa.Column("models_dir", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
    )

    op.create_table(
        "noo_backend_placements",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=False),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("node_id", sa.Text(), nullable=False),
        sa.Column("backend", sa.Text(), nullable=False),
        sa.Column("model", sa.Text(), nullable=True),
        sa.Column("image", sa.Text(), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("tls", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column(
            "env",
            sa.dialects.postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "desired_state",
            sa.Text(),
            server_default=sa.text("'running'"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.UniqueConstraint("node_id", "backend", name="uq_placement_node_backend"),
    )
    op.create_index(
        "ix_backend_placements_node", "noo_backend_placements", ["node_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_backend_placements_node", table_name="noo_backend_placements")
    op.drop_table("noo_backend_placements")
    op.drop_table("noo_node_config")
