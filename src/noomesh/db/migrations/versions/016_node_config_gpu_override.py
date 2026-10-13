# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Operator GPU override on the desired node config.

Revision ID: 016_node_config_gpu_override
Revises: 015_service_key_quota
Create Date: 2026-07-06

Moves the GPU self-description override out of per-node ``.env`` files
(``GPU_MODEL`` / ``VRAM_GB`` env drift) into the DB-backed desired config.
Nodes still auto-detect hardware via nvidia-smi; these columns are the
operator override for nodes where detection fails. The gateway applies the
override where heartbeat capabilities are persisted, and only when BOTH
fields are set — mirroring the node-agent rule that a GPU claim without
VRAM is not advertised.

Set via: ``noo cluster set-config <node> --gpu-model "..." --vram-gb N``
View via: ``noo cluster desired <node>``
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "016_node_config_gpu_override"
down_revision: Union[str, None] = "015_service_key_quota"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("noo_node_config", sa.Column("gpu_model", sa.Text(), nullable=True))
    op.add_column("noo_node_config", sa.Column("vram_gb", sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column("noo_node_config", "vram_gb")
    op.drop_column("noo_node_config", "gpu_model")
