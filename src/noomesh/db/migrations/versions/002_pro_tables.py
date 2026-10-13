# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""No-op chain link — these tables left the mesh chain.

Revision ID: 002_pro_tables
Revises: 001_baseline
Create Date: 2026-04-22

This revision once created tables that now belong to an add-on. The add-on's
OWN Alembic chain is the sole schema authority for them, so this revision is
a no-op.

The revision id is load-bearing (003 revises it; deployed alembic_version
tables reference the chain) — this file must stay, as a pure link.
"""
from typing import Sequence, Union

revision: str = "002_pro_tables"
down_revision: Union[str, None] = "001_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    # Nothing to undo here; dropping evolve's tables is evolve's chain's
    # business (and was already unsafe to do from mesh — another system's
    # schema).
    pass
