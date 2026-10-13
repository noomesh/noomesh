# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Add a serving `role` to backend placements.

Backend candidates for chat were selected purely by CONTAINER TYPE
(`inference_types = ["vllm", "vllm-secondary", "ollama", "llamacpp"]` in
`coordinator/backend.rs`). Nothing recorded what the model behind that
container is actually FOR, so an ollama serving an embedding model was
offered as a chat backend and the coordinator dutifully routed chat at it:

    the backend answered HTTP 400 ("<model> does not support chat"), every
    candidate failed, and the request ended in llm_all_backends_failed.

That was a hard failure, not a fallback, and on a background task it was
completely silent. It will recur for every embedding backend the harrier
migration brings online, so role belongs in the desired state rather than
being inferred from model names.

`role` is one of: `chat` (default, existing behaviour), `embed`, `rerank`.
Defaulting to `chat` keeps every existing placement routable exactly as it
is today — only backends explicitly marked otherwise drop out of the chat
candidate pool.

Revision ID: 032_backend_placement_role
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "032_backend_placement_role"
down_revision: Union[str, Sequence[str], None] = "031_security_posture"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "noo_backend_placements",
        sa.Column(
            "role",
            sa.Text(),
            nullable=False,
            server_default="chat",
        ),
    )
    # Backfill known non-chat backends. The `embedding` and `reranker`
    # container types are unambiguous by name; ollama is NOT — it is a
    # general runtime, which is exactly why harrier slipped through. Those
    # are set explicitly by the operator via `noo cluster place --role`.
    op.execute(
        "UPDATE noo_backend_placements SET role = 'embed' WHERE backend = 'embedding'"
    )
    op.execute(
        "UPDATE noo_backend_placements SET role = 'rerank' WHERE backend = 'reranker'"
    )
    op.create_index(
        "ix_backend_placements_role",
        "noo_backend_placements",
        ["role"],
    )


def downgrade() -> None:
    op.drop_index("ix_backend_placements_role", table_name="noo_backend_placements")
    op.drop_column("noo_backend_placements", "role")
