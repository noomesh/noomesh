# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Carry user_uuid into the mesh-owned user-scoped tables. an earlier change.

Phase A (``042_identity_uuids``) minted ``noo_users.user_uuid``. This revision
carries it into the tables that reference a user, so those references survive a
rename — today they hold the username, and renaming an account orphans every
one of them.

**Mesh-owned tables only.** ``noo_conversations``, ``edges``, ``entities`` and
``noo_temporal_edges`` are owned by the trellion env (``001_memory_baseline`` /
``008_org_columns``) and need the same column added *there*, in a matching
trellion revision. Adding them from here would be exactly the cross-env reach
an earlier change exists to remove — mesh ``002_pro_tables`` already does that to
``noo_temporal_edges`` and it is why ``wait_for_memory_head()`` exists.

## Nullable, deliberately

A user-scoped table is not a user-only table. A `noo_conversations.user_id` holds more than usernames. Besides real users
it carries system principals (`system:heartbeat`, `heartbeat:<task>`,
`noo-evolve`, `google_chat:spaces/...`) and NULL.

Only a real user maps to a person. NOT NULL here would make org- and
system-scoped rows unwritable, which is the shape of the 2026-07-10
``noo_users NOT NULL`` incident.

## NULL is load-bearing for erasure

``session.rs`` documents the rule: NULL marks a row as shared/non-personal, and
a placeholder "would make system data look like someone's personal data".
RTBF deletes with ``user_id = $1`` across conversations, edges, entities and
temporal_edges, so attributing system rows to a person means a later erasure
deletes cluster reports and graph-signal runs as if they were personal data.

That is why heartbeat-generated rows get NULL here even though
``noo_heartbeat_tasks.created_by`` legitimately names the user who configured
the task. The task has an owner; its output does not become that person's
personal data. Confirmed with the operator 2026-08-02.

No foreign key, by design .

Revision ID: 043_domain_user_uuid
Revises: 042_identity_uuids
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "043_domain_user_uuid"
down_revision: Union[str, None] = "042_identity_uuids"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# (table, column holding the username today)
#
# Tables whose user_id may be entirely NULL (noo_prompt_skill_stats,
# noo_service_keys) backfill nothing; that is expected, not a miss. The
# upgrade prints the attributed row count per table so a reader can tell
# "backfilled nothing" from "matched nothing".
_TABLES: list[tuple[str, str]] = [
    ("noo_feedback_conversations", "user_id"),
    ("noo_feedback_ratings", "user_id"),
    ("noo_kb_role_grants", "username"),
    ("noo_prompt_skill_stats", "user_id"),
    ("noo_refresh_tokens", "user_id"),
    ("noo_service_keys", "user_id"),
    ("noo_user_channel_links", "username"),
]


def upgrade() -> None:
    conn = op.get_bind()
    for table, name_col in _TABLES:
        # IF NOT EXISTS: several of these are model-backed, so on a fresh
        # database create_all() builds them before this runs. Same reason
        # 042 and 027_org_boundary use raw SQL here.
        op.execute(
            f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS user_uuid uuid"
        )
        # Partial index: the null rows are org/system and are never looked up
        # by user, so indexing them costs space for nothing.
        op.execute(
            f"CREATE INDEX IF NOT EXISTS ix_{table}_user_uuid "
            f"ON {table} (user_uuid) WHERE user_uuid IS NOT NULL"
        )
        result = conn.execute(
            sa.text(
                f"UPDATE {table} t SET user_uuid = u.user_uuid "
                f"FROM noo_users u WHERE t.{name_col} = u.username "
                f"AND t.user_uuid IS NULL"
            )
        )
        # Printed, not asserted. A low match rate is EXPECTED here — most rows
        # are org- or system-scoped — so a "0 rows backfilled" assertion would
        # be wrong and a "all rows backfilled" one would be wronger.
        print(f"[043] {table}: attributed {result.rowcount} row(s) to a user")


def downgrade() -> None:
    for table, _ in _TABLES:
        op.execute(f"DROP INDEX IF EXISTS ix_{table}_user_uuid")
        op.execute(f"ALTER TABLE {table} DROP COLUMN IF EXISTS user_uuid")
