# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""An ingest never changes an existing document's audience.

Trellion's ``PageIndexStore.insert_doc`` merges the NEW call's metadata over
the existing row on a content-hash hit ("new keys win"). Since #622 every
ingest carries ``roles``, so Bob uploading content identical to Alice's
``user:alice`` document turned it into ``user:bob``: Alice lost it, Bob gained
it, and nothing recorded the change. Only a retag changes an audience.

So ``roles`` is NOT handed to ``rag.ingest``. :func:`settle_roles` writes it
afterwards, and only onto a row THIS ingest created: ``created_at`` at or
after the database clock taken before the call (:func:`db_clock`), and no
``roles`` on the row yet. A row that already existed is left exactly as it
was.

The window: a new row exists without ``roles`` between ``insert_doc`` and the
write here (the page/chunk/embedding work). A document with no ``roles`` is
readable by admins only, so the window fails closed. If the write fails the
call RAISES; reporting success over an untagged document is the state
the design removed. A dedup hit has no window at all: its row is never
written.

SQL from the worker through the store's engine, because trellion's
``set_doc_roles`` is a retag-shaped call and trellion is a separate repo.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

import structlog

log = structlog.get_logger(__name__)


def has_engine(store: Any) -> bool:
    return getattr(store, "_engine", None) is not None


async def db_clock(store: Any) -> Optional[datetime]:
    """The database's clock; a row created at or after it was created by the
    ingest that took it."""
    from sqlalchemy import text

    try:
        async with store._engine.connect() as conn:
            return (await conn.execute(text("SELECT clock_timestamp()"))).fetchone()[0]
    except Exception as e:  # noqa: BLE001
        log.warning("kb_ingest_roles.clock_failed", error=str(e))
        return None


async def settle_roles(store: Any, doc_id: str, roles: list[str], started: datetime) -> str:
    """Write *roles* onto the row if this ingest created it. Returns
    ``created`` or ``existing`` (a dedup hit: audience untouched)."""
    from sqlalchemy import text

    # ONE conditional statement, not read-then-write: two identical uploads
    # racing each other must not both pass a "no roles yet" check and have
    # the later write replace the earlier one. Exactly one UPDATE can match
    # (the row gains `roles` in the same statement); every other caller sees
    # rowcount 0 and is told the document already existed. Concurrent
    # identical uploads cannot be told apart without trellion reporting
    # which call inserted the row, so the first writer wins; the row is
    # never re-audienced afterwards.
    async with store._engine.connect() as conn:
        res = await conn.execute(
            text(
                "UPDATE docs SET metadata = COALESCE(metadata, '{}'::jsonb) "
                "|| jsonb_build_object('roles', CAST(:roles AS jsonb)) "
                "WHERE doc_id = CAST(:id AS uuid) "
                "AND NOT (COALESCE(metadata, '{}'::jsonb) ? 'roles') "
                "AND created_at >= :started"
            ),
            {"id": str(doc_id), "roles": json.dumps(list(roles)), "started": started},
        )
        await conn.commit()
        if res.rowcount == 1:
            return "created"
        exists = await conn.execute(
            text("SELECT 1 FROM docs WHERE doc_id = CAST(:id AS uuid)"), {"id": str(doc_id)}
        )
        if exists.fetchone() is None:
            raise RuntimeError(f"ingested {doc_id} but cannot read it back to set its audience")
        return "existing"
