# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Channel-to-canonical user resolution.

Thin DB helpers around ``noo_user_channel_links``. Intentionally simple —
the table is a map, not a graph, so operations are O(1) lookups.
"""
from __future__ import annotations

from typing import Optional

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

logger = structlog.get_logger(__name__)


async def resolve_user(
    engine: AsyncEngine,
    channel: str,
    channel_user_id: str,
) -> Optional[str]:
    """Look up the canonical username for a (channel, channel_user_id).

    Returns None if no link exists — caller decides whether to fall back
    to ``channel_user_id`` verbatim or prompt for linkage.
    """
    if not channel or not channel_user_id:
        return None
    async with engine.connect() as conn:
        row = await conn.execute(
            text(
                "SELECT username FROM noo_user_channel_links "
                "WHERE channel = :c AND channel_user_id = :u"
            ),
            {"c": channel, "u": channel_user_id},
        )
        value = row.scalar()
        return str(value) if value else None


async def link_user(
    engine: AsyncEngine,
    channel: str,
    channel_user_id: str,
    username: str,
    display_name: Optional[str] = None,
) -> None:
    """Create (or update) a (channel, channel_user_id) → username link.

    Idempotent: calling twice with same args is a no-op-equivalent.
    """
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO noo_user_channel_links "
                "(channel, channel_user_id, username, display_name) "
                "VALUES (:c, :u, :n, :d) "
                "ON CONFLICT (channel, channel_user_id) DO UPDATE "
                "SET username = EXCLUDED.username, "
                "    display_name = EXCLUDED.display_name"
            ),
            {"c": channel, "u": channel_user_id, "n": username, "d": display_name},
        )
    logger.info(
        "identity.link_created",
        channel=channel,
        channel_user_id=channel_user_id,
        username=username,
    )


async def unlink_user(
    engine: AsyncEngine,
    channel: str,
    channel_user_id: str,
) -> bool:
    """Remove a (channel, channel_user_id) link. Returns True if a row was
    removed, False if none existed."""
    async with engine.begin() as conn:
        result = await conn.execute(
            text(
                "DELETE FROM noo_user_channel_links "
                "WHERE channel = :c AND channel_user_id = :u"
            ),
            {"c": channel, "u": channel_user_id},
        )
        return bool(result.rowcount)


async def list_links_for(
    engine: AsyncEngine,
    username: str,
) -> list[dict]:
    """All (channel, channel_user_id) links for a given canonical username."""
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT channel, channel_user_id, display_name, linked_at "
                "FROM noo_user_channel_links "
                "WHERE username = :n "
                "ORDER BY linked_at DESC"
            ),
            {"n": username},
        )
        return [dict(r) for r in rows.mappings()]
