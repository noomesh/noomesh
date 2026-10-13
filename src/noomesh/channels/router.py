# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""FastAPI router for channel webhook endpoints.

No FastAPI app mounts this router any more (the Python gateway app is
gone; the live HTTP surface is Rust). The module survives because it holds
the ChannelManager singleton (``set_channel_manager``/``_channel_manager``)
that worker_pool injects and ``cluster/autonomy.py`` reads. The inbound
POST webhook handlers were archived in
``legacy/python-channels-reference/router.py`` (2026-08-08 sweep).

Routes still defined (unmounted):
- ``GET  /api/channels/status`` -- channel manager status
- ``GET  /api/channels/whatsapp/webhook`` -- WhatsApp verification challenge
- ``POST /api/channels/test`` -- send a test message through a channel
- ``GET  /api/channels/saved-recipients`` -- list saved channel contacts
- ``POST /api/channels/saved-recipients`` -- add a saved contact
- ``PUT  /api/channels/saved-recipients/{id}`` -- update a saved contact
- ``DELETE /api/channels/saved-recipients/{id}`` -- delete a saved contact
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import structlog
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# ChannelManager singleton (injected at startup from app.py)
# ---------------------------------------------------------------------------

_channel_manager = None


def set_channel_manager(manager) -> None:
    """Called during app startup to inject the ChannelManager instance."""
    global _channel_manager
    _channel_manager = manager


def _get_manager():
    if _channel_manager is None:
        raise HTTPException(503, "Channel manager not initialized")
    return _channel_manager


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/channels", tags=["channels"])


@router.get("/status")
async def channel_status() -> Dict[str, Any]:
    """Return status of all registered channel adapters."""
    mgr = _get_manager()
    return mgr.get_status()


@router.get("/{channel}/recipients")
async def list_recipients(channel: str) -> Dict[str, Any]:
    """List known chat contexts (groups, DMs, spaces) for a channel.

    Returns recipients seen in conversation history — useful for building
    a picker or sending proactive messages.

    Example: ``GET /api/channels/google_chat/recipients``
    """
    mgr = _get_manager()
    if mgr.get_adapter(channel) is None:
        raise HTTPException(404, f"Channel '{channel}' not registered")

    recipients = await mgr.list_known_recipients(channel)
    return {"channel": channel, "recipients": recipients}


# ---------------------------------------------------------------------------
# WhatsApp webhook
# ---------------------------------------------------------------------------

@router.get("/whatsapp/webhook")
async def whatsapp_verify(
    request: Request,
) -> PlainTextResponse:
    """Handle WhatsApp webhook verification challenge (GET)."""
    mgr = _get_manager()
    adapter = mgr.get_adapter("whatsapp")
    if adapter is None:
        raise HTTPException(404, "WhatsApp adapter not registered")

    params = dict(request.query_params)
    challenge = adapter.verify_challenge(params)
    if challenge is None:
        raise HTTPException(403, "Verification failed")

    return PlainTextResponse(challenge)


    return {"status": "ok"}

# ---------------------------------------------------------------------------
# Test endpoint
# ---------------------------------------------------------------------------

class SendMessageRequest(BaseModel):
    channel: str
    recipient: str
    message: str
    thread_id: str | None = None


@router.post("/send")
async def send_message(req: SendMessageRequest) -> Dict[str, Any]:
    """Send a message through a channel adapter.

    For Google Chat, *recipient* is the space name (e.g. ``spaces/AAAAxxxxBBBB``).
    For WhatsApp, *recipient* is the phone number.
    For Telegram, *recipient* is the chat ID.

    Optional *thread_id* keeps the reply in an existing thread (Google Chat).
    """
    mgr = _get_manager()
    adapter = mgr.get_adapter(req.channel)
    if adapter is None:
        raise HTTPException(404, f"Channel '{req.channel}' not registered")

    ok = await mgr.dispatch(
        req.channel, req.recipient, req.message, thread_id=req.thread_id,
    )
    return {"success": ok, "channel": req.channel, "recipient": req.recipient}


class TestMessageRequest(BaseModel):
    channel: str
    recipient: str
    message: str = "Hello from PAI!"


@router.post("/test")
async def test_channel(req: TestMessageRequest) -> Dict[str, Any]:
    """Send a test message through a channel adapter."""
    mgr = _get_manager()
    adapter = mgr.get_adapter(req.channel)
    if adapter is None:
        raise HTTPException(404, f"Channel '{req.channel}' not registered")

    ok = await mgr.dispatch(req.channel, req.recipient, req.message)
    return {"success": ok, "channel": req.channel, "recipient": req.recipient}


# ---------------------------------------------------------------------------
# Read messages
# ---------------------------------------------------------------------------

@router.get("/{channel}/messages")
async def list_messages(
    channel: str,
    recipient: str = Query(..., description="Space/chat ID"),
    limit: int = Query(50, ge=1, le=200),
    since: str = Query(None, description="ISO timestamp — only messages after this time"),
) -> Dict[str, Any]:
    """Read messages from a channel (e.g. Google Chat space).

    Currently supported for: ``google_chat``.

    Example: ``GET /api/channels/google_chat/messages?recipient=spaces/AAAA&limit=20``
    """
    mgr = _get_manager()
    adapter = mgr.get_adapter(channel)
    if adapter is None:
        raise HTTPException(404, f"Channel '{channel}' not registered")

    if getattr(adapter, "list_messages", None) is None:
        raise HTTPException(
            501, f"Channel '{channel}' does not support reading messages"
        )

    filter_str = None
    if since:
        filter_str = f'createTime > "{since}"'

    messages = await adapter.list_messages(
        recipient, max_results=limit, filter_str=filter_str,
    )
    return {"channel": channel, "recipient": recipient, "messages": messages, "count": len(messages)}


# ---------------------------------------------------------------------------
# Saved Recipients CRUD
# ---------------------------------------------------------------------------

def _get_async_session():
    """Create an async session from the shared engine pool."""
    try:
        from sqlalchemy.ext.asyncio import AsyncSession
        from ..db.engine import get_async_engine
        engine = get_async_engine()
        return AsyncSession(engine, expire_on_commit=False)
    except RuntimeError:
        raise HTTPException(503, "Database not initialized")


class SavedRecipientCreate(BaseModel):
    channel: str
    recipient_id: str
    display_name: str
    notes: str = ""
    is_default: bool = False
    metadata: Dict[str, Any] = {}


class SavedRecipientUpdate(BaseModel):
    display_name: Optional[str] = None
    notes: Optional[str] = None
    is_default: Optional[bool] = None
    metadata: Optional[Dict[str, Any]] = None


@router.get("/saved-recipients")
async def list_saved_recipients(
    channel: str = Query(None, description="Filter by channel name"),
) -> Dict[str, Any]:
    """List saved channel contacts."""
    from sqlalchemy import select
    from ..db.models import PaiChannelRecipient

    async with _get_async_session() as session:
        stmt = select(PaiChannelRecipient).order_by(
            PaiChannelRecipient.channel,
            PaiChannelRecipient.display_name,
        )
        if channel:
            stmt = stmt.where(PaiChannelRecipient.channel == channel)

        result = await session.execute(stmt)
        rows = result.scalars().all()

    recipients = [
        {
            "id": r.id,
            "channel": r.channel,
            "recipient_id": r.recipient_id,
            "display_name": r.display_name,
            "notes": r.notes or "",
            "is_default": r.is_default,
            "metadata": r.metadata_ or {},
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        }
        for r in rows
    ]
    return {"recipients": recipients, "count": len(recipients)}


@router.post("/saved-recipients")
async def create_saved_recipient(req: SavedRecipientCreate) -> Dict[str, Any]:
    """Add a new saved channel contact."""
    from sqlalchemy import select
    from ..db.models import PaiChannelRecipient

    async with _get_async_session() as session:
        # Check for duplicate
        existing = await session.execute(
            select(PaiChannelRecipient).where(
                PaiChannelRecipient.channel == req.channel,
                PaiChannelRecipient.recipient_id == req.recipient_id,
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(409, "Recipient already exists for this channel")

        # If setting as default, clear other defaults for this channel
        if req.is_default:
            result = await session.execute(
                select(PaiChannelRecipient).where(
                    PaiChannelRecipient.channel == req.channel,
                    PaiChannelRecipient.is_default.is_(True),
                )
            )
            for row in result.scalars().all():
                row.is_default = False

        recipient = PaiChannelRecipient(
            id=str(uuid.uuid4()),
            channel=req.channel,
            recipient_id=req.recipient_id,
            display_name=req.display_name,
            notes=req.notes,
            is_default=req.is_default,
            metadata_=req.metadata,
        )
        session.add(recipient)
        await session.commit()

        # Persist to settings file (survives DB wipes)
        try:
            from .._providers import default_settings_store
            ss = default_settings_store().store()
            if ss:
                ss.save_channel_recipient({
                    "id": recipient.id,
                    "channel": recipient.channel,
                    "recipient_id": recipient.recipient_id,
                    "display_name": recipient.display_name,
                    "notes": recipient.notes,
                    "is_default": recipient.is_default,
                    "metadata": req.metadata,
                })
        except Exception:
            pass

        return {
            "id": recipient.id,
            "channel": recipient.channel,
            "recipient_id": recipient.recipient_id,
            "display_name": recipient.display_name,
            "notes": recipient.notes,
            "is_default": recipient.is_default,
        }


@router.put("/saved-recipients/{recipient_db_id}")
async def update_saved_recipient(
    recipient_db_id: str,
    req: SavedRecipientUpdate,
) -> Dict[str, Any]:
    """Update a saved channel contact."""
    from sqlalchemy import select
    from ..db.models import PaiChannelRecipient

    async with _get_async_session() as session:
        result = await session.execute(
            select(PaiChannelRecipient).where(
                PaiChannelRecipient.id == recipient_db_id,
            )
        )
        recipient = result.scalar_one_or_none()
        if not recipient:
            raise HTTPException(404, "Saved recipient not found")

        if req.display_name is not None:
            recipient.display_name = req.display_name
        if req.notes is not None:
            recipient.notes = req.notes
        if req.is_default is not None:
            # Clear other defaults if setting this one
            if req.is_default:
                others = await session.execute(
                    select(PaiChannelRecipient).where(
                        PaiChannelRecipient.channel == recipient.channel,
                        PaiChannelRecipient.is_default.is_(True),
                        PaiChannelRecipient.id != recipient_db_id,
                    )
                )
                for row in others.scalars().all():
                    row.is_default = False
            recipient.is_default = req.is_default
        if req.metadata is not None:
            recipient.metadata_ = req.metadata

        recipient.updated_at = datetime.now(timezone.utc)
        await session.commit()

        # Persist to settings file (survives DB wipes)
        try:
            from .._providers import default_settings_store
            ss = default_settings_store().store()
            if ss:
                ss.save_channel_recipient({
                    "id": recipient.id,
                    "channel": recipient.channel,
                    "recipient_id": recipient.recipient_id,
                    "display_name": recipient.display_name,
                    "notes": recipient.notes or "",
                    "is_default": recipient.is_default,
                    "metadata": recipient.metadata_ or {},
                })
        except Exception:
            pass

        return {
            "id": recipient.id,
            "channel": recipient.channel,
            "recipient_id": recipient.recipient_id,
            "display_name": recipient.display_name,
            "notes": recipient.notes or "",
            "is_default": recipient.is_default,
        }


@router.delete("/saved-recipients/{recipient_db_id}")
async def delete_saved_recipient(recipient_db_id: str) -> Dict[str, Any]:
    """Delete a saved channel contact."""
    from sqlalchemy import select
    from ..db.models import PaiChannelRecipient

    async with _get_async_session() as session:
        result = await session.execute(
            select(PaiChannelRecipient).where(
                PaiChannelRecipient.id == recipient_db_id,
            )
        )
        recipient = result.scalar_one_or_none()
        if not recipient:
            raise HTTPException(404, "Saved recipient not found")

        channel = recipient.channel
        recipient_id = recipient.recipient_id
        await session.delete(recipient)
        await session.commit()

    # Remove from settings file (survives DB wipes)
    try:
        from .._providers import default_settings_store
        ss = default_settings_store().store()
        if ss:
            ss.remove_channel_recipient(channel, recipient_id)
    except Exception:
        pass

    return {"deleted": True, "id": recipient_db_id}
