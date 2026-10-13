# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Channel messaging tools — send, list, recipients, read."""
from __future__ import annotations

from typing import Any, ClassVar, List, Optional

from pydantic import Field

from ..tool_models import HttpMethod, RiskLevel, ToolDef, register


@register
class PaiChannelSend(ToolDef):
    """Send a message through an external channel (Google Chat, Telegram, WhatsApp).
    Requires the channel adapter to be configured and connected."""

    name: ClassVar[str] = "noo_channel_send"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/channels/send"
    tags: ClassVar[List[str]] = ["channels", "messaging"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    channel: str = Field(description="Channel adapter name: google_chat, telegram, whatsapp")
    recipient: str = Field(description="Recipient identifier (chat ID, phone number, etc.)")
    message: str = Field(description="Message text to send")
    thread_id: Optional[str] = Field(default=None, description="Thread/topic ID for threaded replies")


@register
class PaiChannelList(ToolDef):
    """List configured channel adapters and their connection status."""

    name: ClassVar[str] = "noo_channel_list"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/channels/status"
    tags: ClassVar[List[str]] = ["channels", "status"]

    def format_response(self, data: Any) -> str:
        if not isinstance(data, (dict, list)):
            return str(data)
        channels = data if isinstance(data, list) else data.get("channels", [])
        if not channels:
            return "No channel adapters configured."
        lines = [f"Channel adapters: {len(channels)}\n"]
        for ch in channels:
            name = ch.get("name", ch.get("channel", "?"))
            status = ch.get("status", "unknown")
            lines.append(f"  {name}: {status}")
        return "\n".join(lines)


@register
class PaiChannelListRecipients(ToolDef):
    """List known recipients for a specific channel adapter."""

    name: ClassVar[str] = "noo_channel_list_recipients"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/channels/{channel}/recipients"
    tags: ClassVar[List[str]] = ["channels"]

    channel: str = Field(description="Channel adapter name: google_chat, telegram, whatsapp")


@register
class PaiChannelReadMessages(ToolDef):
    """Read recent messages from a channel, optionally filtered by recipient."""

    name: ClassVar[str] = "noo_channel_read_messages"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/channels/{channel}/messages"
    tags: ClassVar[List[str]] = ["channels", "messaging"]

    channel: str = Field(description="Channel adapter name: google_chat, telegram, whatsapp")
    recipient: Optional[str] = Field(default=None, description="Filter by recipient identifier")
    limit: Optional[int] = Field(default=None, description="Maximum number of messages to return")
    since: Optional[str] = Field(default=None, description="ISO timestamp — only return messages after this time")
