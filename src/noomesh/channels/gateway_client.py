# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Outbound channel sends via the Rust gateway (port-lane item 8).

`GatewayChannelClient` replaces the in-process ChannelManager + adapters
for every outbound consumer left in trellion (proactive loop, coding_tool
notifications, autonomy watched-folder notices, exec-approval pings). It
speaks the same small surface those consumers used — ``dispatch``,
``list_channels``, ``resolve_recipient``, ``get_adapter`` — but the send
itself is one authenticated POST to the gateway's ``/api/channels/send``,
where the single Rust implementation of every channel API lives.

Why HTTP and not the old adapters: the Python adapters stopped receiving
inbound traffic when channels moved to Rust, so keeping a
second outbound implementation alive meant two copies of every channel's
auth + formatting that could drift (and did — the daily-digest 401 saga).

Auth: this container's OWN service key (``NOO_GATEWAY_KEY``), through the
one door, ``cluster_auth.internal_gateway_headers``. No shared-secret HMAC:
the gateway refuses the controller secret from every caller.
The 2026-08-09 exec-approval saga proved mTLS-only loopbacks 401 on this
route — the bearer is not optional.
"""

from __future__ import annotations

import os
from typing import Any, List, Optional

import httpx
import structlog

from ..secret_env import secret

logger = structlog.get_logger(__name__)

# Mirror of gateway-rust routes/communication.rs CHANNEL_ENV_KEYS: a channel
# counts as configured when any of its credential env vars is non-empty.
# Trellion receives the same channel env vars the adapters used, so local
# detection matches what the gateway will accept.
CHANNEL_ENV_KEYS: dict[str, tuple[str, ...]] = {
    "whatsapp": ("WHATSAPP_TOKEN", "WHATSAPP_PHONE_ID"),
    "telegram": ("TELEGRAM_BOT_TOKEN",),
    "google_chat": (
        "GOOGLE_CHAT_CREDENTIALS_JSON",
        "GOOGLE_CHAT_CREDENTIALS",
        "GOOGLE_CHAT_BEARER_TOKEN",
    ),
}


def _configured(keys: tuple[str, ...]) -> bool:
    """Any of *keys* non-empty — read through ``secret_env``, because the
    credentials arrive as ``/run/secrets`` files (``<NAME>_FILE``) and a
    plain ``os.getenv`` would call every configured channel unconfigured.
    ``WHATSAPP_PHONE_ID`` / ``GOOGLE_CHAT_CREDENTIALS`` are not secrets; the
    same reader answers them from the plain env."""
    return any(secret(k) for k in keys)


def _gateway_url() -> str:
    return (os.getenv("NOO_GATEWAY_URL") or "https://gateway:8080").rstrip("/")


def _auth_headers() -> dict[str, str]:
    """The one door. This used to mint its own cluster token.

    Two things were wrong with that beyond the duplication. It read only
    NOO_CLUSTER_SECRET, so on a controller carrying NOO_CONTROLLER_SECRET
    alone it returned no header at all and every channel call 401'd silently.
    And a per-consumer key added to the shared helper would never have
    reached here — this call site would have kept presenting the shared
    secret while the install read as migrated.
    """
    try:
        from ..cluster.cluster_auth import internal_gateway_headers
        # Actor `worker-channels`, never `trellion`: this runs in noo-worker
        # as well as in the trellion containers, and the gateway refuses a
        # shared-secret HMAC whose actor is an add-on's. With
        # the container's own key set (the normal case) no actor travels.
        return internal_gateway_headers("worker-channels")
    except Exception as exc:  # noqa: BLE001
        logger.warning("channel_gateway_auth_token_failed", error=str(exc))
        return {}


class GatewayChannelClient:
    """Drop-in for the consumer-facing slice of ChannelManager."""

    def list_channels(self) -> List[str]:
        return [
            name
            for name, keys in CHANNEL_ENV_KEYS.items()
            if _configured(keys)
        ]

    def get_adapter(self, name: str) -> Optional["GatewayChannelClient"]:
        """Truthy sentinel when the channel is configured, else None —
        callers only ever used the result as an is-configured check
        before dispatching (real adapter objects live in Rust now)."""
        return self if name in self.list_channels() else None

    async def resolve_recipient(self, channel: str, recipient: str) -> Optional[str]:
        """Same semantics as ChannelManager.resolve_recipient: a concrete
        id passes through; ``"broadcast"`` resolves to the channel's
        default saved recipient (noo_channel_recipients); None = skip."""
        if recipient and recipient != "broadcast":
            return recipient
        try:
            from sqlalchemy import select
            from sqlalchemy.ext.asyncio import AsyncSession
            from ..db.engine import get_async_engine
            from ..db.models import PaiChannelRecipient

            async with AsyncSession(get_async_engine(), expire_on_commit=False) as session:
                result = await session.execute(
                    select(PaiChannelRecipient).where(
                        PaiChannelRecipient.channel == channel,
                        PaiChannelRecipient.is_default.is_(True),
                    )
                )
                default = result.scalar_one_or_none()
                if default:
                    return default.recipient_id
        except Exception as exc:  # noqa: BLE001
            logger.debug("channel_gateway_resolve_failed", channel=channel, error=str(exc))
        return None

    async def dispatch(
        self,
        channel: str,
        recipient: str,
        message: str,
        *,
        thread_id: Optional[str] = None,
        file_path: Optional[str] = None,
        filename: Optional[str] = None,
        **_ignored: Any,
    ) -> bool:
        """POST the send to the gateway. Returns True on success; failures
        log and return False (every consumer treats sends as best-effort)."""
        from .._providers import default_http_context

        ctx = default_http_context()
        body: dict[str, Any] = {
            "channel": channel,
            "recipient": recipient,
            "message": message,
        }
        if thread_id:
            body["thread_id"] = thread_id
        if file_path:
            body["file_path"] = file_path
        if filename:
            body["filename"] = filename
        try:
            async with httpx.AsyncClient(
                timeout=30, verify=ctx.verify, cert=ctx.cert
            ) as client:
                resp = await client.post(
                    f"{_gateway_url()}/api/channels/send",
                    json=body,
                    headers=_auth_headers(),
                )
                resp.raise_for_status()
                payload = resp.json()
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "channel_gateway_dispatch_failed", channel=channel, error=str(exc)
            )
            return False
        if not payload.get("success"):
            logger.warning(
                "channel_gateway_dispatch_rejected",
                channel=channel,
                error=payload.get("error", ""),
            )
            return False
        return True
