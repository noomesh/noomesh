# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Base protocol definitions for channel adapters.

Defines the contracts that all channel adapters must implement, plus the
ChannelDispatcher protocol used by the proactive agent loop to send
outbound messages without coupling to a specific platform.

ChannelMessage is the normalized inbound message format that all adapters
produce, regardless of the originating platform.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable, Protocol, runtime_checkable


@dataclass
class ChannelMessage:
    """Platform-agnostic inbound message.

    Every adapter converts its platform-specific webhook payload into this
    common shape before handing it to the gateway for inference.

    Attributes:
        channel: Adapter identifier, e.g. ``"whatsapp"`` or ``"google_chat"``.
        sender_id: Opaque platform user ID (phone number, Google Chat user ID).
        sender_name: Human-readable display name when available.
        text: Plain-text message content.
        attachments: List of attachment dicts (keys vary by platform; typically
            ``{"type": "image", "url": "..."}``).
        thread_id: Platform thread/conversation ID for threaded replies.
            ``None`` for platforms or messages without threading.
        timestamp: UTC timestamp of the original message.
        raw: The original platform payload, preserved for debugging or
            adapter-specific processing.
    """

    channel: str
    sender_id: str
    sender_name: str
    text: str
    attachments: list[dict[str, Any]] = field(default_factory=list)
    thread_id: str | None = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    raw: dict[str, Any] = field(default_factory=dict, repr=False)
    metadata: dict[str, Any] = field(default_factory=dict)


def strip_think_blocks(text: str) -> str:
    """Strip ``<think>...</think>`` blocks from a model reply before it is
    delivered to a channel. Mirrors Rust ``verify::response::strip_think_blocks``:
    paired blocks are removed wherever they appear, an unclosed ``<think>``
    drops everything after it, and a stray leading ``</think>`` (opener lost
    upstream) is removed. Result is trimmed.

    Thinking is ephemeral reasoning — and often quotes internal context
    (cluster state, addresses) that must never reach a chat surface.
    """
    result = []
    remaining = text
    while True:
        start = remaining.find("<think>")
        if start == -1:
            break
        result.append(remaining[:start])
        end = remaining.find("</think>", start)
        if end == -1:
            return "".join(result).strip()
        remaining = remaining[end + len("</think>"):]
    result.append(remaining)
    out = "".join(result).lstrip()
    if out.startswith("</think>"):
        out = out[len("</think>"):]
    return out.strip()


def webhook_reply(
    status: int, payload: Any, content_type: str = "application/json"
) -> dict[str, Any]:
    """Build the ``{status, content_type, body}`` webhook response dict.

    This is the shape ``worker.channels.webhook`` relays to the Rust
    gateway as the HTTP response. ``payload`` may be a pre-serialized
    string or any JSON-serializable object.
    """
    if isinstance(payload, str):
        body = payload
    else:
        import json

        body = json.dumps(payload)
    return {"status": status, "content_type": content_type, "body": body}


@runtime_checkable
class ChannelAdapter(Protocol):
    """Protocol that every channel adapter must satisfy.

    Adapters handle two concerns:

    1. **Outbound** -- sending messages from PAI to a user on the platform.
    2. **Webhook verification** -- proving to the platform that the webhook
       endpoint is legitimate (e.g. WhatsApp challenge-response, Google Chat
       bearer token).

    Adapters do *not* own their own FastAPI routes; the channel router creates
    routes and delegates to the adapter's ``parse_webhook`` method.
    """

    @property
    def name(self) -> str:
        """Short lowercase identifier, e.g. ``"whatsapp"``."""
        ...

    async def send_message(
        self,
        recipient_id: str,
        text: str,
        thread_id: str | None = None,
    ) -> bool:
        """Send a plain-text message to a user on this platform.

        Returns ``True`` on success, ``False`` on failure (adapter logs the
        error internally).
        """
        ...

    async def send_rich(
        self,
        recipient_id: str,
        blocks: list[dict[str, Any]],
        thread_id: str | None = None,
    ) -> bool:
        """Send a rich message (cards, buttons, images).

        ``blocks`` is a list of adapter-specific block dicts.  Each adapter
        documents its supported block schema.  Falls back to plain text if
        the platform cannot render the block type.

        Returns ``True`` on success, ``False`` on failure.
        """
        ...

    def verify_webhook(self, headers: dict[str, str], body: bytes) -> bool:
        """Verify that an incoming webhook request is authentic.

        WhatsApp uses a ``hub.verify_token`` challenge; Google Chat uses a
        bearer token in the ``Authorization`` header.  Each adapter
        implements the check appropriate to its platform.
        """
        ...

    def handle_verification(self, query: dict[str, str]) -> str | None:
        """Handle a GET verification challenge (endpoint-ownership proof).

        Some platforms verify a webhook endpoint with a GET request before
        sending events — e.g. WhatsApp/Meta's ``hub.mode`` /
        ``hub.verify_token`` / ``hub.challenge`` exchange. ``query`` is the
        request's query parameters. Return the challenge string to echo
        back (200 text/plain), or ``None`` to reject (403). The default
        (``ChannelAdapterBase``) rejects — platforms without a GET
        handshake never see this path.
        """
        ...

    async def parse_webhook(self, headers: dict[str, str], body: bytes) -> ChannelMessage | None:
        """Parse a raw webhook payload into a ``ChannelMessage``.

        Returns ``None`` if the payload is a non-message event (e.g. a
        delivery receipt or typing indicator) that should be silently
        acknowledged.
        """
        ...

    async def handle_interaction(
        self, headers: dict[str, str], body: bytes
    ) -> dict[str, Any] | None:
        """Handle an interaction payload (button press / card click).

        Called by the generic webhook handler AFTER ``verify_webhook``
        succeeds and BEFORE the normal ``parse_webhook`` → reply flow.
        When the payload is an interaction rather than a chat message
        (e.g. a Telegram ``callback_query`` approval button or a Google
        Chat ``CARD_CLICKED`` approval card), the adapter performs the
        interaction's side effects (record the decision, acknowledge in
        chat) and returns the platform-facing webhook response as a
        ``{"status": int, "content_type": str, "body": str}`` dict —
        the generic handler relays it verbatim. Return ``None`` for
        non-interaction payloads to continue the normal message flow
        (the default; mirrors ``handle_verification``'s opt-in shape).
        """
        ...

    # -- Declared-optional capabilities --------------------------------------
    # These are part of the contract but may be ``None`` (unsupported).
    # ``ChannelAdapterBase`` supplies the ``None`` defaults; adapters that
    # support a capability override the attribute with a real async method.
    # Callers MUST check ``adapter.send_file is not None`` — never hasattr().

    send_file: Callable[..., Awaitable[bool]] | None
    """Optional: ``async send_file(recipient_id, file_path, *, text="",
    thread_id=None, filename=None) -> bool``. ``None`` when the platform
    cannot deliver file attachments (dispatch degrades to inline text)."""

    list_messages: Callable[..., Awaitable[list[dict[str, Any]]]] | None
    """Optional: ``async list_messages(recipient, max_results=50,
    filter_str=None) -> list[dict]``. ``None`` when the platform offers no
    message-history read API."""

    # -- Routing hooks (defaults on ChannelAdapterBase) -----------------------

    webhook_reply_mode: str
    """``"sync"`` (reply in the webhook handler) or ``"deferred"`` (ack
    immediately, reply asynchronously — e.g. Google Chat's ~30s timeout)."""

    def resolve_reply_target(self, msg: ChannelMessage) -> tuple[str, str | None]:
        """Return ``(recipient_id, thread_id)`` for replying to *msg*."""
        ...

    def reply_send_kwargs(self, msg: ChannelMessage) -> dict[str, Any]:
        """Extra kwargs the webhook reply loop passes to ``send_message`` for
        *msg* (default ``{}`` on ``ChannelAdapterBase``)."""
        ...

    def reply_target_from_task(self, task: dict[str, Any]) -> tuple[str, str | None]:
        """Return ``(recipient_id, thread_id)`` from a serialized queue task."""
        ...

    def chat_context_id(self, msg: ChannelMessage) -> str:
        """Return the conversation-identity key for *msg* (e.g. ``"telegram:<chat_id>"``)."""
        ...

    def conversation_metadata(self, msg: ChannelMessage) -> dict[str, Any]:
        """Extra adapter-specific metadata stored on a newly created conversation."""
        ...


class ChannelAdapterBase:
    """Default implementations of the optional/derived parts of ``ChannelAdapter``.

    Concrete adapters subclass this so they only implement the required
    surface (``name``, ``send_message``, ``send_rich``, ``verify_webhook``,
    ``parse_webhook``) plus whichever optional capabilities the platform
    supports. Overriding an optional capability means assigning a real
    method over the ``None`` default (e.g. ``async def send_file(...)``).
    """

    # Declared-optional capabilities — None means "unsupported".
    send_file: Callable[..., Awaitable[bool]] | None = None
    list_messages: Callable[..., Awaitable[list[dict[str, Any]]]] | None = None

    # Most platforms tolerate a slow webhook response; Google Chat overrides.
    webhook_reply_mode: str = "sync"

    def handle_verification(self, query: dict[str, str]) -> str | None:
        """Default: no GET verification handshake — reject the challenge."""
        return None

    async def handle_interaction(
        self, headers: dict[str, str], body: bytes
    ) -> dict[str, Any] | None:
        """Default: no interaction payloads — always the normal message flow."""
        return None

    def resolve_reply_target(self, msg: ChannelMessage) -> tuple[str, str | None]:
        """Default: reply directly to the sender, unthreaded."""
        return (msg.sender_id, None)

    def reply_send_kwargs(self, msg: ChannelMessage) -> dict[str, Any]:
        """Extra per-message kwargs the webhook reply loop passes to
        ``send_message`` for *msg*. Default: none — the loop calls
        ``send_message(recipient, text, thread_id)`` unchanged. Adapters
        that need extra send-time context (e.g. Google Chat's ``chat_type``
        for correct thread routing) override this; the kwargs must match
        that same adapter's ``send_message`` signature."""
        return {}

    def reply_target_from_task(self, task: dict[str, Any]) -> tuple[str, str | None]:
        """Default: reply to the task's sender, preserving its thread."""
        return (task.get("sender_id", ""), task.get("thread_id"))

    def chat_context_id(self, msg: ChannelMessage) -> str:
        """Default: ``<channel>:<sender_id>`` (sender_id is the chat context
        for DMs, and platforms like Telegram already send the group chat_id
        as sender_id)."""
        return f"{msg.channel}:{msg.sender_id}"

    def conversation_metadata(self, msg: ChannelMessage) -> dict[str, Any]:
        """Default: no adapter-specific conversation metadata."""
        return {}


@runtime_checkable
class ChannelDispatcher(Protocol):
    """Outbound-only interface for sending messages across channels.

    The proactive agent loop and other internal components depend on this
    protocol -- not on individual adapters -- so they can dispatch messages
    to any registered channel without knowing platform details.

    Typical implementation: ``ChannelManager.dispatch``.
    """

    async def dispatch(
        self,
        channel: str,
        recipient: str,
        message: str,
        *,
        thread_id: str | None = None,
        rich_blocks: list[dict[str, Any]] | None = None,
    ) -> bool:
        """Send a message to *recipient* on *channel*.

        If *rich_blocks* is provided the adapter will attempt ``send_rich``;
        otherwise it falls back to ``send_message`` with plain text.

        Returns ``True`` if delivery succeeded.
        """
        ...
