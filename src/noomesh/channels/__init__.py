# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Channels — outbound goes through the Rust gateway; adapters are gone.

Everything channel-shaped lives in ``gateway-rust/src/channels/`` (inbound
pipelines) and ``routes/communication.rs`` (the single outbound
implementation behind ``POST /api/channels/send``). What remains here,
post the task #23 sweep:

- ``gateway_client.GatewayChannelClient`` — how in-process trellion
  consumers (proactive loop, coding notify, approval ping, autonomy
  notices) send: one authenticated POST to the gateway.
- ``base.ChannelDispatcher`` — the protocol those consumers type against.
- ``manager_ref.set_channel_manager`` / ``get_channel_manager`` — the global the
  consumers resolve the client through.

The Python adapters (google_chat, telegram), ChannelManager, the
registry and the approvals bridge are gone from the tree. Their final
versions live in git history, at the parent of commit b97a4e02 (the 2026-08-08 sweep).
"""

from .base import (
    ChannelAdapter,
    ChannelAdapterBase,
    ChannelDispatcher,
    ChannelMessage,
)
from .gateway_client import GatewayChannelClient

__all__ = [
    "ChannelAdapter",
    "ChannelAdapterBase",
    "ChannelDispatcher",
    "ChannelMessage",
    "GatewayChannelClient",
]
