# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Process-global reference to the channel client.

worker_pool injects the GatewayChannelClient here at startup; in-process
consumers resolve it through ``get_channel_manager``. It replaced the old
FastAPI channels router, removed in the 2026-08-08 sweep (history in git log before that).
"""

from __future__ import annotations

_channel_manager = None


def set_channel_manager(manager) -> None:
    """Called during startup to inject the channel client."""
    global _channel_manager
    _channel_manager = manager


def get_channel_manager():
    """Return the injected channel client, or None before startup."""
    return _channel_manager
