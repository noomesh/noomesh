# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""User identity resolution across channels.

Channel adapters receive messages identified by (channel, channel_user_id)
pairs — e.g. ("telegram", "@johndoe"), ("google_chat", "users/12345").
This module resolves those to the canonical ``noo_users.username``, so
the same human across multiple channels maps to a single identity in
the temporal graph and elsewhere.

Linkage is stored in ``noo_user_channel_links``. A link is created by:
  - ``noo users link <channel> <channel_user_id> <username>`` CLI
  - Future: automatic prompt during channel adapter onboarding

If no link exists, callers get ``None`` and typically fall back to
``channel_user_id`` itself as the canonical name (fragmented but
useful) — the temporal graph handles either gracefully.
"""
from .resolver import resolve_user, link_user, list_links_for, unlink_user
from .scope import resolve_scope_user, reset_scope_cache

__all__ = [
    "resolve_user",
    "link_user",
    "list_links_for",
    "unlink_user",
    "resolve_scope_user",
    "reset_scope_cache",
]
