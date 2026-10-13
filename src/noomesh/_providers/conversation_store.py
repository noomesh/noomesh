# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Conversation store provider — multi-turn conversation persistence.

Replaces the direct import:
    from noomesh.gateway.deps import services  # services.conversation_store

Consumers:
    - agents/parallel_collab.py:35 — _CollabConversationTracker

Why: the conversation store is a TRELLION concept (lives at
``trellion.live.ConversationStore``) but the gateway service registry
happens to be where the live singleton is published. Reaching into
gateway internals from harness code couples the harness to gateway
structure; this provider is the clean abstraction.

Investigated 2026-04-29: the agent confirms ``conversation_store`` calls
expose ``create_conversation`` + ``add_message`` and the underlying type
is ``trellion.live.ConversationStore``. So this provider is a thin
wrapper that returns the same Trellion object — when HARNESS becomes its
own repo it can construct its own (or reuse the gateway's via the
provider injection pattern) without touching gateway internals.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol, runtime_checkable


@runtime_checkable
class ConversationStoreProvider(Protocol):
    """Provider for the live ConversationStore singleton.

    The returned object (if any) is a ``trellion.live.ConversationStore``
    with at minimum ``create_conversation(user_id, session_id, metadata)``
    and ``add_message(conversation_id, role, content, metadata)``.
    """

    def store(self) -> Optional[Any]:
        """Return the live ConversationStore, or None if the gateway
        hasn't initialised it yet (tests, no-harness deployment)."""
        ...


class GatewayConversationStoreProvider:
    """Default impl that reads ``gateway.deps.services.conversation_store``
    (set by the worker pool's ``_init_python_services``; ``gateway.app``
    was deleted along with the Python FastAPI gateway)."""

    def store(self) -> Optional[Any]:
        try:
            from ..gateway.deps import services
            return getattr(services, "conversation_store", None)
        except Exception:
            return None


def default_conversation_store() -> ConversationStoreProvider:
    return GatewayConversationStoreProvider()
