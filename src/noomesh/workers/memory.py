# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Memory search/index handlers (worker.memory.*).

Moved verbatim from ``noomesh.gateway.worker_pool`` (2026-07-14 split
— pure code motion). Live subjects register on import via
``@worker_handler``; see ``noomesh.workers.registry``. Handlers whose
subjects were ported to native Rust were moved to
``legacy/python-workers-reference/`` (2026-08-08 sweep) — only live
registrations and helpers that live paths still call remain here.

NOTE on lazy (in-function) imports: they are deliberate — heavy/optional
deps (trellion, sqlalchemy, httpx, ML stacks) and modules that pull
FastAPI (gateway.deps) stay lazy so importing this package is cheap.
"""

from __future__ import annotations

from typing import Any

import structlog


from ..gateway import bus_principal
from ..identity import resolve_scope_user
from .common import _get_conversation_store
from .registry import worker_handler

log = structlog.get_logger(__name__)


async def _resolve_org_teams(store: Any, user_id: "str | None") -> "tuple[str | None, list[str] | None]":
    """Resolve the tenant scope for a username (PR5): their org
    (``noo_users.org_id``) and their ``team:*`` role grants. Both feed the
    conversation-store filter so a read sees only the user's org, and within it
    their personal + team + org-shared tiers. Degrades to (None, None) on any
    lookup failure — the caller stays scoped by ``user_id`` regardless."""
    if not user_id:
        return None, None
    org: "str | None" = None
    teams: "list[str] | None" = None
    # A `team:<name>` identity (space→team, PR5c) resolves its org from the team
    # registry and IS its own team tier — a shared team space reads the team's
    # org + the team's own conversations.
    is_team = user_id.startswith("team:")
    try:
        from sqlalchemy import text as _sql_text
        if store is not None and hasattr(store, "_engine"):
            async with store._engine.connect() as conn:
                if is_team:
                    row = await conn.execute(
                        _sql_text("SELECT org_id FROM noo_kb_teams WHERE name = :t"),
                        {"t": user_id[len("team:"):]},
                    )
                else:
                    row = await conn.execute(
                        _sql_text("SELECT org_id FROM noo_users WHERE username = :u"),
                        {"u": user_id},
                    )
                val = row.scalar()
                org = str(val) if val else None
    except Exception as e:
        log.debug("org_resolve_failed", error=str(e))
    if is_team:
        return org, [user_id]
    try:
        from .kb import _kb_grants_map
        grants = (await _kb_grants_map()).get(user_id) or []
        picked = [g for g in grants if isinstance(g, str) and g.startswith("team:")]
        teams = picked or None
    except Exception:
        teams = None
    return org, teams


# ═══════════════════════════════════════════════════════════════════════
# Memory handlers
# ═══════════════════════════════════════════════════════════════════════


# NOTE: HTTP memory routes are native Rust (gateway-rust/src/routes/
# memory.rs), but the Rust coordinator uses the worker.memory.search /
# worker.memory.cross_channel NATS subjects for context injection
# (fetch_memory_context, fetch_cross_channel_context). Both are needed.
@worker_handler("worker.memory.search")
async def _memory_search(request: dict) -> Any:
    """Handle memory search delegation.

    H-D1 cross-user scoping: when ``user_id``/``persona_id`` are present in the
    request the store filters to that user's entries plus shared (NULL) rows via
    ``(c.user_id = :user_id OR c.user_id IS NULL)``. When absent, the scope is
    *resolved* (see ``identity.resolve_scope_user``) rather than dropped — a
    sole-account install scopes to that account, anything else fails closed.
    """
    try:
        conversation_store = _get_conversation_store()
        if not conversation_store:
            return ""
        params = request.get("params", request)
        query = params.get("query", request.get("query", ""))
        top_k = params.get("top_k", 5)
        # Tenancy comes from the SIGNED principal, not the payload. For a
        # user principal the two cannot disagree — the worker pool refused
        # the message if they did.
        user_id = bus_principal.tenant_of(request, params)
        persona_id = params.get("persona_id") or request.get("persona_id") or None
        # Without a user_id the store would skip the scope join and return
        # EVERY user's entries — the old NOO_MULTI_USER default. So resolve
        # first (sole account = that account) and, failing that, return
        # nothing rather than leak.
        user_id = await resolve_scope_user(
            user_id, denial_event="memory_search_denied_no_identity"
        )
        if not user_id:
            return ""
        # PR5: resolve the org + team tiers so the search is bounded to the
        # user's org and their personal/team/org-shared conversations.
        org, teams = await _resolve_org_teams(conversation_store, user_id)
        # search_text returns List[Tuple[entry_dict, score]] and applies the
        # user/persona/org/team scope when those are supplied.
        results = await conversation_store.search_text(
            query, top_k=top_k, user_id=user_id, persona_id=persona_id, org=org, teams=teams
        )
        if results:
            return "\n".join(
                (entry.get("content", "") or "")[:500]
                for entry, _score in results[:top_k]
            )
        return ""
    except Exception as e:
        return {"error": str(e)}


@worker_handler("worker.memory.cross_channel")
async def _memory_cross_channel(request: dict) -> Any:
    """Fetch recent messages from other channels for cross-channel context.

    H-D1 cross-user scoping: only the requesting user's conversations (plus
    shared/NULL rows) are considered, so one user never sees another user's
    cross-channel activity. An absent ``user_id`` is resolved the same way as
    in :func:`_memory_search`. (``max_age_hours`` is best-effort: the store
    already returns the most recent conversations first.)
    """
    try:
        conversation_store = _get_conversation_store()
        if not conversation_store:
            return {"success": True, "data": {"messages": []}}

        params = request.get("params", request)
        exclude = params.get("exclude_channel", request.get("exclude_channel", ""))
        top_k = params.get("top_k", request.get("top_k", 3))
        user_id = bus_principal.tenant_of(request, params)
        # Resolve, then fail closed (see _memory_search): an unresolved
        # user_id would list every user's conversations across channels.
        user_id = await resolve_scope_user(
            user_id, denial_event="memory_cross_channel_denied_no_identity"
        )
        if not user_id:
            return {"success": True, "data": {"messages": []}}

        # PR5: bound cross-channel recall to the user's org + team tiers.
        org, teams = await _resolve_org_teams(conversation_store, user_id)
        listing = await conversation_store.list_conversations(
            user_id=user_id, active_only=False, limit=20, org=org, teams=teams
        )
        convos = (
            listing.get("conversations", [])
            if isinstance(listing, dict)
            else (listing or [])
        )

        messages: list[dict] = []
        for conv in convos:
            channel = (conv.get("metadata") or {}).get("source_channel", "unknown")
            if exclude and channel == exclude:
                continue
            conv_id = conv.get("id") or conv.get("conversation_id")
            if not conv_id:
                continue
            for m in await conversation_store.get_recent_messages(conv_id, limit=top_k):
                content = (m.get("content") or "")[:500]
                if content:
                    messages.append({"channel": channel, "content": content})
                if len(messages) >= top_k:
                    break
            if len(messages) >= top_k:
                break
        return {"success": True, "data": {"messages": messages[:top_k]}}
    except Exception as e:
        log.debug("cross_channel_failed", error=str(e))
        return {"success": True, "data": {"messages": []}}


@worker_handler("worker.memory.batch_index")
async def _memory_batch_index(request: dict) -> Any:
    """Handle memory batch index delegation.

    `max_batches` is bounded to fit the NATS reply deadline, not to fit the
    work. At the observed ~0.6s per record a 100-record batch takes ~60s, so
    trellion's own default of 5 batches overruns NOO_WORKER_TIMEOUT_SECS
    (120s): the caller got a 503 while the drain kept running invisibly in
    the background — the same failure the bounding was meant to remove. One
    batch per call fits, and the `remaining` count tells the caller to call
    again.
    """
    try:
        from ..gateway.deps import services
        ew = services.embedding_worker
        if not ew:
            return {"error": "Embedding worker not initialized"}
        if hasattr(ew, "batch_index"):
            params = request.get("params", request)
            try:
                max_batches = int(params.get("max_batches", 1))
            except (TypeError, ValueError):
                return {"error": "max_batches must be an integer"}
            if max_batches < 1:
                return {"error": "max_batches must be >= 1"}
            result = await ew.batch_index(max_batches=max_batches)
            return result
        return {"status": "not_supported"}
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════

# `worker.retrieval.feedback` had a handler here until 2026-09-28. It was
# the subject's only subscriber and could never record anything: `memory`
# is an `ml` module (noo-trellion), the tracker it imported lives in an
# add-on package (absent from that image), and the method it called
# (`record_implicit_feedback`) does not exist on it. Every miss was swallowed as
# `{"success": True}`. The subject is trellion-intel's now
# (addons.rs::is_trellion_intel_subject); the consumer is the add-on's to
# register — the design holds the contract.

@worker_handler("worker.memory.resolve_conversation")
async def _memory_resolve_conversation(request: dict) -> Any:
    """Resolve the stable conversation id for a chat context.

    THE SEAM for . The Rust channel pipeline owns parse,
    threading, formatting and send; conversation IDENTITY is memory, and
    memory is Trellion, so Rust asks for it here rather than reading
    Trellion's tables directly. Duplicating schema knowledge across two
    languages is the exact failure mode the channels port exists to remove
    — it is what produced the OAuth token-cache outage.

    Why this must exist BEFORE the pipeline moves: `native_inference` mints
    a random UUID when `conversation_id` is absent, so a Rust pipeline that
    skips this call starts a brand new conversation on every message. The
    bot answers each message sensibly and remembers nothing. That passes any
    smoke test and surfaces only as "it stopped remembering things".

    Request: ``{channel, chat_context_id, metadata}`` where `metadata` is
    the conversation metadata to use IF a new conversation must be created
    (including the `noo_routing` block the harness owns). `chat_context_id`
    is the caller's — the adapter-specific rule (Google Chat keys a space by
    space name, not sender) travels with the caller, which is the harness.

    Returns ``{conversation_id, created}``. `created` is reported so the
    caller can tell a resumed conversation from a fresh one; a caller seeing
    created=true on every message has a context-id bug, and this is the
    signal that makes that visible instead of silent.
    """
    try:
        store = _get_conversation_store()
        if not store:
            # No store: return no id rather than inventing one. A synthesised
            # id would be accepted downstream and silently fragment history.
            return {"success": True, "data": {"conversation_id": None,
                                              "created": False}}

        params = request.get("params", request)
        channel = params.get("channel") or ""
        context_id = params.get("chat_context_id") or ""
        if not channel or not context_id:
            return {"success": False,
                    "error": "channel and chat_context_id are required"}

        existing = await store.find_active_conversation(context_id, channel)
        if existing:
            return {"success": True, "data": {"conversation_id": existing,
                                              "created": False}}

        metadata = params.get("metadata") or {}
        conv_id = await store.create_conversation(
            user_id=context_id,
            metadata=metadata,
        )
        log.info(
            "memory.conversation_created",
            channel=channel,
            context_id=context_id,
            conversation_id=conv_id,
        )
        return {"success": True, "data": {"conversation_id": conv_id,
                                          "created": True}}
    except Exception as exc:  # noqa: BLE001
        log.error("memory.resolve_conversation_failed", error=str(exc))
        # Fail LOUD. Returning a null id here would let the caller fall
        # through to inference, which mints a random UUID — turning a
        # resolution failure into silent memory loss.
        return {"success": False, "error": str(exc)}
