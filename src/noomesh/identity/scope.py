# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tenant scope resolution for data reads — resolve, then fail closed.

This replaces the old ``NOO_MULTI_USER`` gate (``identity.gate``, deleted).
That flag made the safe behaviour opt-in: **off** (the default) meant an
absent ``user_id`` fell through to the *global* scope, so the conversation
store skipped its scope join and a memory search with no identity returned
every user's entries — and the auto-injected KB context path put the whole
corpus into the system prompt. **On** meant those reads failed closed. A
security property that only holds when an operator remembers to set an env
var is not a security property, so the flag is gone and the safe behaviour is
unconditional.

Deleting the flag outright was not an option in either direction: hard
fail-closed would break the calls that legitimately arrive with no
identity on a single-user box (terminal, CLI, heartbeat), and dropping the
check would leave the leak. So we do neither — we *resolve* instead:

1. If the install has **exactly one** enabled account, that account is the
   identity. This is safe because on such an install there is no other
   tenant to leak to; the sole account is by definition the only person
   whose data could be returned. It is also strictly better than the old
   default: those calls now read *scoped* results rather than unscoped
   ones, which means org/team filters apply where they never used to.
2. Otherwise — zero accounts, or two or more — **fail closed**: return
   ``None``, and the caller returns the same empty result the flag used to
   produce. Two accounts and no identity is exactly the ambiguity that used
   to leak.

A DB error resolves to ``None`` for the same reason: if we cannot prove the
install has a single tenant, we must not serve it another tenant's data.
"""
from __future__ import annotations

import time

import structlog

log = structlog.get_logger(__name__)

# The sole-account answer is consulted on every memory search and every
# auto-injected KB context — i.e. per prompt — so it is cached rather than
# re-queried each time. The TTL exists because the answer can change: an
# install that gains a second account MUST stop resolving unattributed reads
# to the first one, and it must do so without a restart. A permanently
# cached answer would keep leaking the first user's data to the second for
# the life of the process; 60s bounds that window to about one prompt's worth
# of staleness while still collapsing the per-call queries.
_SOLE_ACCOUNT_TTL_SECONDS = 60.0

_SOLE_ACCOUNT_CACHE: dict = {"at": 0.0, "username": None, "reason": "", "valid": False}


def reset_scope_cache() -> None:
    """Drop the memoised sole-account answer (tests; account admin paths)."""
    _SOLE_ACCOUNT_CACHE.update(
        {"at": 0.0, "username": None, "reason": "", "valid": False}
    )


async def _sole_account() -> "tuple[str | None, str]":
    """``(username, reason)`` — the only enabled account, or ``None`` with the
    reason no single tenant could be established."""
    now = time.monotonic()
    if _SOLE_ACCOUNT_CACHE["valid"] and now - _SOLE_ACCOUNT_CACHE["at"] < _SOLE_ACCOUNT_TTL_SECONDS:
        return _SOLE_ACCOUNT_CACHE["username"], _SOLE_ACCOUNT_CACHE["reason"]

    # Same DB access the workers already use for org/team and KB-grant
    # resolution (`_resolve_org_teams`, `_kb_grants_map`): the conversation
    # store's async engine. Imported lazily — identity is imported by the
    # workers, and `workers.common` reaches into `gateway.deps`.
    usernames: "list[str]" = []
    try:
        from sqlalchemy import text as _sql_text

        from ..workers.common import _get_conversation_store

        store = _get_conversation_store()
        if store is None or not hasattr(store, "_engine"):
            # Deliberately NOT cached — the store is set up asynchronously at
            # worker start, so "not ready yet" must not stick for the TTL.
            return None, "no_store"
        async with store._engine.connect() as conn:
            # LIMIT 2 is the whole question: we need to distinguish "one" from
            # "more than one", not count them. Disabled accounts do not count
            # as tenants — they cannot log in to read their own data either.
            res = await conn.execute(
                _sql_text(
                    "SELECT username FROM noo_users WHERE disabled = false LIMIT 2"
                )
            )
            usernames = [str(r[0]) for r in res.fetchall()]
    except Exception as e:  # noqa: BLE001 — cannot prove single tenancy → deny
        log.debug("scope_user_lookup_failed", error=str(e))
        # Deliberately NOT cached: a transient DB blip must not fail every
        # unattributed read for the whole TTL.
        return None, "lookup_failed"

    if len(usernames) == 1:
        username, reason = usernames[0], "sole_account"
    elif not usernames:
        username, reason = None, "no_accounts"
    else:
        username, reason = None, "several_accounts"
    _SOLE_ACCOUNT_CACHE.update(
        {"at": now, "username": username, "reason": reason, "valid": True}
    )
    return username, reason


async def resolve_scope_user(
    user_id: "str | None", *, denial_event: "str | None" = None
) -> "str | None":
    """Resolve the identity a data read should be scoped to.

    Returns the username to scope by, or ``None`` meaning **fail closed** —
    the caller must return an empty result rather than an unscoped one.

    An explicitly supplied ``user_id`` is authoritative and is never
    overridden; resolution only fills the gap when none was supplied.

    ``denial_event`` is the log event the *caller* wants emitted when the
    answer is "fail closed", so one line names both the call site and which
    case fired (no accounts / several accounts) — the reason is only known
    here, and duplicating the lookup at each call site is how the two
    enforcement points drift apart.
    """
    if user_id:
        return user_id
    resolved, reason = await _sole_account()
    if resolved is None:
        if denial_event:
            log.debug(denial_event, reason=reason)
        return None
    log.debug("scope_user_resolved_sole_account", user_id=resolved)
    return resolved
