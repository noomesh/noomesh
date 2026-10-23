# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Knowledge-base role/grant/team admin handlers (worker.api.kb.*).

Moved verbatim from ``noomesh.gateway.worker_pool`` (2026-07-14 split
— pure code motion). Live subjects register on import via
``@worker_handler``; see ``noomesh.workers.registry``. Handlers whose
subjects were ported to native Rust were moved to
``git history (before 2026-08-08)`` (2026-08-08 sweep) — only live
registrations and helpers that live paths still call remain here.

NOTE on lazy (in-function) imports: they are deliberate — heavy/optional
deps (trellion, sqlalchemy, httpx, ML stacks) and modules that pull
FastAPI (gateway.deps) stay lazy so importing this package is cheap.

7 handlers removed 2026-07-18 — ported to native Rust routes
(gateway-rust routes/users.rs); see PR #206. The remaining helpers
(_kb_grants_map, _kb_source_rules, _resolve_kb_roles) are imported by
rag.py and memory.py.
"""

from __future__ import annotations

import re

import structlog

from .common import _get_conversation_store

log = structlog.get_logger(__name__)



_KB_GRANTS_CACHE: dict = {"at": 0.0, "grants": {}}


async def _kb_grants_map() -> dict:
    """username → extra granted KB roles (noo_kb_role_grants), cached 30s.
    This is where teams/orgs attach to users: grant ["team:research"] and
    every query by that user includes it. Errors degrade to no-grants."""
    import time as _time

    now = _time.monotonic()
    if now - _KB_GRANTS_CACHE["at"] < 30.0:
        return _KB_GRANTS_CACHE["grants"]
    _KB_GRANTS_CACHE["at"] = now
    grants: dict = {}
    try:
        from sqlalchemy import text as _sql_text
        store = _get_conversation_store()
        if store is not None and hasattr(store, "_engine"):
            async with store._engine.connect() as conn:
                result = await conn.execute(
                    _sql_text("SELECT username, roles FROM noo_kb_role_grants"))
                for username, roles in result.fetchall():
                    grants[str(username)] = [str(r) for r in (roles or [])]
    except Exception:  # noqa: BLE001 — table may not exist yet; degrade
        pass
    _KB_GRANTS_CACHE["grants"] = grants
    return grants


async def _kb_source_rules() -> list:
    """DB-backed provenance rules (noo_kb_source_rules), cached 30s,
    ordered by priority. Take precedence over the kb.source_roles YAML."""
    import time as _time

    cache = _KB_GRANTS_CACHE.setdefault("rules_cache", {"at": 0.0, "rules": []})
    now = _time.monotonic()
    if now - cache["at"] < 30.0:
        return cache["rules"]
    cache["at"] = now
    rules: list = []
    try:
        from sqlalchemy import text as _sql_text
        store = _get_conversation_store()
        if store is not None and hasattr(store, "_engine"):
            async with store._engine.connect() as conn:
                result = await conn.execute(_sql_text(
                    "SELECT match, roles FROM noo_kb_source_rules "
                    "WHERE enabled ORDER BY priority, id"))
                rules = [(str(m), [str(r) for r in (roles or [])])
                         for m, roles in result.fetchall()]
    except Exception:  # noqa: BLE001
        pass
    cache["rules"] = rules
    return rules


# Signed-principal scope the gateway adds for a turn in a group chat or a
# shared space (`channels::scoped_turn`). Every KB read is clamped to the
# tiers the whole room may see, and personal memory search is refused.
SHARED_ROOM_SCOPE = "kb:shared-room"
SHARED_ROOM_KB_ROLES = ("company", "system")


def _resolve_kb_roles(params: dict, grants: "list[str] | None" = None) -> "list[str] | None":
    """Resolve the KB role set for a request (KB role segmentation).

    Docs carry audience tags in metadata.roles ("system", "company",
    "user:<name>", ...); retrieval only surfaces docs overlapping the
    requester's role set. Resolution policy:

    - **No verified principal: REFUSED.** This used to be the widest
      answer in the function — "no ``_requester``" meant unrestricted, so
      the ABSENCE of an identity granted more than any identity could. It
      was safe only while the gateway was the only thing that could
      publish `worker.>` (#100), and that is a property of the bus, not of
      this call. A caller now proves who it is or gets nothing
      (``BusPrincipal`` in ``noomesh/gateway/bus_principal.py``).
    - unrestricted (None) for a verified principal that carries ``admin``
      or ``kb:unrestricted`` — the latter being how the enumerated
      internal loops (heartbeat research, reindex) keep the corpus-wide
      read they genuinely need without being handed admin. Both are read
      from the SIGNED header; ``"admin" in scopes`` taken out of the
      message body was R32. Still narrowable by an EXPLICIT ``roles``.
      ``write`` does NOT confer this — see :func:`_writable_kb_roles`.
    - every other requester (read/write/ingest): defaults to their own
      docs + shared tiers
      (["user:<sub>", "company", "system"]). An explicit ``roles`` list
      is CLAMPED to that allowed set — a read user cannot query
      user:someone-else. Note the generic legacy "user" tier (docs
      ingested before roles existed) is NOT granted to read users.
    """
    from ..gateway import bus_principal

    explicit = params.get("roles")
    if isinstance(explicit, str):
        explicit = [explicit]

    principal = bus_principal.of(params)
    if principal is not None and principal.has_scope(SHARED_ROOM_SCOPE):
        # A turn in a group chat or shared space (the gateway adds this scope
        # to the SIGNED principal for the whole turn, tool calls included):
        # the reply is posted to the room, so every read is clamped to what
        # the whole room may see. It is checked before kb_unrestricted, and
        # it can only narrow.
        wanted = list(explicit) if explicit else list(SHARED_ROOM_KB_ROLES)
        return [r for r in wanted if r in SHARED_ROOM_KB_ROLES] or list(SHARED_ROOM_KB_ROLES)
    if principal is not None:
        if principal.kb_unrestricted:
            return list(explicit) if explicit else None
        requester = principal.as_requester()
    else:
        # Reachable only from an in-process caller that skipped the bus
        # gate. Refusing loudly is the point: the alternative is the
        # unrestricted answer this branch used to give.
        raise PermissionError(
            "knowledge-base read with no verified bus principal — refused"
        )

    allowed = _kb_audience(requester, grants) | {"system"}
    # `generated` is OPT-IN, and the asymmetry is the whole feature: it is
    # permitted when asked for, absent when not.
    #
    # Machine-authored documents (heartbeat reports, research notes) carry
    # `generated` as their ONLY role, so a default query — whose role list is
    # `allowed` — cannot overlap them and they drop out. Ask for them by name
    # and they come back.
    #
    # Retrieval matches by overlap (`jsonb_exists_any`) with no NOT clause, so
    # this is the only way to express exclusion without changing trellion:
    # withhold the tag from the default set rather than subtract it afterwards.
    # Post-filtering would not work either — synthesis happens inside the
    # retrieval call, so the answer is already written from whatever evidence
    # was pulled.
    #
    # Why it matters: 211 daily research notes were out-ranking 74 substantive
    # meeting transcripts, so "what did we discuss in our meetings" came back
    # with the cluster's own essays. An agent doing new research should not
    # rediscover yesterday's summary of itself.
    if explicit:
        clamped = [r for r in explicit if r in allowed or r == "generated"]
        return clamped if clamped else sorted(allowed)
    return sorted(allowed)


async def _kb_roles_for(params: dict) -> "list[str] | None":
    """The role set for this request, grants and all: THE resolver entry.

    Retrieval (``worker.rag.query``) and the gateway's listing/graph reads
    (``worker.rag.audience``) both come through here, so "which audiences may
    this caller read" is answered by one function in one language. The
    gateway does not re-derive it.

    Grants are looked up by the account of the SIGNED principal, not by a
    ``_requester`` claim in the body. ``None`` means unrestricted.
    """
    from ..gateway import bus_principal

    principal = bus_principal.of(params)
    account = _account_of(principal.sub) if principal is not None else ""
    grants = (await _kb_grants_map()).get(account) if account else None
    return _resolve_kb_roles(params, grants=grants)


# Kept for tests/worker_pool re-export (team-name validation regex).
_TEAM_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def _account_of(name: str) -> str:
    """``alice/laptop`` -> ``alice``. Mirrors ``auth::account_of`` in the
    gateway (``CONNECTION_SEP`` = ``/``); a bare account is itself."""
    return name.split("/", 1)[0]


def _kb_audience(requester: dict, grants: "list[str] | None" = None) -> "set[str]":
    """The tiers this requester BELONGS TO — own, shared, and granted teams.

    The single source for both sides, so "who is this caller" is computed
    once. What each side then DOES with it differs, and that difference is
    policy, not drift:

        read  = _kb_audience(...) | {"system"}     # system is world-readable
        write = _kb_audience(...)                  # and operator-only writable

    Keeping the union/subtraction at the call sites makes the asymmetry a
    visible one-token difference instead of two functions that look alike and
    quietly disagree — the failure mode this repo keeps paying for.
    """
    # The ACCOUNT, never the connection. A token minted for an
    # MCP-door connection carries `alice/laptop` as its subject; a doc is
    # tagged `user:alice`. Matching the whole string put the caller in a tier no
    # document is in, so their own uploads vanished and (worse, for the
    # listing that now reuses this resolver) the grants lookup missed too.
    sub = _account_of(str(requester.get("sub") or "").strip())
    audience = {"company"} | ({f"user:{sub}"} if sub else set())
    # DB grants attach teams/orgs. `system` is filtered here rather than at
    # one call site: a granted `system` must not become writable, and the
    # read side re-adds it unconditionally anyway.
    # `admin` is filtered for the same reason: it is the operator-only
    # audience, so a grant row must never put it in a non-admin's read OR
    # write set. Admins reach it by being unrestricted, not by membership.
    audience |= {r for r in (grants or []) if r not in ("system", "user", "admin")}
    return audience


def _writable_kb_roles(requester: dict, grants: "list[str] | None" = None) -> "set[str] | None":
    """Audience tags this requester may TAG A DOCUMENT WITH.

    The write-side peer of :func:`_resolve_kb_roles`, and deliberately not a
    copy of it. Two differences matter:

    - ``system`` is readable by everyone and writable by no one but an
      admin. It is the tier repo runbooks live in, so a document tagged
      ``system`` reads as authoritative to every user on the deployment;
      letting a contributor self-declare that is a content-injection path,
      not a sharing feature.
    - the generic legacy ``user`` tier is never writable — new documents
      should not be born into the pre-roles bucket.

    Everything the caller is genuinely ASSIGNED to is allowed: their own
    ``user:<sub>``, the shared ``company`` tier, and any ``team:*`` from
    ``noo_kb_role_grants``. So a document can land in the org tier the same
    way a Drive-sourced one does — by being tagged ``company`` — rather than
    being trapped in the ingesting account's personal tier.

    Returns ``None`` for an unrestricted caller (no requester, or admin),
    meaning "no clamp".

    ``write`` is deliberately NOT unrestricted. It is an API-access tier —
    "may call mutating endpoints" — and for a while it doubled as a KB
    visibility tier, which quietly made every operator account able to read
    every other user's ``user:*`` docs and to publish into ``system``. Those
    are two different questions, and conflating them meant granting somebody
    the ability to CONTRIBUTE documents also granted the ability to READ
    everyone's private ones. Audience is now decided by membership
    (`_kb_audience`) for everybody except admin.
    """
    if not requester:
        return None
    scopes = requester.get("scopes") or []
    if "admin" in scopes:
        return None
    return _kb_audience(requester, grants)
