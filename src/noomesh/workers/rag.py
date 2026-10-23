# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""RAG query/ingest handlers (worker.rag.*).

Moved verbatim from ``noomesh.gateway.worker_pool`` (2026-07-14 split
— pure code motion). Live subjects register on import via
``@worker_handler``; see ``noomesh.workers.registry``. Handlers whose
subjects were ported to native Rust were removed in the
2026-08-08 sweep (history in git log before that) — only live
registrations and helpers that live paths still call remain here.

NOTE on lazy (in-function) imports: they are deliberate — heavy/optional
deps (trellion, sqlalchemy, httpx, ML stacks) and modules that pull
FastAPI (gateway.deps) stay lazy so importing this package is cheap.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog


from ..gateway import bus_principal
from ..identity import resolve_scope_user
from .common import _get_conversation_store, _get_rag
from .kb import (
    _kb_grants_map,
    _kb_roles_for,
    _kb_source_rules,
    _resolve_kb_roles,
    _writable_kb_roles,
)
from . import ingest_confine, kb_ingest_roles, kb_trace
from . import walks as _walks
from .registry import worker_handler

log = structlog.get_logger(__name__)

@worker_handler("worker.rag.query")
async def _rag_query(request: dict) -> Any:
    """Handle RAG query delegation."""
    rag = _get_rag()
    if not rag or not rag._started:
        raise RuntimeError("RAG not started")
    params = request.get("params", request)
    # Accept both keys — half the callers say "query". Before this alias,
    # a {"query": ...} body silently ran an EMPTY question through the
    # whole pipeline (which then died with an unrelated-looking TEI 413).
    question = (params.get("question") or params.get("query")
                or request.get("question") or "").strip()
    if not question:
        return {"error": "question required (accepts 'question' or 'query')"}
    strategy = params.get("strategy", "hybrid")
    roles = await _kb_roles_for(params)
    result = await rag.query(question, strategy=strategy, roles=roles)
    reply = {
        "answer": result.answer if result else "",
        "citations": [c.__dict__ for c in (result.citations or [])] if result else [],
        "strategy_used": result.strategy_used if result else "",
        # The CLI prints `intent <x> · <n> evidence pages` from these two keys.
        # Before they were returned it printed `intent ?` and `0 evidence
        # pages` for EVERY query — including ones that answered — so a
        # retrieval miss and a hit looked the same.
        "intent": result.intent if result else "",
        "evidence_count": len(result.evidence or []) if result else 0,
    }
    if result:
        # A signed-in user's walk is kept as a thread, AFTER the reply is
        # built and off its path (workers/walks.py). Never raises.
        _walks.keep(request, via="rag", query=question, build=lambda: _walks.walk_from_rag_result(result))
    return reply


@worker_handler("worker.rag.audience")
async def _rag_audience(request: dict) -> Any:
    """The caller's KB role set, for the gateway's SQL-side listing/graph reads.

    ``{"roles": null}`` = unrestricted (admin / ``kb:unrestricted``); a list
    is the audience tags the caller may read. The gateway filters
    ``GET /api/v1/docs`` and the graph routes with it, so those surfaces obey
    the same audience as ``worker.rag.query`` without a second copy of the
    rules. Reads the caller from the signed header only.
    """
    params = request.get("params", request)
    return {"roles": await _kb_roles_for(params)}


# ── Graph layer of the injected context ───────────────────────────────────
#
# gateway-rust/src/coordinator/context.rs::fetch_rag_context reads
# `data.graph_context.hypotheses[].{description,confidence}` and
# `data.graph_context.seed_entities[].canonical_name` and renders the top
# three / five into the system prompt. Nothing here used to produce them, so
# the graph layer was empty on every install (docs audit 2026-10-08).
# tests/test_rag_context_graph.py pins these names against context.rs.
GRAPH_CONTEXT_KEY = "graph_context"
GRAPH_ERROR_KEY = "graph_error"
GRAPH_MAX_HYPOTHESES = 3  # context.rs renders .take(3)
GRAPH_MAX_SEEDS = 5       # context.rs renders .take(5)
# The gateway waits 10 s for the whole reply and retrieval alone is ~5 s, so
# the graph walk runs CONCURRENTLY with retrieval and gets a short budget of
# its own: a slow graph costs the graph, never the pages.
GRAPH_BUDGET_S = 3.0
_GRAPH_DESC_MAX = 300


async def _account_may_read_graph(user_id: str) -> bool:
    """Whether the account may read the knowledge graph at all.

    The operator's standing rule: a plain read-only (User-tier,
    scope ``read``) account gets NO graph reads. The gateway refuses its
    ``POST /api/v1/graph/*`` with a scope 403, EXCEPT that an account holding
    the additive ``graph`` scope (``read`` + ``graph``) may call the six
    explicit audience-scoped query routes (classify-intent, explain-path,
    navigate, search-clusters, semantic-search, traverse). The injected
    context deliberately stays the more conservative of the two: it is gated
    on ``write``/``admin`` only, so ``graph`` does NOT open it. The coordinator forwards only a
    ``user_id`` (no role), so the worker asks the account row — the same
    ``noo_users.scopes`` the gateway's tokens are minted from — and applies the
    gateway's own derivation (``Role::from_scopes``: ``write``/``admin`` =
    Operator or above, anything else = User). Unknown = refused (fail closed).
    """
    try:
        from sqlalchemy import text as _sql_text

        store = _get_conversation_store()
        if store is None or not hasattr(store, "_engine"):
            return False
        async with store._engine.connect() as conn:
            row = (await conn.execute(
                _sql_text("SELECT scopes FROM noo_users WHERE username = :u AND disabled = false"),
                {"u": user_id},
            )).first()
    except Exception as e:  # noqa: BLE001 - cannot establish the role -> deny
        log.warning("rag_context_graph_role_lookup_failed", error=str(e))
        return False
    if row is None:
        return False
    scopes = row[0] or []
    return any(str(x) in ("write", "admin") for x in scopes)


async def _readable_ids(rag: Any, audience_mod: Any, roles: Any, *, docs: set, entities: set) -> tuple[set, set]:
    """(readable doc ids, entity ids with a mention on a readable document).

    The audience predicate is trellion's own (``audience_mod.ROLES_WHERE``,
    the same one the scoped store walks with). Raises on any DB problem; the
    caller treats that as "nothing is provably readable".
    """
    from sqlalchemy import text as _sql_text

    engine = rag.store._engine
    where = audience_mod.ROLES_WHERE
    ok_docs: set = set()
    ok_ents: set = set()
    async with engine.connect() as conn:
        if docs:
            res = await conn.execute(
                _sql_text(f"SELECT d.doc_id::text FROM docs d WHERE d.doc_id::text = ANY(CAST(:ids AS text[])) AND {where}"),
                {"ids": sorted(docs), "roles": list(roles)},
            )
            ok_docs = {str(r[0]) for r in res.fetchall()}
        if entities:
            res = await conn.execute(
                _sql_text(
                    "SELECT DISTINCT m.entity_id::text FROM mentions m "
                    "JOIN pages p ON p.page_id = m.page_id JOIN docs d ON d.doc_id = p.doc_id "
                    f"WHERE m.entity_id::text = ANY(CAST(:ids AS text[])) AND {where}"
                ),
                {"ids": sorted(entities), "roles": list(roles)},
            )
            ok_ents = {str(r[0]) for r in res.fetchall()}
    return ok_docs, ok_ents


def _edge_doc_ids(edge: Any) -> set | None:
    """The source documents of an edge whose provenance is COMPLETE, else None.

    trellion records, per edge, the document that created it (``evidence.doc_id``)
    and — once the same triple is seen again — overwrites ``reinforced_at`` and
    ``last_evidence`` on every further sighting. It stores NO count of
    sightings (``confidence`` starts at its 1.0 default and clamps there, so it
    is no counter either). A reinforced edge may therefore have been seen
    readable -> private -> readable: the middle document is gone, yet its
    sighting moved the edge's confidence and refreshed its age. The only edge
    whose sources are provably all recorded is one that was never reinforced:
    one sighting, one recorded document. Everything else (reinforced, or with
    no ``doc_id``) returns None and is never shown to a restricted caller.
    the design asks trellion to record full per-edge provenance so this can
    loosen.
    """
    ev = edge.get("evidence") if isinstance(edge, dict) else None
    if isinstance(ev, str):
        try:
            import json as _json

            ev = _json.loads(ev)
        except ValueError:
            ev = None
    if not isinstance(ev, dict) or not ev.get("doc_id"):
        return None
    if "reinforced_at" in ev or "last_evidence" in ev:
        return None
    return {str(ev["doc_id"])}


async def _graph_context_for(
    rag: Any, question: str, roles: Any, user_id: str | None = None
) -> tuple[dict | None, str | None]:
    """(graph_context, error) for the injected context. Never raises.

    * Base tier (no ``navigator`` on the RAG object — the Intelligent tier is
      not installed): ``(None, None)``. Not an error; the fields are omitted.
    * Read-only account: ``(None, "graph_role_refused")`` before anything is
      walked (operator rule: no graph reads for the User tier).
    * With the navigator role present: its seeds and top relationships,
      bounded and confidence-ordered. A restricted caller (``roles`` is a
      list) only ever sees entities and edges derived from documents it can
      read: the worker re-checks provenance before anything is returned. If
      the audience filter cannot be confirmed, the graph part is refused
      (``graph_error``) rather than served on trust.
    * Timeout / exception: ``(None, "<reason>")`` so the pages still return
      and the missing graph is visible. ``graph_error`` is for logs and
      operators; the gateway never prints it.
    """
    nav = getattr(rag, "navigator", None)
    if nav is None or not question:
        return None, None
    if user_id is not None and not await _account_may_read_graph(user_id):
        log.info("rag_context_graph_role_refused", user=user_id)
        return None, "graph_role_refused"
    try:
        extra: dict = {}
        audience_mod = None
        if roles is not None:
            from .graph import _intel_audience

            audience_mod, err = _intel_audience("navigate")
            if err:
                return None, "graph_audience_unconfirmed"
            extra = {"roles": roles}
        started = asyncio.get_running_loop().time()
        result = await asyncio.wait_for(
            nav.navigate(query=question, max_hops=1, **extra),
            timeout=GRAPH_BUDGET_S,
        )
        hyps_in = list(getattr(result, "hypotheses", None) or [])
        seeds_in = [e for e in (getattr(result, "seed_entities", None) or []) if isinstance(e, dict)]
        if roles is not None:
            docs: set = set()
            for h in hyps_in:
                for edge in getattr(h, "edges", None) or []:
                    docs |= _edge_doc_ids(edge) or set()
            ents = {str(e["entity_id"]) for e in seeds_in if e.get("entity_id")}
            ok_docs, ok_ents = await asyncio.wait_for(
                _readable_ids(rag, audience_mod, roles, docs=docs, entities=ents),
                # one budget for walk + re-check, not two
                timeout=max(0.1, GRAPH_BUDGET_S - (asyncio.get_running_loop().time() - started)),
            )
            seeds_in = [e for e in seeds_in if str(e.get("entity_id")) in ok_ents]

            def _provable(h: Any) -> bool:
                edges = getattr(h, "edges", None) or []
                if not edges:
                    return False
                for edge in edges:
                    ids = _edge_doc_ids(edge)
                    if not ids or not ids <= ok_docs:
                        return False
                return True

            hyps_in = [h for h in hyps_in if _provable(h)]
    except asyncio.TimeoutError:
        log.warning("rag_context_graph_timeout", timeout_s=GRAPH_BUDGET_S)
        return None, "graph_timeout"
    except asyncio.CancelledError:
        raise
    except Exception as e:  # noqa: BLE001 - the graph must never cost the pages
        log.warning("rag_context_graph_failed", error=str(e))
        return None, f"graph_failed: {type(e).__name__}"[:120]

    def _conf(h: Any) -> float:
        try:
            return float(getattr(h, "confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            return 0.0

    hyps = sorted(hyps_in, key=_conf, reverse=True)
    hypotheses = [
        {"description": str(h.description)[:_GRAPH_DESC_MAX], "confidence": _conf(h)}
        for h in hyps
        if getattr(h, "description", "")
    ][:GRAPH_MAX_HYPOTHESES]
    seeds = [
        {"canonical_name": str(e["canonical_name"])}
        for e in seeds_in
        if e.get("canonical_name")
    ][:GRAPH_MAX_SEEDS]
    if not hypotheses and not seeds:
        return None, None
    return {"hypotheses": hypotheses, "seed_entities": seeds}, None


#: The tiers a shared room (group chat / space) may draw on: shared knowledge only.
SHARED_ROOM_ROLES = ("company", "system")


@worker_handler("worker.rag.context")
async def _rag_context(request: dict) -> Any:
    """Lightweight retrieval-only RAG for context injection (no LLM synthesis).

    Returns relevant document chunks + citations + graph context without
    generating an LLM answer. Completes in ~5s vs ~120s for full query.
    Used by the Rust coordinator's fetch_rag_context() for system prompt injection.
    """
    rag = _get_rag()
    if not rag or not rag._started:
        # Envelope kept (the Rust coordinator reads data.answer / .citations
        # and would panic on nothing else), but an explicit `error` is added
        # everywhere this path fails. This runs on EVERY prompt: previously a
        # dead/unstarted KB returned exactly the same {"answer": "",
        # "citations": []} as "nothing relevant matched", so a broken RAG
        # silently degraded every answer with no signal anywhere.
        return {"answer": "", "citations": [],
                "error": "rag_not_started"}

    question = request.get("question", "")
    top_k = request.get("top_k", 5)

    # KB audience scoping for the AUTO-INJECTED context path. This runs on
    # every prompt, so an unscoped retrieve() leaks the whole corpus into the
    # system prompt regardless of who is asking — which is what the old
    # NOO_MULTI_USER default did. The Rust coordinator forwards the
    # authenticated `user_id`; when it does not, `resolve_scope_user` fills
    # the gap from the account table (sole account = that account) and
    # otherwise says fail CLOSED, i.e. inject nothing. Either way we end up
    # scoped to a real identity's own + shared tiers, reusing the same policy
    # as worker.rag.query via a synthetic read-scope requester.
    # `tenant_of` reads the SIGNED principal first and only falls back to
    # the payload for an internal loop acting for somebody;
    # `resolve_scope_user` then fills a genuinely absent identity from the
    # account table, or fails closed.
    user_id = await resolve_scope_user(
        (bus_principal.tenant_of(request) or "").strip() or None,
        denial_event="rag_context_skipped_no_identity",
    )
    if not user_id:
        # Deliberate policy skip, not a failure — but still distinguishable
        # from a genuine empty retrieval.
        return {"answer": "", "citations": [],
                "skipped": "no_identity"}
    grants = (await _kb_grants_map()).get(user_id)
    # The synthetic read-scope requester is handed to `_resolve_kb_roles` as a
    # PRINCIPAL, not as a body claim, because that resolver stopped reading
    # bodies and refuses a read it cannot attribute.
    #
    # This read IS attributed: `user_id` above is either the identity the bus
    # authenticated or, failing that, the sole account — and if it were
    # neither we returned `no_identity` several lines ago. So the synthetic
    # principal states a fact that has already been established rather than
    # laundering an unattributed read into an attributed one.
    #
    # It is deliberately a `user` principal with `read` and nothing else: this
    # is the auto-injected context path, it runs on every prompt, and it must
    # never be the widest caller in the system. The verified principal from
    # the header, if any, is NOT used here — an internal loop carrying
    # `kb:unrestricted` must not make an end-user's injected context
    # corpus-wide.
    resolve_params: dict = {
        "_requester": {"sub": user_id, "scopes": ["read"]},
        bus_principal.PRINCIPAL_KEY: bus_principal.Principal(
            sub=user_id, kind="user", role="user", scopes=["read"]
        ),
    }
    if request.get("shared_room") is True:
        # A turn in a group chat or shared space: the reply is posted to the
        # whole room, so it may only draw on what the whole room may read.
        # The gateway sets this flag; it can only NARROW (an explicit `roles`
        # is clamped to the caller's own set by the resolver), so a forged
        # flag costs the forger context, never gains any. Own-user tier,
        # granted team tiers and the legacy tiers are dropped.
        resolve_params["roles"] = list(SHARED_ROOM_ROLES)
    roles = _resolve_kb_roles(resolve_params, grants=grants)

    try:
        # Use retriever.retrieve() — does embed → pages → chunks → evidence
        # without the LLM synthesis step that makes rag.query() slow
        retriever = getattr(rag, "retriever", None) or getattr(rag.orchestrator, "retriever", None)
        if not retriever:
            return {"answer": "", "citations": [],
                    "error": "rag_retriever_unavailable"}

        # The graph walk starts now and overlaps retrieval (own short budget).
        graph_task = asyncio.ensure_future(_graph_context_for(rag, question, roles, user_id))
        try:
            evidence_packs = await asyncio.wait_for(
                retriever.retrieve(question, top_k=top_k, roles=roles),
                timeout=15.0,
            )
        except BaseException:
            graph_task.cancel()
            raise
        if not evidence_packs:
            graph_task.cancel()
            return {"answer": "", "citations": []}

        # Build context from evidence packs (no LLM synthesis)
        answer_parts = []
        citations = []
        for pack in evidence_packs[:top_k]:
            text = getattr(pack, "text", "") or getattr(pack, "snippet", "") or str(pack)
            if text:
                answer_parts.append(str(text)[:500])
            title = getattr(pack, "title", None) or getattr(pack, "doc_title", None)
            if title:
                citations.append({"title": str(title)})

        answer = "\n---\n".join(answer_parts)
        reply: dict = {"answer": answer, "citations": citations}
        graph, graph_err = await graph_task
        if graph:
            reply[GRAPH_CONTEXT_KEY] = graph
        if graph_err:
            reply[GRAPH_ERROR_KEY] = graph_err
        return reply
    except asyncio.TimeoutError:
        # Was: identical to "nothing relevant" — a 15s retrieval timeout was
        # invisible to the caller and to the logs at info level.
        log.warning("rag_context_retrieval_timeout", timeout_s=15.0)
        return {"answer": "", "citations": [],
                "error": "rag_retrieval_timeout"}
    except Exception as e:
        # Was: identical to "nothing relevant".
        log.warning("rag_context_retrieval_failed", error=str(e))
        return {"answer": "", "citations": [],
                "error": f"rag_retrieval_failed: {type(e).__name__}: {e}"[:300]}


@worker_handler("worker.rag.ingest")
async def _rag_ingest(request: dict) -> Any:
    """Handle document ingestion delegation."""
    rag = _get_rag()
    if not rag:
        raise RuntimeError("RAG not started")
    params = request.get("params", request)
    source = params.get("source", "")
    text = params.get("text", "")
    title = params.get("title", "") or "Untitled"
    # Optional explicit source_uri — used by the ingest loop so a Drive
    # file can be tagged "gdrive://<file_id>" instead of the working-dir
    # path it was downloaded to. Falls back to PageIndexRAG.ingest()'s
    # default (file path → source_uri) when omitted.
    source_uri = params.get("source_uri")
    # Optional structured metadata (folder_path, drive_id, tags, etc.)
    # stored on the docs row for future narrowers. Merged on dedup hits.
    metadata = params.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        raise ValueError("metadata must be a JSON object")
    # `ingest` and `audience_history` are written by the system (kb_trace);
    # a caller-supplied value would forge the trail an operator reviews.
    if metadata:
        metadata = {k: v for k, v in metadata.items() if k not in kb_trace.RESERVED_METADATA_KEYS}
    # KB role tagging: roles=["system"] etc. lands in metadata.roles.
    # Read-scope requesters may only tag into their own tier.
    roles = params.get("roles")
    if isinstance(roles, str):
        roles = [roles]
    requester = params.get("_requester") or {}
    uploader = str(requester.get("sub") or "").strip()
    if not roles:
        # ── The audience rule: a document ALWAYS has an audience ──────────
        # Order, first that applies wins:
        #   1. explicit `roles` from the caller (clamped below) — the only
        #      way an upload is shared with a team (`team:<name>`) or the
        #      org (`company`);
        #   2. a known uploader — admin or not, CLI login or console session
        #      — gets `user:<account sub>`. An upload is the uploader's own
        #      until they say otherwise: neither a source rule nor
        #      kb.default_roles widens it;
        #   3. NO uploader identity (cluster HMAC, watched folders, the
        #      Drive loop, internal/heartbeat ingests): a source rule
        #      (DB-backed noo_kb_source_rules, then kb.source_roles), else
        #      kb.default_roles, else the explicit `admin` tag.
        # An untagged document used to be the "admin only" case. That was an
        # accident of the read filter, not a stated audience, and it is not
        # something a retag or a query can see or name. `admin` is explicit.
        # Whatever happens next, empty roles never reach rag.ingest (below).
        if uploader:
            roles = [f"user:{uploader}"]
        else:
            from ..gateway.kb_roles import default_roles, resolve_source_roles
            roles = resolve_source_roles(
                source_uri, source, extra_rules=await _kb_source_rules(),
                include_default=False,
            ) or default_roles() or ["admin"]
    # Clamp to what this caller may actually tag. Admin / no requester
    # (cluster HMAC) is unrestricted (`allowed is None`) and keeps the
    # default chosen above.
    allowed = _writable_kb_roles(
        requester,
        (await _kb_grants_map()).get(uploader) if requester else None,
    )
    if allowed is not None:
        clamped = [r for r in roles if r in allowed]
        # Falling back to the personal tier rather than dropping the
        # document: a caller who asks for an audience they do not hold
        # (`admin`, `system`, someone else's `user:*`) still gets their
        # upload stored, just not published wider than they are entitled to.
        roles = clamped or ([f"user:{uploader}"] if uploader else [])
    if not roles:
        raise ValueError(
            "ingest has no audience: refusing to store an untagged document"
        )
    metadata = dict(metadata or {})
    # Decide what this is BEFORE trellion sees it: PageIndexRAG.ingest opens
    # any string that names an existing file, so a source outside the
    # declared roots (or text that spells a path) must never reach it.
    # Raises ValueError (the contract for a bad request) with the fix named.
    try:
        target = ingest_confine.classify(source, text)
    except ingest_confine.IngestRefused as e:
        log.warning("rag_ingest_refused", reason=str(e)[:200])
        raise
    # An ingest never changes an existing document's audience; only a retag
    # does. Trellion merges a dedup hit's metadata over the
    # existing row (new keys win), so `roles` is NOT passed to rag.ingest:
    # kb_ingest_roles.settle_roles writes it onto a row this call created.
    # A store with no database handle (a test double) keeps the in-metadata path.
    store = getattr(rag, "store", None)
    settle = kb_ingest_roles.has_engine(store)
    started = None
    if settle:
        started = await kb_ingest_roles.db_clock(store)
        if started is None:
            raise RuntimeError("cannot read the database clock; refusing an ingest it cannot settle")
    else:
        metadata["roles"] = list(roles)
    doc_id = await _store_document(
        rag, target, title=title, source_uri=source_uri, metadata=metadata,
    )
    outcome = (
        await kb_ingest_roles.settle_roles(store, str(doc_id), roles, started) if settle else "created"
    )
    if outcome == "created" and settle:
        # Provenance: who ingested this and by which path,
        # written once onto the row this call CREATED. A dedup hit keeps the
        # first ingest's. Read from the request; see kb_trace.ingest_via.
        await kb_trace.record_ingest(
            store, str(doc_id),
            kb_trace.ingest_block(requester, uploader, source_uri, params.get("metadata")),
        )
    out = {"doc_id": str(doc_id), "message": f"Ingested as '{title}'", "title": title}
    if outcome == "existing" and _may_see_existing(requester, allowed):
        # Operator/admin only: "identical content is already stored" is a
        # confirmation oracle, so a restricted caller gets the plain shape.
        out.update(
            existing=True,
            audience_unchanged=True,
            message=f"'{title}' is already in the knowledge base; its audience is unchanged",
        )
    return out


async def _store_document(rag: Any, target: Any, *, title: str, source_uri: Any, metadata: dict) -> Any:
    """Hand a classified document to trellion by the explicit entry point.

    Text goes to ``ingest_text`` and a vetted file to ``ingest_file``, so
    trellion never has to guess (and cannot guess a path out of text). A
    rag object without the explicit entry points (a test double) gets
    ``ingest`` -- but never text that ``ingest`` would open as a file.
    """
    ingestor = getattr(rag, "ingestor", None)
    if target.kind == "file":
        from pathlib import Path
        if ingestor is not None and hasattr(ingestor, "ingest_file"):
            return await ingestor.ingest_file(
                Path(target.value), title=title, source_uri=source_uri, metadata=metadata,
            )
    else:
        if ingestor is not None and hasattr(ingestor, "ingest_text"):
            return await ingestor.ingest_text(
                text=target.value, title=title, source_uri=source_uri or "", metadata=metadata,
            )
        if ingest_confine.text_would_be_read_as_path(target.value):
            raise ValueError(
                "refusing text that names a file on the worker: this RAG backend "
                "cannot store it without opening that file"
            )
    return await rag.ingest(
        target.value, title=title, source_uri=source_uri, metadata=metadata,
    )


def _may_see_existing(requester: dict, allowed: Any) -> bool:
    """Operator/admin, or an internal caller (no requester, unrestricted)."""
    if not requester:
        return True
    return allowed is None or str(requester.get("role") or "") in ("operator", "admin")


# ═══════════════════════════════════════════════════════════════════════
# Graph handlers
# ═══════════════════════════════════════════════════════════════════════

EMPTY_AUDIENCE_MSG = (
    "a document always has an audience; to make one admin-only use --role admin"
)


@worker_handler("worker.rag.retag")
async def _rag_retag(request: dict) -> Any:
    """POST /api/v1/rag/retag — change which audience documents belong to.

    Roles were written once, at ingest, and never again. That made one empty
    config value permanent: with ``kb.default_roles`` unset, every document
    from an unmatched source was stored untagged, and an untagged document
    overlaps no audience — so only an unrestricted caller could ever see it.

    Two things this is NOT:

    - Not backfill-only. ``only_untagged=false`` relabels documents that
      already carry an audience, because a source rule changing is a normal
      event and "these went to the wrong team" has to be fixable.
    - Not automatic. ``apply`` defaults false and the call returns exactly
      what it WOULD change. Retagging moves documents between audiences,
      which is an access-control change; it does not happen because someone
      typed a glob slightly wrong.

    Authorization is the ingest rule, reused rather than restated: a caller
    may only tag into an audience it could write to itself
    (:func:`_writable_kb_roles`). An operator cannot publish somebody's
    private documents into a team they do not belong to.
    """
    rag = _get_rag()
    if not rag or not rag.store:
        return {"error": "RAG not initialized"}

    roles = request.get("roles")
    if isinstance(roles, str):
        roles = [roles]
    if roles is None:
        return {"error": EMPTY_AUDIENCE_MSG}
    if not isinstance(roles, list) or any(not isinstance(r, str) for r in roles):
        return {"error": "roles must be a list of strings"}
    roles = [r.strip() for r in roles if r.strip()]
    if not roles:
        # A document ALWAYS has an audience (the ingest rule). Clearing one
        # used to be allowed, which made the document untagged again: the
        # state the design removed, readable by no one but an admin by
        # accident of the read filter rather than by a stated audience.
        return {"error": EMPTY_AUDIENCE_MSG}

    match = request.get("match")
    doc_ids = request.get("doc_ids") or None
    if not match and not doc_ids:
        # Refusing the empty selector on purpose. "Everything" is a
        # defensible thing to ask for, but never by omission.
        return {"error": "give `match` (a glob on source_uri) or `doc_ids`"}

    grants = (await _kb_grants_map()).get(
        str((request.get("_requester") or {}).get("sub") or "")
    )
    allowed = _writable_kb_roles(request.get("_requester") or {}, grants)
    if allowed is not None:
        refused = [r for r in roles if r not in allowed]
        if refused:
            # Named, not silently dropped: a caller who asked for an
            # audience they do not hold has made a mistake worth seeing.
            return {
                "error": (
                    f"not yours to tag into: {sorted(refused)} — "
                    f"you may tag into {sorted(allowed)}"
                )
            }

    only_untagged = request.get("only_untagged")
    only_untagged = True if only_untagged is None else bool(only_untagged)

    # fnmatch-style glob in, SQL LIKE out. The caller writes `gdrive://*`
    # because that is what `kb.source_roles` takes, and the two must not
    # drift into different dialects for the same job.
    uri_pattern = None
    if match:
        uri_pattern = str(match).replace("\\", "\\\\").replace("%", "\\%")
        uri_pattern = uri_pattern.replace("_", "\\_").replace("*", "%").replace("?", "_")

    try:
        candidates = await rag.store.select_docs_for_retag(
            uri_pattern=uri_pattern,
            doc_ids=list(doc_ids) if doc_ids else None,
            only_untagged=only_untagged,
            limit=int(request.get("limit") or 1000),
        )
    except Exception as e:  # noqa: BLE001
        return {"error": f"retag preview failed: {e}"}

    preview = [
        {
            "doc_id": d["doc_id"],
            "title": d["title"],
            "source_uri": d["source_uri"],
            "from": d["roles"],
            "to": list(roles),
        }
        for d in candidates
    ]

    if not request.get("apply"):
        return {
            "status": "dry-run",
            "matched": len(candidates),
            "applied": 0,
            "roles": list(roles),
            "only_untagged": only_untagged,
            "documents": preview[:50],
            "message": (
                f"{len(candidates)} document(s) would be retagged. "
                "Re-run with apply=true to write."
            ),
        }

    try:
        changed = await rag.store.set_doc_roles([d["doc_id"] for d in candidates], roles)
    except Exception as e:  # noqa: BLE001
        return {"error": f"retag failed: {e}"}

    # Who changed what. Only documents whose audience actually
    # differs are recorded. The roles ARE written by now, so a failure here is
    # reported alongside the success rather than turned into an error.
    by = str((request.get("_requester") or {}).get("sub") or "") or "cluster"
    target = sorted(set(roles))
    history_error = await kb_trace.record_retag(
        rag.store,
        [
            {"doc_id": d["doc_id"], "from": d["roles"], "to": list(roles)}
            for d in candidates
            if sorted(set(d["roles"])) != target
        ],
        by,
    )

    log.info(
        "kb.retag",
        matched=len(candidates),
        applied=changed,
        roles=roles,
        only_untagged=only_untagged,
        requester=by,
    )
    out = {
        "status": "ok",
        "matched": len(candidates),
        "applied": changed,
        "roles": list(roles),
        "only_untagged": only_untagged,
        "documents": preview[:50],
    }
    if history_error:
        out["warning"] = history_error
    return out


# ═══════════════════════════════════════════════════════════════════════
# Document hold (worker.rag.hold / unhold / held / purge)
# ═══════════════════════════════════════════════════════════════════════
#
# A held document is KEPT (row, pages, chunks, ids) but is not embedded, not
# searched and not counted as unembedded. Nothing is deleted by a hold; purge
# is a separate, explicit act on documents already held under one reason.
# The gateway gates these to the Operator tier (and audits the applied
# ones); the store is trellion's (`PageIndexStore.hold_docs` and friends).

HOLD_SKEW_MSG = (
    "this trellion does not support document hold yet; roll trellion first "
    "(its migration 105 adds docs.held_at)"
)


def _hold_error(what: str, e: Exception) -> str:
    """A database that has not had trellion's migration 105 yet fails with an
    undefined `held_at` / `hold_reason` column: say what to do, not the SQL."""
    text = str(e)
    if "held_at" in text or "hold_reason" in text:
        return HOLD_SKEW_MSG
    return f"{what} failed: {e}"


def _hold_selector(request: dict):
    """(title_prefix, doc_ids) with exactly one set, or an error string."""
    prefix = request.get("title_prefix")
    ids = request.get("doc_ids") or None
    if isinstance(prefix, str) and not prefix:
        prefix = None
    if prefix and ids:
        return None, None, "give title_prefix or doc_ids, not both"
    if not prefix and not ids:
        return None, None, "give `title_prefix` or `doc_ids`; an empty selector is refused"
    if ids is not None and (
        not isinstance(ids, list) or any(not isinstance(i, str) for i in ids)
    ):
        return None, None, "doc_ids must be a list of strings"
    return prefix, (list(ids) if ids else None), None


def _hold_reason(request: dict):
    reason = request.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        return None, "a hold needs a non-empty `reason`"
    return reason.strip(), None


async def _hold_call(request: dict, op: str) -> Any:
    rag = _get_rag()
    if not rag or not rag.store:
        return {"error": "RAG not initialized"}
    prefix, ids, err = _hold_selector(request)
    if err:
        return {"error": err}
    apply = bool(request.get("apply"))  # default: dry run
    try:
        if op == "hold":
            reason, err = _hold_reason(request)
            if err:
                return {"error": err}
            out = await rag.store.hold_docs(
                title_prefix=prefix, doc_ids=ids, reason=reason, apply=apply
            )
        else:
            out = await rag.store.unhold_docs(title_prefix=prefix, doc_ids=ids, apply=apply)
    except AttributeError:
        return {"error": HOLD_SKEW_MSG}
    except ValueError as e:
        return {"error": str(e)}
    except Exception as e:  # noqa: BLE001
        return {"error": _hold_error(op, e)}
    verb = op if apply else f"would {op}"
    log.info(f"kb.{op}", count=out["count"], applied=apply)
    return {
        "status": "ok" if apply else "dry-run",
        "count": out["count"],
        "applied": out["count"] if apply else 0,
        # A bus reply is size-capped and a hold can match tens of thousands
        # of documents: the first 50 ride along, `held` pages the rest.
        "doc_ids": out["doc_ids"][:50],
        "message": (
            f"{out['count']} document(s) {op} (held)." if apply and op == "hold"
            else f"{out['count']} document(s) released." if apply
            else f"Nothing changed: {out['count']} document(s) {verb}. "
                 "Re-run with apply=true to write."
        ),
    }


@worker_handler("worker.rag.hold")
async def _rag_hold(request: dict) -> Any:
    """POST /api/v1/docs/hold — keep documents, out of embedding and search."""
    return await _hold_call(request, "hold")


@worker_handler("worker.rag.unhold")
async def _rag_unhold(request: dict) -> Any:
    """POST /api/v1/docs/unhold — make held documents eligible again."""
    return await _hold_call(request, "unhold")


@worker_handler("worker.rag.held")
async def _rag_held(request: dict) -> Any:
    """GET /api/v1/docs/held — held documents, paged (id, title, reason, held_at)."""
    rag = _get_rag()
    if not rag or not rag.store:
        return {"error": "RAG not initialized"}
    try:
        return await rag.store.list_held(
            reason=request.get("reason") or None,
            limit=int(request.get("limit") or 1000),
            offset=int(request.get("offset") or 0),
        )
    except AttributeError:
        return {"error": HOLD_SKEW_MSG}
    except Exception as e:  # noqa: BLE001
        return {"error": _hold_error("held listing", e)}


@worker_handler("worker.rag.purge")
async def _rag_purge(request: dict) -> Any:
    """POST /api/v1/docs/purge — DELETE the documents held under one reason.

    Irreversible. Only documents already held under exactly `reason` are
    touched; there is no "purge everything held". Dry run unless `apply`.
    """
    rag = _get_rag()
    if not rag or not rag.store:
        return {"error": "RAG not initialized"}
    reason = request.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        return {"error": "a purge needs the non-empty `reason` the documents are held under"}
    apply = bool(request.get("apply"))
    try:
        out = await rag.store.purge_held(reason=reason.strip(), apply=apply)
    except AttributeError:
        return {"error": HOLD_SKEW_MSG}
    except ValueError as e:
        return {"error": str(e)}
    except Exception as e:  # noqa: BLE001
        return {"error": _hold_error("purge", e)}
    log.info("kb.purge", count=out["count"], deleted=out["deleted"], applied=apply)
    return {
        "status": "ok" if apply else "dry-run",
        "count": out["count"],
        "deleted": out["deleted"],
        "doc_ids": out["doc_ids"][:50],
        "message": (
            f"{out['deleted']} document(s) deleted."
            if apply
            else f"Nothing changed: {out['count']} document(s) held under that reason "
                 "would be deleted. Re-run with apply=true to delete."
        ),
    }


@worker_handler("worker.rag.deduplicate")
async def _rag_deduplicate(request: dict) -> Any:
    """POST /api/v1/rag/deduplicate — page-level dedupe (worker.rag.deduplicate).

    The original endpoint died with the archived Python gateway;
    PageIndexStore.deduplicate_pages survived in trellion — re-exposed here.
    """
    rag = _get_rag()
    if not rag or not rag.store:
        return {"error": "RAG not initialized"}
    try:
        removed = await rag.store.deduplicate_pages()
        return {"status": "ok", "pages_removed": removed}
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════
# Junk-entity cleanup (worker.rag.entity_cleanup)
# ═══════════════════════════════════════════════════════════════════════
#
# ``trellion.live.junk_entity_cleanup`` (trellion #83) stages the junk
# entities already in the graph (``a``, ``x_t``, ``theta``, ``0.003``) into
# ``graph_prune_staging`` with reason ``junk_entity`` and deletes them, under
# graph prune's advisory lock and a 5,000-per-run cap. It was reachable only as
# ``docker exec noo-trellion trellion entity-cleanup``, which skips the
# gateway's authorisation and audit. This subject is the front door's way in:
# ``POST /api/v1/graph/entity-cleanup`` (admin only, an async op) -> here.
#
# Why ``worker.rag.*`` and not ``worker.graph.*``: the validator and the
# cleanup are in trellion's OPEN tree (``trellion.live``), so every install
# that has trellion can run it. ``worker.graph.*`` is the Intelligent tier's
# surface (``_ML_INTEL_MODULES``) and would put this behind a licence it does
# not need, on a container that has no business serving it.

ENTITY_CLEANUP_MAX_DELETE = 5000
ENTITY_CLEANUP_MAX_EXAMPLES = 200

ENTITY_CLEANUP_UPGRADE_MSG = (
    "this trellion build has no entity cleanup (trellion.live.junk_entity_cleanup); "
    "upgrade the trellion image, then retry"
)


def _bounded_int(value: Any, default: int, lo: int, hi: int) -> int | None:
    """``value`` as an int in ``[lo, hi]``; ``default`` when absent; None when
    present and unusable (a bool is not a count)."""
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if lo <= value <= hi else None


def _entity_cleanup_payload(report: Any, examples: int) -> dict:
    """The cleanup report as JSON: counts, the examples, the run id.

    The examples are the only place an entity NAME appears; the gateway keeps
    them out of its audit row.
    """
    cands = list(report.candidates)
    ranked = sorted(cands, key=lambda c: (-c.edges, c.name))[:examples]
    return {
        "status": "dry-run" if report.dry_run else "applied",
        "dry_run": bool(report.dry_run),
        "scanned": report.scanned,
        "junk": len(cands),
        "with_edges": sum(1 for c in cands if c.edges),
        "edge_rows": sum(c.edges for c in cands),
        "with_mentions": sum(1 for c in cands if c.mentions),
        "mention_rows": sum(c.mentions for c in cands),
        "in_clusters": sum(1 for c in cands if c.clusters),
        "cluster_rows": sum(c.clusters for c in cands),
        "by_reason": dict(report.by_reason()),
        "by_type": dict(report.by_type()),
        "examples": [
            {
                "name": c.name,
                "type": c.etype,
                "reason": c.reason,
                "edges": c.edges,
                "mentions": c.mentions,
                "clusters": c.clusters,
            }
            for c in ranked
        ],
        "staged": report.staged,
        "skipped_over_cap": report.skipped_over_cap,
        "run_id": None if report.dry_run else report.run_id,
    }


async def _staging_schema(engine: Any) -> str:
    """The schema holding the ``graph_prune_staging`` the GATEWAY reads:
    ``mesh`` in the cluster layout, ``public`` on an install that predates the
    layout move. ``""`` when neither has it.

    ONLY those two, in the gateway's own search_path order (its pool runs
    ``mesh,public,…``), because ``GET /api/v1/graph/prune/staged`` and
    ``POST /api/v1/graph/prune/restore`` read through that path. Staging into a
    table the gateway does not read (a stray ``trellion.graph_prune_staging``
    the engine's own path would find) would delete entities whose 30-day undo
    nothing can find, so the engine's path is never consulted; no table in
    ``mesh`` or ``public`` means refuse, nothing deleted. Never from the request.
    ``to_regclass`` needs no privilege beyond USAGE on the schema.
    """
    from sqlalchemy import text

    async with engine.connect() as conn:
        for schema in ("mesh", "public"):
            found = (await conn.execute(
                text("SELECT to_regclass(:n) IS NOT NULL"), {"n": f"{schema}.graph_prune_staging"})).scalar()
            if found:
                return schema
    return ""


@worker_handler("worker.rag.entity_cleanup")
async def _rag_entity_cleanup(request: dict) -> Any:
    """POST /api/v1/graph/entity-cleanup — preview or apply the junk-entity cleanup.

    A DRY RUN unless ``apply`` is the boolean ``True``: the default pass only
    SELECTs. Applying stages every junk entity into ``graph_prune_staging``
    (restorable with ``POST /api/v1/graph/prune/restore`` for the staging
    retention window) and deletes it, at most ``max_delete`` per run.

    The engine is THIS worker's store engine and nothing the request says: the
    only fields read are ``apply``, ``examples`` and ``max_delete``. Admin only
    at the gateway; the same is re-checked here against ``_requester`` so a
    caller that reached the subject some other way is still refused.
    """
    # The gateway attaches the caller to every request it sends (and refuses to
    # send this one for anyone but an admin account). A request with NO caller,
    # or one that is not an admin, did not come through the front door: refuse.
    requester = request.get("_requester")
    if not isinstance(requester, dict) or requester.get("role") != "admin":
        return {"error": "the junk-entity cleanup needs the admin role"}

    apply = request.get("apply")
    if apply is not None and not isinstance(apply, bool):
        return {"error": "apply must be true or false"}
    apply = apply is True
    examples = _bounded_int(request.get("examples"), 20, 0, ENTITY_CLEANUP_MAX_EXAMPLES)
    max_delete = _bounded_int(request.get("max_delete"), ENTITY_CLEANUP_MAX_DELETE, 1, ENTITY_CLEANUP_MAX_DELETE)
    if examples is None:
        return {"error": f"examples must be an integer from 0 to {ENTITY_CLEANUP_MAX_EXAMPLES}"}
    if max_delete is None:
        return {"error": f"max_delete must be an integer from 1 to {ENTITY_CLEANUP_MAX_DELETE}"}

    # An older trellion build has no such module. Say so; do not crash on the
    # import. Only THIS module's absence reads as "upgrade": an ImportError from
    # inside it (a missing dependency) is a different fault and is reported as one.
    import importlib

    try:
        cleanup = importlib.import_module("trellion.live.junk_entity_cleanup")
    except ImportError as e:
        if getattr(e, "name", None) in ("trellion.live.junk_entity_cleanup", "trellion.live", "trellion"):
            return {"error": ENTITY_CLEANUP_UPGRADE_MSG}
        log.warning("entity_cleanup.import_failed", error_type=type(e).__name__, module=getattr(e, "name", None))
        return {"error": f"entity cleanup could not be loaded: {type(e).__name__}"}

    rag = _get_rag()
    engine = getattr(getattr(rag, "store", None), "_engine", None)
    if engine is None:
        return {"error": "RAG not initialized"}

    kwargs: dict = {}
    if apply:
        # WHERE the staging table is, not left to the engine's search_path. This
        # engine is trellion's store engine, pinned to ``trellion,public``; the
        # table is the gateway's, in ``mesh`` (followup: the first real apply
        # failed 42P01 and staged nothing). Qualified here, so no role's
        # search_path has to grow ``mesh``, and the grant the engine's role
        # already holds (INSERT on mesh.graph_prune_staging) is the only access used.
        import inspect

        if "staging_schema" not in inspect.signature(cleanup.run).parameters:
            return {"error": ENTITY_CLEANUP_UPGRADE_MSG}
        try:
            kwargs["staging_schema"] = await _staging_schema(engine)
        except Exception as e:  # noqa: BLE001
            log.warning("entity_cleanup.staging_lookup_failed", error_type=type(e).__name__)
            return {"error": f"entity cleanup could not locate the staging table ({type(e).__name__}); nothing was changed"}
        if kwargs["staging_schema"] == "":
            return {"error": "the prune staging table the gateway restores from (mesh.graph_prune_staging) "
                             "does not exist; nothing was changed"}

    try:
        report = await cleanup.run(engine, apply=apply, max_delete=max_delete, **kwargs)
    except Exception as e:  # noqa: BLE001
        # The exception text of a database error carries bound parameters,
        # which here are entity names. It goes to the log, not the reply.
        # NOT str(e) and NOT exc_info: a driver error carries the statement's bound
        # parameters, which here are entity names and the staging payload's mention
        # quote text, and the log goes to Loki. The class and the SQLSTATE say what
        # kind of failure it was.
        orig = getattr(e, "orig", None) or e
        sqlstate = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
        log.warning("entity_cleanup.failed", error_type=type(e).__name__, sqlstate=sqlstate)
        return {
            "error": f"entity cleanup failed ({type(e).__name__}); batches already committed are staged "
                     "and restorable, and a re-run continues; see the worker log"
        }

    if getattr(report, "lock_busy", False):
        return {
            "status": "busy",
            "error": "busy: graph prune (or another cleanup) holds the lock right now; nothing was changed",
        }
    out = _entity_cleanup_payload(report, examples)
    log.info(
        "entity_cleanup.done", dry_run=out["dry_run"], junk=out["junk"],
        staged=out["staged"], run_id=out["run_id"],
    )
    return out
