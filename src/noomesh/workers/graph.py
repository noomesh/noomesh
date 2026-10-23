# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Graph handlers (ported to Rust; kept as reference) + temporal-graph extraction (worker.temporal.extract).

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

from typing import Any

import structlog


from .audience import AUDIENCE_KEY, audience_of as _audience_of
from . import walks as _walks
from .common import _get_rag
from .registry import worker_handler

log = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# Temporal graph: conversation extraction (Phase 1, OSS-safe)
# ═══════════════════════════════════════════════════════════════════════

_temporal_extractor_cache: Any = None


def _get_temporal_extractor():
    """Lazy singleton for the conversation extractor (an add-on role).

    Reuses the PageIndexRAG store engine for the temporal graph.
    Returns None if RAG isn't ready yet (the temporal graph schema lives
    in the same Postgres, so the rag store engine is shared).
    """
    global _temporal_extractor_cache
    if _temporal_extractor_cache is not None:
        return _temporal_extractor_cache
    try:
        rag = _get_rag()
        if rag is None or not getattr(rag, "_started", False):
            return None
        from ..addon_roles import CONVERSATION_EXTRACTOR, TEMPORAL_GRAPH_STORE, provider
        graph_store_factory = provider(TEMPORAL_GRAPH_STORE)
        extractor_factory = provider(CONVERSATION_EXTRACTOR)
        engine = rag.store._engine  # PageIndexStore async engine
        graph = graph_store_factory(engine)
        # Through the gateway, as the `graph` purpose (i145): mesh-routed with
        # failover, and which model extracts is a preference in the DB. It
        # used to dial the controller's own vLLM directly (PAGEINDEX_LLM_URL
        # and VLLM_MODEL): one node, no fallback.
        from .. import llm_purposes
        from ..config import get_config
        tg_cfg = None
        try:
            tg_cfg = get_config().temporal_graph
        except Exception:
            pass
        extractor_kwargs: dict[str, Any] = {
            "graph_store": graph,
            "llm_url": llm_purposes.gateway_url(),
            "model": llm_purposes.GRAPH,
        }
        if tg_cfg is not None:
            extractor_kwargs.update(
                timeout_seconds=tg_cfg.extraction_timeout_seconds,
                max_message_chars=tg_cfg.max_message_chars,
                extracted_confidence_default=tg_cfg.extracted_confidence_default,
                min_confidence=tg_cfg.min_confidence,
            )
        _temporal_extractor_cache = extractor_factory(**extractor_kwargs)
        return _temporal_extractor_cache
    except Exception as e:
        log.debug("temporal_extractor.init_failed", error=str(e))
        return None


@worker_handler("worker.temporal.extract")
async def _temporal_extract(request: dict) -> Any:
    """Extract triples from a conversation message and write to temporal graph.

    Fire-and-forget from the Rust coordinator post-response. Request fields:
      - conversation_id (str)
      - entry_id        (str, optional — for provenance)
      - user_id         (str, optional)
      - author          ("user" | "assistant")
      - message_text    (str)
    """
    try:
        extractor = _get_temporal_extractor()
        if extractor is None:
            return {"success": True, "data": {"inserted": 0, "skipped": "extractor not ready"}}

        text = request.get("message_text", "")
        author = request.get("author", "user")
        conversation_id = request.get("conversation_id", "")
        entry_id = request.get("entry_id")
        user_id = request.get("user_id")

        if not text or not conversation_id:
            return {"success": True, "data": {"inserted": 0}}

        inserted = await extractor.extract_and_store(
            message_text=text,
            author=author,
            conversation_id=conversation_id,
            entry_id=entry_id,
            user_id=user_id,
        )
        return {"success": True, "data": {"inserted": inserted}}
    except Exception as e:
        log.debug("temporal_extract.failed", error=str(e))
        return {"success": True, "data": {"inserted": 0, "error": str(e)}}


# ═══════════════════════════════════════════════════════════════════════
# Community detection (worker.graph.recluster)
# ═══════════════════════════════════════════════════════════════════════
#
# The subject exists so clustering can be triggered on demand rather than only
# by a scheduled ``graph_clustering`` heartbeat action; otherwise
# ``/api/v1/graph/clusters/overview`` is served, green, and empty on most
# installs.
#
# This module is ``_ML_INTEL_MODULES``: the clustering role is supplied by an
# add-on. When the role is absent, ``rag.clusterer`` is None and this subject
# must not be registered on the base ``ml`` surface, because that container
# could never satisfy it. The base tier still has a document graph; the
# structure over it (clusters, navigation, signals) is the add-on's. The
# gateway refuses this route before dispatch when the add-on is off, so the
# message is a tier message and not a NATS timeout.

# A plain flag, not an asyncio.Lock, and the difference is the whole point.
#
# The first version checked `lock.locked()` and then did `async with lock`.
# `worker_pool._handle_concurrent` dispatches every message as its own task,
# so two requests arriving before either acquired both saw "not locked", both
# fell through, and the second BLOCKED on the lock and then ran a complete
# second clustering pass — which is precisely the "two generations writing
# the same two tables" this guard exists to prevent, and which the docstring
# below claimed was impossible. Check-then-act with an await in between is
# not a guard.
#
# asyncio is cooperative: with no `await` between the test and the set, no
# other task can interleave, so a bare boolean IS atomic here and a lock is
# not needed. The timestamp is set and cleared with the flag for the same
# reason — clearing it separately let a concurrent caller see "in flight" with
# `started_at: null` and report a fourteen-minute run as "0s elapsed".
_recluster_running: bool = False
_recluster_started_at: float | None = None

_PRUNE_LOCK_SQL = "SELECT pg_try_advisory_lock(hashtext('noo:graph_prune')::bigint)"
_PRUNE_UNLOCK_SQL = "SELECT pg_advisory_unlock(hashtext('noo:graph_prune')::bigint)"


async def _take_prune_lock(rag: Any):
    """Take graph prune's advisory lock on its own connection.

    Returns the connection holding it, ``None`` when there is no store engine to
    lock through (clustering then runs as it always did), or ``False`` when
    another session holds the lock.
    """
    engine = getattr(getattr(rag, "store", None), "_engine", None)
    if engine is None:
        return None
    from sqlalchemy import text

    conn = await engine.connect()
    try:
        got = (await conn.execute(text(_PRUNE_LOCK_SQL))).scalar()
        await conn.commit()  # a session lock survives the commit; the transaction does not idle
    except Exception:
        await conn.close()
        raise
    if not got:
        await conn.close()
        return False
    return conn


async def _release_prune_lock(conn: Any) -> None:
    if not conn:
        return
    from sqlalchemy import text

    try:
        await conn.execute(text(_PRUNE_UNLOCK_SQL))
        await conn.commit()
    except Exception as e:  # noqa: BLE001
        log.warning("graph_recluster.unlock_failed", error_type=type(e).__name__)
    finally:
        await conn.close()  # closing the session drops the lock regardless


@worker_handler("worker.graph.recluster")
async def _graph_recluster(request: dict) -> Any:
    """POST /api/v1/graph/recluster — run community detection over the graph.

    Synchronous and slow: the clusterer role groups the whole graph and
    labels each cluster. Minutes on a real corpus. The gateway gives this subject a longer timeout than the
    rest for that reason.

    A second request while a run is in flight does NOT start another one.
    Two concurrent runs would write the same two tables from two generations
    and the loser's rows would survive as orphans — and, more practically, a
    caller whose NATS request timed out mid-run will retry, and the honest
    answer to that retry is "the thing you asked for is still happening",
    not a second copy of it. The run continues either way; only the reply
    differs.
    """
    global _recluster_running, _recluster_started_at
    import time

    def _in_flight() -> dict:
        started = _recluster_started_at
        return {
            "status": "already_running",
            "started_at": started,
            "elapsed_secs": round(time.time() - started, 1) if started else None,
            "message": "a clustering run is already in flight; this request started nothing",
        }

    if _recluster_running:
        return _in_flight()

    rag = _get_rag()
    if rag is None or getattr(rag, "clusterer", None) is None:
        # Not "zero clusters". The distinction matters: an operator reading
        # an empty graph needs to know whether the corpus is empty or the
        # clusterer is absent, and only this end can tell them.
        return {
            "error": "clusterer unavailable",
            "detail": "the graph clusterer is not constructed on this worker — "
                      "the ML surface (NOO_WORKER_SURFACES=ml, the noo-trellion "
                      "container) is where it lives",
        }

    min_cluster_size = int(request.get("min_cluster_size") or 3)
    resolution = float(request.get("resolution") or 1.0)

    # Claim the run. Re-checked because everything between the first check
    # and here is synchronous — but stating it once, next to the set, is what
    # keeps it true when someone later adds an `await` to the validation above.
    if _recluster_running:
        return _in_flight()
    # Claim the run FIRST, with no await since the check, then take the lock.
    _recluster_running = True
    _recluster_started_at = time.time()
    started = _recluster_started_at
    # The graph's maintenance lock: the SAME advisory lock graph_prune and the
    # junk-entity cleanup take. Clustering rewrites the cluster tables that a
    # cleanup's deletes cascade into, so the two must not overlap, and the
    # gateway's "is a recluster running" look cannot guarantee that (it is a
    # check, then an act). Taken on one dedicated connection for the whole run,
    # because the lock is session-scoped.
    lock_conn = None
    try:
        lock_conn = await _take_prune_lock(rag)
    except Exception as e:  # noqa: BLE001
        _recluster_running = False
        _recluster_started_at = None
        log.warning("graph_recluster.lock_failed", error_type=type(e).__name__)
        return {"error": f"could not take the graph lock ({type(e).__name__})"}
    if lock_conn is False:
        _recluster_running = False
        _recluster_started_at = None
        return {
            "status": "already_running",
            "started_at": None,
            "elapsed_secs": None,
            "message": "graph prune or a junk-entity cleanup holds the graph lock right now; "
                       "this request started nothing",
        }
    try:
        summary = await rag.clusterer.run_clustering(
            min_cluster_size=min_cluster_size,
            resolution=resolution,
        )
    except Exception as e:
        log.warning("graph_recluster.failed", error=str(e), exc_info=True)
        return {"error": str(e)}
    finally:
        elapsed = round(time.time() - started, 1)
        _recluster_running = False
        _recluster_started_at = None
        await _release_prune_lock(lock_conn)

    if isinstance(summary, dict) and summary.get("error"):
        # run_clustering returns {"error": ...} rather than raising when
        # networkx is missing. Pass it through as an error, not a summary
        # with zero clusters in it.
        return {"error": summary["error"], "clusters": summary.get("clusters", 0)}

    result = dict(summary or {})
    result["status"] = "ok"
    result["elapsed_secs"] = elapsed
    log.info("graph_recluster.done", **result)
    return result


# ═══════════════════════════════════════════════════════════════════════
# The Intelligent tier's graph surface (worker.graph.*)
# ═══════════════════════════════════════════════════════════════════════
#
# Request fields below match `mcp/tool_defs/graph.py` exactly: those
# definitions are the contract clients send against.
#
# Every handler follows the same three rules:
#   - the collaborator it needs is fetched from the live RAG object, never
#     constructed here — construction order and dependencies are trellion's;
#   - an absent collaborator is an ERROR, never an empty result. `[]` from a
#     graph search means "nothing matched", and answering that when the
#     navigator was never built is the empty-that-reads-as-small failure this
#     repo keeps paying for;
#   - the gateway refuses before dispatch when the add-on is off, so reaching
#     a handler at all means the tier is licensed. These messages are for a
#     licensed install where something is genuinely wrong.


# Collaborators that come from the OPEN tree. `embedder` is
# `PageIndexEmbedder` — it is not licensed, and telling an operator to check
# their entitlement when the real cause is that RAG has not finished starting
# would send them down the wrong path entirely.
_OPEN_COMPONENTS = {"embedder", "store", "graph_builder"}


# ── Audience ──────────────────────────────────────────
#
# A restricted caller is served these routes only if the build that answers
# them filters by audience, and the answer SAYS so. The gateway's rule is
# fail closed: a reply that does not carry ``audience_filtered: true`` is never
# forwarded to a restricted caller. That is what protects a restricted caller
# from skew: an older worker, or a worker over an older trellion-intel (which
# ignores or rejects ``roles``), simply cannot produce the flag.
#
# `roles` arrives from the gateway, which resolved it once (`worker.rag.audience`)
# and strips any client-supplied `roles` before it sets its own: absent = the
# caller is unrestricted, a list = the audience tags they may read. The worker
# does not re-derive it; it only refuses the one shape that cannot be right
# (a verified, non-privileged USER principal arriving with no audience).

def _intel_audience(op: str):
    """(audience scope, error): the provider, only if this build filters ``op``.

    An add-on that declares no audience scope (an older one) cannot confirm;
    a newer trellion that dropped the document predicate fails the provider's
    import. Both land here and neither produces the flag.
    """
    try:
        from ..addon_roles import AUDIENCE_SCOPE, provider

        mod = provider(AUDIENCE_SCOPE)
        supported = bool(mod.supports(op))
    except Exception as e:  # noqa: BLE001 - any failure to load = cannot confirm
        log.warning("graph.audience_unavailable", op=op, error=str(e))
        return None, {
            "error": "this graph capability is not audience-aware on this install "
                     "(the Intelligent tier is older than the worker); restricted callers are refused"
        }
    if not supported:
        return None, {"error": f"the Intelligent tier does not filter `{op}` by audience"}
    return mod, None


def _audience_op(op: str):
    """Wrap a graph handler: resolve the audience, confirm the capability, stamp the reply.

    The wrapped coroutine takes ``(request, roles, audience)``: ``roles`` None
    and ``audience`` None for an unrestricted caller (the original code path,
    nothing new passed anywhere); for a restricted one, the role list and the
    verified audience-scope provider. Every reply produced under a
    verified restricted call carries ``audience_filtered: true``; a refusal
    before that point does not, so the gateway drops it.
    """
    import functools

    def deco(fn):
        @functools.wraps(fn)
        async def handler(request: dict) -> Any:
            roles, err = _audience_of(request)
            if err:
                return err
            audience = None
            if roles is not None:
                audience, err = _intel_audience(op)
                if err:
                    return err
            out = await fn(request, roles, audience)
            if roles is not None and isinstance(out, dict):
                out[AUDIENCE_KEY] = True
            return out

        return handler

    return deco


def _intel_component(name: str):
    """(component, error) — the named collaborator off the live RAG object."""
    rag = _get_rag()
    if rag is None:
        return None, {"error": "RAG not initialized on this worker"}
    comp = getattr(rag, name, None)
    if comp is None:
        detail = (
            "this is an open-tier component, so an entitlement is not the "
            "cause — RAG is up but did not construct it; check the worker's "
            "startup log"
            if name in _OPEN_COMPONENTS else
            "the Intelligent tier is licensed but this collaborator was not "
            "constructed — check the Intelligent tier is importable in this "
            "container (NOO_WORKER_SURFACES=ml-intel)"
        )
        return None, {"error": f"{name} unavailable", "detail": detail}
    return comp, None


# ── Edge evidence for a restricted caller ──────────────
#
# `insert_edge` keeps ONE row per (src, rel, dst). A second sighting of the
# same triple overwrites ``evidence_json.last_evidence`` with a full Evidence
# dict (doc_id, page_id, page_no, a 200-character snippet), while the SQL
# scope (`scoped_edges`) checks only the FIRST sighting's ``doc_id``. So an
# edge that passes the scope can carry a private document's snippet and page
# ids, and `navigate` / `explain_path` return whole edges. The injected-context
# path closes this in `rag._graph_context_for`; these two routes close it here
# with the SAME helpers (`_edge_doc_ids`, `_readable_ids`), not a copy:
#
#   * an edge is kept only if its provenance is complete (never reinforced,
#     has a doc_id) AND that document is readable by the caller;
#   * a kept edge's evidence is cut to a whitelist: no snippet, page id, page
#     number, span or last_evidence ever reaches a restricted caller;
#   * a reasoning path or hypothesis containing a dropped edge is dropped as a
#     whole (a chain with a missing link is not the chain that was found).
#
# Unrestricted callers (operator/admin, ``roles is None``) are not touched.

_EDGE_EVIDENCE_KEEP = ("doc_id", "source_type", "confidence")


def _clean_edge(edge: dict) -> dict:
    """A copy of ``edge`` whose evidence is reduced to ``_EDGE_EVIDENCE_KEEP``."""
    import json as _json

    out = dict(edge)
    ev = out.get("evidence")
    if isinstance(ev, str):
        try:
            ev = _json.loads(ev)
        except ValueError:
            ev = None
    out["evidence"] = (
        {k: ev[k] for k in _EDGE_EVIDENCE_KEEP if k in ev} if isinstance(ev, dict) else None
    )
    # the raw column under its storage name, should a store ever return it
    out.pop("evidence_json", None)
    return out


async def _restrict_edge_evidence(out: Any, audience: Any, roles: Any) -> Any:
    """``out`` with every edge provable-and-clean for ``roles``; an error dict if it cannot be.

    Handles the three places `navigate` puts edges (``expanded_entities``,
    ``reasoning_paths``, ``hypotheses[].edges``) and `explain_path`'s ``path``.
    Fails closed: if the readability re-check cannot run, nothing is returned.
    """
    if not isinstance(out, dict):
        return out
    from .rag import _edge_doc_ids, _readable_ids

    def _edges(v: Any) -> list:
        return [e for e in v if isinstance(e, dict)] if isinstance(v, list) else []

    expanded = out.get("expanded_entities")
    paths = out.get("reasoning_paths")
    hyps = out.get("hypotheses")
    path = out.get("path")

    all_edges: list = _edges(expanded) + _edges(path)
    for p in paths if isinstance(paths, list) else []:
        all_edges += _edges(p)
    for h in hyps if isinstance(hyps, list) else []:
        all_edges += _edges(h.get("edges") if isinstance(h, dict) else None)

    docs: set = set()
    for e in all_edges:
        docs |= _edge_doc_ids(e) or set()
    rag = _get_rag()
    ok_docs: set = set()
    try:
        if docs:  # no edge names a document -> every edge fails `_ok` below; no query needed
            if rag is None or getattr(rag, "store", None) is None:
                raise RuntimeError("no store to re-check edge documents against")
            ok_docs, _ = await _readable_ids(rag, audience, roles, docs=docs, entities=set())
    except Exception as e:  # noqa: BLE001 - nothing is provably readable -> serve nothing
        log.warning("graph.edge_evidence_recheck_failed", error=str(e))
        return {"error": "could not verify the documents behind these edges for your audience"}

    def _ok(edge: Any) -> bool:
        ids = _edge_doc_ids(edge)
        return bool(ids) and ids <= ok_docs

    def _chain_ok(edges: Any) -> bool:
        return isinstance(edges, list) and bool(edges) and all(_ok(e) for e in edges)

    res = dict(out)
    if isinstance(expanded, list):
        res["expanded_entities"] = [_clean_edge(e) for e in expanded if _ok(e)]
    if isinstance(paths, list):
        res["reasoning_paths"] = [[_clean_edge(e) for e in p] for p in paths if _chain_ok(p)]
    if isinstance(hyps, list):
        res["hypotheses"] = [
            {**h, "edges": [_clean_edge(e) for e in h["edges"]]}
            for h in hyps
            if isinstance(h, dict) and _chain_ok(h.get("edges"))
        ]
    if isinstance(path, list):
        # An empty path means "no route within 5 hops"; a route we cannot show is
        # reported as not found rather than as a different, shorter route.
        if path and not _chain_ok(path):
            res["path"] = []
            res["hops"] = 0
            res["found"] = False
            res["reason"] = "route_not_provable_for_audience"
        else:
            res["path"] = [_clean_edge(e) for e in path]
    return res


# Cluster hierarchy fields that name clusters the caller's audience may not be
# able to see (: a documented interim leak, closed here by
# not returning them to a restricted caller).
_CLUSTER_HIERARCHY_FIELDS = ("parent_cluster_id", "level", "generation")


@worker_handler("worker.graph.navigate")
@_audience_op("navigate")
async def _graph_navigate(request: dict, roles=None, audience=None) -> Any:
    """POST /api/v1/graph/navigate — seeds → expand → pages → paths."""
    nav, err = _intel_component("navigator")
    if err:
        return err
    query = (request.get("query") or "").strip()
    if not query:
        return {"error": "query is required"}
    try:
        extra = {} if roles is None else {"roles": roles}
        result = await nav.navigate(
            query=query,
            seed_entities=request.get("seed_entities"),
            max_hops=int(request.get("max_hops") or 2),
            rel_types=request.get("rel_types"),
            **extra,
        )
    except Exception as e:
        log.warning("graph_navigate.failed", error=str(e), exc_info=True)
        return {"error": str(e)}
    # GraphResult is a dataclass owned by the add-on; hand back plain JSON so
    # the gateway never has to know the class exists.
    out = _as_json(result)
    if roles is not None:
        out = await _restrict_edge_evidence(out, audience, roles)
        if isinstance(out, dict) and "error" in out:
            return out
    # A signed-in user's walk is kept as a thread, AFTER this reply is built
    # and off its path (workers/walks.py). Never raises.
    _walks.keep(request, via="navigate", query=query, build=lambda: _walks.walk_from_graph_result(out))
    return out


@worker_handler("worker.graph.traverse")
@_audience_op("traverse")
async def _graph_traverse(request: dict, roles=None, audience=None) -> Any:
    """POST /api/v1/graph/traverse — intent-weighted priority traversal."""
    nav, err = _intel_component("navigator")
    if err:
        return err
    entity_id = (request.get("entity_id") or "").strip()
    intent = (request.get("intent") or "").strip()
    if not entity_id or not intent:
        return {"error": "entity_id and intent are both required"}
    try:
        extra = {} if roles is None else {"roles": roles}
        rows = await nav.traverse_with_intent(
            entity_id=entity_id,
            query_intent=intent,
            hops=int(request.get("max_hops") or 2),
            **extra,
        )
    except Exception as e:
        log.warning("graph_traverse.failed", error=str(e), exc_info=True)
        return {"error": str(e)}
    out_rows = _as_json(rows)
    _walks.keep(
        request, via="traverse", query=None,
        build=lambda: _walks.walk_from_traverse(entity_id, out_rows, intent),
    )
    return {"entities": out_rows, "count": len(rows)}


@worker_handler("worker.graph.explain_path")
@_audience_op("explain_path")
async def _graph_explain_path(request: dict, roles=None, audience=None) -> Any:
    """POST /api/v1/graph/explain-path — shortest reasoning path, ≤5 hops."""
    nav, err = _intel_component("navigator")
    if err:
        return err
    src = (request.get("src_entity_id") or "").strip()
    dst = (request.get("dst_entity_id") or "").strip()
    if not src or not dst:
        return {"error": "src_entity_id and dst_entity_id are both required"}
    try:
        extra = {} if roles is None else {"roles": roles}
        path = await nav.explain_path(src_entity_id=src, dst_entity_id=dst, **extra)
    except Exception as e:
        log.warning("graph_explain_path.failed", error=str(e), exc_info=True)
        return {"error": str(e)}
    # An empty path is a real answer here — "no route within 5 hops" — so it
    # is reported as such rather than as an absence.
    out = {"path": _as_json(path), "hops": len(path), "found": bool(path)}
    if roles is not None:
        out = await _restrict_edge_evidence(out, audience, roles)
    return out


@worker_handler("worker.graph.semantic_search")
@_audience_op("semantic_search")
async def _graph_semantic_search(request: dict, roles=None, audience=None) -> Any:
    """POST /api/v1/graph/semantic-search — entities by embedding similarity."""
    rag = _get_rag()
    if rag is None or rag.store is None:
        return {"error": "RAG not initialized on this worker"}
    embedder, err = _intel_component("embedder")
    if err:
        return err
    query = (request.get("query") or "").strip()
    if not query:
        return {"error": "query is required"}
    top_k = max(1, min(int(request.get("top_k") or 10), 100))
    try:
        vec = await embedder.embed_text(query)
        if audience is None:
            rows = await rag.store.search_entity_embeddings(embedding=vec, top_k=top_k)
        else:
            # The cut is made in SQL AFTER the audience filter, so a restricted
            # caller gets top_k readable entities, not top_k minus hidden ones.
            rows = await audience.search_entity_embeddings(rag.store, vec, top_k, roles)
    except AttributeError as e:
        # Named separately: this is "the method moved", not "the search
        # failed", and the two want different fixes.
        return {"error": f"store/embedder API mismatch: {e}"}
    except Exception as e:
        log.warning("graph_semantic_search.failed", error=str(e), exc_info=True)
        return {"error": str(e)}
    return {"entities": _as_json(rows), "count": len(rows)}


@worker_handler("worker.graph.search_clusters")
@_audience_op("search_clusters")
async def _graph_search_clusters(request: dict, roles=None, audience=None) -> Any:
    """POST /api/v1/graph/search-clusters — clusters by centroid similarity.

    Centroids are written by the clusterer, so this is empty until a
    clustering pass has run. That is reported as a reason, not as a result:
    `search_clusters` filters on `centroid IS NOT NULL`, and an unclustered
    graph would otherwise answer "no matching clusters" for every query.
    """
    rag = _get_rag()
    if rag is None or rag.store is None:
        return {"error": "RAG not initialized on this worker"}
    embedder, err = _intel_component("embedder")
    if err:
        return err
    query = (request.get("query") or "").strip()
    if not query:
        return {"error": "query is required"}
    top_k = max(1, min(int(request.get("top_k") or 5), 50))
    try:
        vec = await embedder.embed_text(query)
        if audience is None:
            rows = await rag.store.search_clusters(embedding=vec, top_k=top_k)
        else:
            rows = await audience.search_clusters(rag.store, vec, top_k, roles)
    except Exception as e:
        log.warning("graph_search_clusters.failed", error=str(e), exc_info=True)
        return {"error": str(e)}
    out: dict[str, Any] = {"clusters": _as_json(rows), "count": len(rows)}
    if roles is not None:
        out["clusters"] = [
            {k: v for k, v in c.items() if k not in _CLUSTER_HIERARCHY_FIELDS} if isinstance(c, dict) else c
            for c in out["clusters"]
        ]
    if not rows:
        out["reason"] = "no_clusters_with_centroids"
        out["hint"] = ("cluster centroids are written by a clustering pass — "
                       "run `noo graph recluster` first")
    return out


@worker_handler("worker.graph.classify_intent")
async def _graph_classify_intent(request: dict) -> Any:
    """POST /api/v1/graph/classify-intent — the router's query classification."""
    query = (request.get("query") or "").strip()
    if not query:
        return {"error": "query is required"}
    try:
        from ..addon_roles import QUERY_CLASSIFIER, provider
        classify_query = provider(QUERY_CLASSIFIER)
    except ImportError as e:
        return {"error": str(e)}
    try:
        # Called unbound on purpose: classification is read-only and must
        # not construct the full router or touch persistence per request.
        intent = classify_query(None, query)
    except Exception as e:
        log.warning("graph_classify_intent.failed", error=str(e), exc_info=True)
        return {"error": str(e)}
    # The intent is an Enum; its VALUE is the wire form. Sending the repr
    # would put a Python type name in an API response.
    return {"intent": getattr(intent, "value", str(intent)), "query": query}


@worker_handler("worker.graph.extract_relations")
@_audience_op("extract_relations")
async def _graph_extract_relations(request: dict, roles=None, audience=None) -> Any:
    """POST /api/v1/graph/extract-relations — typed relations for one page."""
    ext, err = _intel_component("relation_extractor")
    if err:
        return err
    page_id = (request.get("page_id") or "").strip()
    if not page_id:
        return {"error": "page_id is required"}
    if audience is not None:
        # A WRITE. A restricted caller may run it only over a page whose
        # document they can read, so the edges it draws (evidence = that
        # document) are readable by exactly the audience that could read the
        # page. An unreadable page and a missing one answer identically.
        try:
            readable = await audience.page_is_readable(ext.store, page_id, roles)
        except Exception as e:
            log.warning("graph_extract_relations.audience_failed", error=str(e), exc_info=True)
            return {"error": str(e)}
        if not readable:
            return {"error": "page not found"}
    try:
        count = await ext.extract_relations_for_page(page_id)
    except Exception as e:
        log.warning("graph_extract_relations.failed", error=str(e), exc_info=True)
        return {"error": str(e)}
    # `edges_created`, the name the tool's formatter reads and the more
    # accurate one — what is written is edges. `relations_extracted` was
    # mine and rendered as "Extracted 0 semantic edge(s)" every time.
    return {"page_id": page_id, "edges_created": int(count)}


@worker_handler("worker.graph.recall_traversals")
@_audience_op("recall_traversals")
async def _graph_recall_traversals(request: dict, roles=None, audience=None) -> Any:
    """POST /api/v1/graph/recall-traversals — past traversals by similarity."""
    rag = _get_rag()
    if rag is None or rag.store is None:
        return {"error": "RAG not initialized on this worker"}
    query = (request.get("query") or "").strip()
    if not query:
        return {"error": "query is required"}
    top_k = max(1, min(int(request.get("top_k") or 5), 50))
    # No tracker check. The first version fetched `get_retrieval_tracker()`
    # and errored when it was None — but nothing here uses the tracker;
    # `_recall_traversal_rows` reads `trellion_traversal_records` directly.
    # The tracker is a per-process singleton, so on a freshly restarted worker
    # (or one where archiving happens in another container) it is None while
    # the table is full, and the caller was told there was nothing to recall
    # when there was.
    intent = (request.get("intent") or "").strip() or None
    try:
        rows = await _recall_traversal_rows(rag, query, intent, top_k, roles, audience)
    except Exception as e:
        log.warning("graph_recall_traversals.failed", error=str(e), exc_info=True)
        return {"error": str(e)}
    # `strategy` too: the formatter's first line is `Strategy: {strategy}` and
    # without it every response opened with "Strategy: unknown".
    return {
        "traversals": _as_json(rows),
        "count": len(rows),
        "strategy": "embedding_similarity" + (f"+intent={intent}" if intent else ""),
    }


@worker_handler("worker.graph.recall_walks")
@_audience_op("recall_walks")
async def _graph_recall_walks(request: dict, roles=None, audience=None) -> Any:
    """GET /api/v1/walks — the caller's OWN saved threads.

    * ``id``    -> that one thread (``{"walk": ...}``);
    * ``query`` -> the threads nearest the query, revalidated against the
      current graph for the caller's audience (hard gates drop, soft gates log);
    * neither   -> their most recent threads.

    The account is the VERIFIED principal's (``asker_account``), never a body
    field: a caller cannot ask for somebody else's threads, and a request with
    no signed-in account (an internal loop, an unsigned call) has none to show.
    An unrestricted caller (admin) still sees only their own here; reading
    another user's threads is the audited admin route, not this one.
    """
    from .audience import asker_account

    account = asker_account(request)
    if account is None:
        return {"error": "saved walks belong to a signed-in account; this caller has none"}
    rag = _get_rag()
    if rag is None or rag.store is None:
        return {"error": "RAG not initialized on this worker"}
    _, err = _intel_audience("recall_walks")
    if err:
        return err
    from ..addon_roles import WALK_STORE, provider

    walks = provider(WALK_STORE)
    from ..config import get_config

    cfg = get_config().walks
    policy = walks.WalkPolicy(
        soft_gating=cfg.soft_gating,
        min_relevance=cfg.min_relevance,
        min_usefulness=cfg.min_usefulness,
        min_confidence=cfg.min_confidence,
        half_life_days=cfg.freshness_half_life_days,
    )
    top_k = max(1, min(int(request.get("top_k") or 5), 50))
    walk_id = (request.get("id") or "").strip()
    query = (request.get("query") or "").strip()
    try:
        if walk_id:
            walk = await walks.get_walk(rag.store, account, roles, walk_id, policy=policy)
            if walk is None:
                return {"error": "walk not found"}
            return {"walk": _as_json(walk)}
        if query:
            embedder = getattr(rag, "embedder", None)
            if embedder is None:
                return {"error": "embedder unavailable; cannot rank walks"}
            vec = await embedder.embed_text(query)
            rows = await walks.recall_walks(rag.store, account, roles, vec, top_k, policy=policy)
            strategy = "thread_similarity"
        else:
            rows = await walks.list_walks(rag.store, account, roles, top_k, policy=policy)
            strategy = "recent"
    except Exception as e:
        log.warning("graph_recall_walks.failed", error=str(e), exc_info=True)
        return {"error": str(e)}
    return {"walks": _as_json(rows), "count": len(rows), "strategy": strategy}


async def _recall_traversal_rows(
    rag, query: str, intent, top_k: int, roles=None, audience=None
) -> list:
    """Archived traversals ranked by embedding similarity to `query`.

    Kept out of the handler because it is the only part that touches SQL
    directly: `trellion_traversal_records` is a trellion table with no store
    accessor, and inventing one belongs in trellion rather than here.
    """
    from sqlalchemy import text as _text

    embedder = getattr(rag, "embedder", None)
    if embedder is None:
        raise RuntimeError("embedder unavailable; cannot rank traversals")
    vec = await embedder.embed_text(query)
    if audience is not None:
        # A stored traversal carries whoever's query text and entity path it
        # was; it is re-filtered on read, in SQL, per audience (see
        # the audience scope's recall_traversals).
        return await audience.recall_traversals(rag.store, vec, intent, top_k, roles)
    literal = "[" + ",".join(f"{float(x):.8f}" for x in vec) + "]"

    # Columns from 100_trellion_squash: query_text/query_embedding/
    # traversal_path/outcome_score, not the shorter names the tool's response
    # formatter uses. Mapped here rather than in the formatter, so the wire
    # shape stays the tool's contract.
    # `text` and `path`, not `query` and `traversal_path`, because
    # `PaiRecallTraversals.format_response` reads `t["text"]`, `t["score"]`
    # and `t["path"]` (mcp/tool_defs/memory.py). The first version aliased to
    # the column's own meaning and every traversal rendered through the MCP
    # door as an empty bullet — the shape was right for an API client and
    # wrong for the only caller. The descriptive names are kept alongside so
    # both readings work.
    sql = (
        "SELECT id::text AS record_id, query_text AS text, query_text AS query, "
        "       intent, traversal_path AS path, traversal_path, "
        "       outcome_score AS score, created_at::text, "
        "       1 - (query_embedding <=> CAST(:vec AS vector)) AS similarity "
        "FROM trellion_traversal_records "
        "WHERE query_embedding IS NOT NULL "
        # A user's saved threads are theirs: they come back only
        # through worker.graph.recall_walks, which gates them, and the audited
        # admin view. An unrestricted caller of THIS route sees the shared walks.
        "  AND kind <> 'thread' AND status = 'active' "
    )
    params: dict = {"vec": literal, "vec2": literal, "top_k": top_k}
    if intent:
        sql += "  AND intent = :intent "
        params["intent"] = intent
    sql += "ORDER BY query_embedding <=> CAST(:vec2 AS vector) LIMIT :top_k"

    async with rag.store._engine.connect() as conn:
        rows = (await conn.execute(_text(sql), params)).mappings().all()
    return [dict(r) for r in rows]


def _as_json(value: Any) -> Any:
    """Plain JSON for a dataclass, a list of them, or something already plain.

    The gateway must never need to know an add-on class exists: these
    payloads cross a NATS boundary and land in an HTTP response, and a
    dataclass that serialises today by accident stops when a field changes.
    """
    import dataclasses

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    if isinstance(value, (list, tuple)):
        return [_as_json(v) for v in value]
    if isinstance(value, dict):
        return {k: _as_json(v) for k, v in value.items()}
    return value
