# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Trellion snapshot worker handlers (worker.api.snapshots*).

Moved verbatim from ``noomesh.gateway.worker_pool`` (2026-07-14 split
— pure code motion). Live subjects register on import via
``@worker_handler``; see ``noomesh.workers.registry``. Handlers whose
subjects were ported to native Rust were removed in the
2026-08-08 sweep (history in git log before that) — only live
registrations and helpers that live paths still call remain here.

NOTE on lazy (in-function) imports: they are deliberate — heavy/optional
deps (trellion, sqlalchemy, httpx, ML stacks) and modules that pull
FastAPI (gateway.deps) stay lazy so importing this package is cheap.

3 handlers removed 2026-07-18 — ported to native Rust routes
(gateway-rust routes/snapshots.rs); see PR #206.
"""

from __future__ import annotations

from typing import Any

import structlog


from .audience import AUDIENCE_KEY, audience_of
from .common import _trellion_engine, _unwrap_body
from .registry import worker_handler

log = structlog.get_logger(__name__)


#: Body keys that belong to the request, not to the slice. Everything else at
#: the top level of a flat body is a slice param.
_CONSOLIDATE_ENVELOPE = frozenset({"kind", "params", "label"})


def _consolidate_fields(request: dict) -> "tuple[str, dict, str | None]":
    """``(kind, params, label)`` from a consolidate request, however it arrived.

    this used to be ``kind=body.get("kind", "topic")`` and
    ``params=body.get("params") or {}``. A flat body (``{"kind": "topic",
    "canonical_name": "X"}``) left params empty and the slicer died on
    ``params["canonical_name"]`` with a bare KeyError; a body WITH params had
    the worker pool's verified principal injected into it
    (``bus_principal.apply_to_request``), so it could not even be written to
    the snapshot row as JSON. Shapes accepted:

      * ``{kind, params: {...}, label}``  - the HTTP contract
      * ``{kind, <slice keys...>, label}`` - flat: leftover keys are the params
      * ``{params: {kind, params, label}}`` - the NATS envelope the autonomy
        loop wraps a payload in

    Underscore-prefixed keys (``_requester``, ``_principal``) are the pool's,
    never the slice's, and are dropped.
    """
    body = request if isinstance(request, dict) else {}
    inner = body.get("params")
    if "kind" not in body and isinstance(inner, dict) and "kind" in inner:
        body = inner  # the envelope: the real request is one level down
        inner = body.get("params")
    if isinstance(inner, dict):
        params = dict(inner)
    else:
        params = {k: v for k, v in body.items() if k not in _CONSOLIDATE_ENVELOPE}
    params = {k: v for k, v in params.items() if not str(k).startswith("_")}
    return str(body.get("kind") or "topic"), params, body.get("label")


_CONSOLIDATE_EXAMPLE = '{"kind": "topic", "params": {"canonical_name": "<entity>"}}'

def _consolidate_problem(spec: Any) -> "str | None":
    """Why this slice cannot be consolidated, or None.

    Two checks, in order:
      * no slice parameters at all (an empty body; the pool-signed
        ``user_id`` does not count except for ``user_attention``) - refused
        here, whatever trellion version is installed, naming the shape that
        works;
      * the kind's own required params - trellion's ``SliceSpec.validate()``
        when this trellion has it. An older trellion has no
        validate(); its failure still lands on the row, as ``Type: message``.
    """
    # The pool signs the caller's `user_id` into every request
    # (bus_principal.apply_to_request), so `{}` arrives as {"user_id": ...}.
    # That key is a real slice param only for user_attention.
    slice_keys = [k for k in spec.params if k != "user_id" or spec.kind == "user_attention"]
    if not slice_keys:
        return (
            "consolidate needs a slice: give kind (topic, time_window or "
            f"user_attention) and its params, e.g. {_CONSOLIDATE_EXAMPLE}"
        )
    validate = getattr(spec, "validate", None)
    if callable(validate):
        try:
            validate()
        except ValueError as exc:
            return f"consolidate cannot slice: {exc}"
    return None


def _failure_reason(exc: BaseException) -> str:
    """``Type: message`` - a bare KeyError prints as just its key."""
    return f"{type(exc).__name__}: {exc}"[:500]


@worker_handler("worker.api.snapshots.consolidate")
async def _snapshots_consolidate(request: dict) -> Any:
    """Kick off a consolidation cycle and return immediately (fire-and-forget).

    Body: {kind, params:{...slice...}, label?}

    Consolidations can take 30s-5min depending on slice size + LLM extraction
    cost — far longer than the NATS request deadline. So we:

      1. Create the snapshot row in 'building' status (fast — <100ms)
      2. Spawn the actual orchestrator.consolidate() as a background task
      3. Return the snapshot_id to the caller right away
      4. Caller polls GET /api/snapshots/{id} for status='complete'|'failed'

    This matches how `submit_job`-style autonomy actions work elsewhere in
    the system: trigger something, let it run, observe via state.
    """
    import asyncio
    from trellion.snapshots import SliceSpec, SnapshotOrchestrator, SnapshotStore

    kind, params, label = _consolidate_fields(request)
    spec = SliceSpec(kind=kind, params=params, label=label)

    # Refuse a request that cannot slice BEFORE a snapshot row exists
    #: the release rehearsal POSTed `{}`, got a 'building'
    # snapshot id, and only found a failed row with "'canonical_name'" later.
    # A `{"error": ...}` reply is a 400 at the gateway (delegation::worker_ok).
    problem = _consolidate_problem(spec)
    if problem:
        return {"error": problem}

    engine = _trellion_engine()

    # Step 1+2: synchronously stamp the snapshot row so the caller has an id
    # to poll. The orchestrator's create_snapshot() is fast.
    store = SnapshotStore(engine)
    snapshot_id = await store.create_snapshot(
        slice_kind=spec.kind,
        slice_spec=spec.params,
        label=spec.label,
    )

    # Step 3: spawn the heavy work as a fire-and-forget task. The orchestrator
    # ALSO calls create_snapshot internally — that creates a second row, so we
    # bypass the public consolidate() and drive its internals directly.
    async def _run():
        try:
            orchestrator = SnapshotOrchestrator(engine)
            entities, edges = await orchestrator._slicer.slice(spec)
            if not entities:
                await store.mark_complete(snapshot_id, {
                    "reason": "empty_slice", "entities": 0, "edges": 0,
                })
                return
            canonical, mention_map, dag_edges, communities = orchestrator._run_build(entities, edges)
            concept_id_map = await store.write_concepts(snapshot_id, canonical)
            edge_count = await store.write_dag_edges(snapshot_id, dag_edges, concept_id_map)
            community_count = await store.write_communities(snapshot_id, communities, concept_id_map)
            live_to_canonical = {
                ent.entity_id: mention_map[(ent.canonical_name.lower().strip(), ent.type)]
                for ent in entities
                if (ent.canonical_name.lower().strip(), ent.type) in mention_map
            }
            await store.write_provenance(snapshot_id, concept_id_map, live_to_canonical)
            await store.mark_complete(snapshot_id, {
                "live_entities": len(entities),
                "live_edges": len(edges),
                "concepts": len(canonical),
                "dag_edges": edge_count,
                "communities": community_count,
            })
        except Exception as exc:
            log.exception("snapshot.background_consolidate_failed", snapshot_id=snapshot_id)
            try:
                await store.mark_failed(snapshot_id, _failure_reason(exc))
            except Exception:
                pass

    asyncio.create_task(_run())

    return {
        "snapshot_id": snapshot_id,
        "status": "building",
        "note": "consolidation running in background — poll GET /api/snapshots/{snapshot_id} for status",
    }


@worker_handler("worker.api.snapshots.curriculum")
async def _snapshots_curriculum(request: dict) -> Any:
    """Pure-traversal answer over a snapshot DAG (zero LLM).

    Body: {snapshot_id, q, max_hops?}
    """
    from trellion.query.answer import answer_query
    from trellion.snapshots import get_cached_ckg
    p = _unwrap_body(request)
    snapshot_id = p.get("snapshot_id") or p.get("id")
    q = p.get("q") or p.get("query") or ""
    max_hops = int(p.get("max_hops", 5))
    # the gateway passes the caller's knowledge-base audience as
    # `roles` (absent = unrestricted). A restricted caller is answered from a
    # concept graph built from what they may read, and the reply says so
    # (`audience_filtered`); the gateway refuses to forward one that does not.
    roles, err = audience_of(request)
    if err:
        return err
    if not snapshot_id or not q:
        return _stamp({"error": "missing snapshot_id or q"}, roles)
    try:
        if roles is None:
            ckg = await get_cached_ckg(_trellion_engine(), snapshot_id)
        else:
            from .snapshot_audience import load_ckg_for_audience
            ckg = await load_ckg_for_audience(_trellion_engine(), snapshot_id, roles)
    except Exception as exc:
        return {"error": f"could not load snapshot: {exc}"}
    if not ckg.concepts:
        return _stamp({
            "snapshot_id": snapshot_id, "query": q, "query_type": "EMPTY",
            "content": "Snapshot has no concepts.", "concept_ids": [],
            "retrieved_tokens": 0,
        }, roles)
    answer = answer_query(ckg, q, max_hops=max_hops)
    return _stamp({
        "snapshot_id": snapshot_id, "query": q,
        "query_type": answer.query_type, "content": answer.content,
        "concept_ids": answer.concept_ids, "retrieved_tokens": answer.retrieved_tokens,
    }, roles)


def _stamp(reply: dict, roles) -> dict:
    """Confirm to the gateway that this reply was produced under the caller's audience."""
    if roles is not None:
        reply[AUDIENCE_KEY] = True
    return reply


@worker_handler("worker.api.snapshots.scoped")
async def _snapshots_scoped(request: dict) -> Any:
    """What a RESTRICTED caller may see of a snapshot's contents.

    Backs ``GET /api/snapshots``, ``GET /api/snapshots/{id}`` and
    ``POST /api/snapshots/diff`` for a caller whose audience is restricted; the
    gateway keeps its own SQL for everyone else, so this answers restricted
    callers only (no ``roles`` = refused). The rule is the curriculum's
    (``snapshot_audience._scope_sql``), not restated.

    Body: ``{roles, op, ...}``
      * ``op: "counts"``, ``snapshot_ids: [..]`` -> ``{counts: {id: {concepts, dag_edges}}}``
      * ``op: "concepts"``, ``snapshot_id`` -> ``{concepts: [[name, type], ..]}``
    Every reply carries ``audience_filtered`` (the gateway refuses one without it).
    """
    import uuid

    from .snapshot_audience import readable_concepts, readable_counts

    p = _unwrap_body(request)
    roles, err = audience_of(request)
    if err:
        return err
    if roles is None:
        return {"error": "snapshots.scoped answers restricted callers only"}
    op = p.get("op")
    try:
        if op == "counts":
            ids = p.get("snapshot_ids")
            if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
                return _stamp({"error": "snapshot_ids must be a list of ids"}, roles)
            ids = [str(uuid.UUID(i)) for i in ids]
            return _stamp({"counts": await readable_counts(_trellion_engine(), ids, roles)}, roles)
        if op == "concepts":
            sid = str(uuid.UUID(str(p.get("snapshot_id"))))
            rows = await readable_concepts(_trellion_engine(), sid, roles)
            return _stamp({"concepts": [list(r) for r in rows]}, roles)
    except ValueError:
        return _stamp({"error": "invalid snapshot id"}, roles)
    except Exception as exc:
        return _stamp({"error": f"could not load snapshot: {exc}"}, roles)
    return _stamp({"error": f"unknown op {op!r}"}, roles)
