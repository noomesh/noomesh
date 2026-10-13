# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Saving a signed-in user's graph walks as recallable threads.

A successful ``navigate`` / ``traverse`` (``workers/graph.py``) or ``rag.query``
(``workers/rag.py``) leaves a WALK behind: the entity chain it followed and the
edges and documents that chain rests on. For a signed-in user that walk is
saved as a ``kind='thread'`` row of ``trellion_traversal_records`` so
trellion-intel's ``recall_walks`` can show it back to them (and only them).

The rules, each pinned by a test:

* the asker is ``asker_account(request)``: the verified principal's ACCOUNT. An
  unsigned or ``internal`` (heartbeat, autonomy) request has none, and a walk
  with no asker is not a thread and is not saved here;
* a per-account switch, ``walks.save_threads`` in ``noo_user_settings``
  (default ON). OFF stops new saves and deletes nothing. The switch is read
  fail-CLOSED: if it cannot be read the walk is not saved;
* the save happens AFTER the reply, off the response path: the handler builds
  the (pure, in-memory) walk, calls :func:`schedule_save` and returns; the
  embedding, the opt-out read, the retention cap and the insert run in a
  background task. A failure there is logged (``walk_save.failed``) and never
  reaches the caller;
* the query is embedded with the same embedder recall uses
  (``rag.embedder.embed_text``) so save and recall share one vector space; no
  embedding, no row (a row without one can never be recalled);
* retention (phase 1b): ``expires_at`` = saved + ``walks.thread_ttl_days`` (180);
  over ``walks.max_threads_per_user`` (500) the least-recalled, then oldest,
  active threads are STAGED (``status='staged'``: out of recall, still in the
  table for the phase 3 restore window), not skipped: skipping would silently
  stop remembering the user's newest work.

Nothing here imports trellion-intel: ``rag.query`` runs on the base ``ml``
surface, which does not carry it. The archiver is trellion's open one.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import structlog

from .audience import asker_account

log = structlog.get_logger(__name__)

#: The per-account switch, as stored in ``noo_user_settings.key``.
SETTING_KEY = "walks.save_threads"

#: Strong references to in-flight saves (a bare ``create_task`` can be GC'd).
_pending: "set[asyncio.Task]" = set()


@dataclass
class Walk:
    """A walk, as a path plus what it rests on. Built synchronously from a reply."""

    path: "list[dict]"
    triples: "list[list[str]]"
    doc_ids: "list[str]" = field(default_factory=list)
    #: Walk quality in [0, 1] (the archiver's ``outcome_score``).
    outcome: float = 0.5
    intent: Optional[str] = None
    #: A traverse has no question, only an intent and a seed entity: the query
    #: text is made from them once the seed's name is known.
    query_template: Optional[str] = None
    #: How the walk was produced beyond ``via``: a rag walk's verification and
    #: citation count, which trellion-intel's accuracy term reads at recall.
    provenance: dict = field(default_factory=dict)


# ----------------------------------------------------------------------
# Building a walk from a reply (pure)
# ----------------------------------------------------------------------


def _as_dict(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    return value


def _doc_of(edge: dict) -> Optional[str]:
    ev = edge.get("evidence")
    if ev is None:
        ev = edge.get("evidence_json")
    if isinstance(ev, dict) and ev.get("doc_id"):
        return str(ev["doc_id"])
    return None


def _chain(edges: "list[dict]", seed_ids: "set[str]") -> "Optional[tuple[list[str], list[str], list[str], list[list[str]]]]":
    """Order ``edges`` (a reasoning path) into ``(entity_ids, directions, rels, triples)``.

    Edges are undirected in a reasoning path; the chain starts at the endpoint
    of the first edge that is a seed (else either) and must connect end to end.
    """
    first = edges[0]
    ends = [str(first["src_entity_id"]), str(first["dst_entity_id"])]
    ends.sort(key=lambda e: e not in seed_ids)  # seeds first; stable otherwise
    for start in ends:
        cur, ids, dirs, rels, triples = start, [start], ["seed"], [""], []
        ok = True
        for e in edges:
            src, dst = str(e["src_entity_id"]), str(e["dst_entity_id"])
            if src == cur:
                nxt, d = dst, "outgoing"
            elif dst == cur:
                nxt, d = src, "incoming"
            else:
                ok = False
                break
            rel = str(e.get("rel_type") or "")
            triples.append([cur, rel, nxt])
            ids.append(nxt)
            dirs.append(d)
            rels.append(rel)
            cur = nxt
        if ok:
            return ids, dirs, rels, triples
    return None


def walk_from_graph_result(
    result: Any, *, extra_doc_ids: "list[str] | None" = None, outcome: Optional[float] = None
) -> Optional[Walk]:
    """The longest reasoning path of a ``GraphResult`` (``navigate``, or the
    ``graph_context`` of a ``rag.query``). ``None`` when there is no walk to keep."""
    r = _as_dict(result)
    if not isinstance(r, dict):
        return None
    paths = [p for p in (r.get("reasoning_paths") or []) if isinstance(p, list) and p]
    if not paths:
        return None
    seeds = {str(s.get("entity_id")): s for s in (r.get("seed_entities") or []) if isinstance(s, dict)}
    names = r.get("entity_name_map") or {}
    best = max(paths, key=len)  # longest; max() keeps the first of equals
    chain = _chain(best, set(seeds))
    if chain is None:
        return None
    ids, dirs, rels, triples = chain
    path = []
    for eid, d, rel in zip(ids, dirs, rels):
        seed = seeds.get(eid) or {}
        path.append({
            "entity_id": eid,
            "entity_name": str(names.get(eid) or seed.get("canonical_name") or ""),
            "entity_type": str(seed.get("type") or ""),
            "edge_type": rel,
            "edge_confidence": 1.0,
            "direction": d,
        })
    docs = [d for d in (_doc_of(e) for e in best) if d]
    docs.extend(extra_doc_ids or [])
    if outcome is None:
        outcome = min(1.0, len(r.get("candidate_page_ids") or []) / 3.0)
    return Walk(path, triples, list(dict.fromkeys(docs)), float(outcome))


def walk_from_rag_result(result: Any) -> Optional[Walk]:
    """The graph walk behind a ``rag.query`` answer, with what backed the answer.

    ``None`` when the answer carried no graph walk, or when its verification was
    ``rejected`` (a rejected claim is not a walk worth keeping).
    """
    gc = getattr(result, "graph_context", None)
    if gc is None:
        return None
    ver = getattr(result, "verification", None)
    status = getattr(ver, "status", None)
    if status == "rejected":
        return None
    cites = list(getattr(result, "citations", None) or [])
    docs = [str(c.doc_id) for c in cites if getattr(c, "doc_id", None)]
    if status in ("approved", "verified"):
        outcome = 1.0
    elif status == "partial":
        outcome = 0.5
    else:
        outcome = min(1.0, len(cites) / 2.0) if cites else 0.5
    walk = walk_from_graph_result(gc, extra_doc_ids=docs, outcome=outcome)
    if walk is None:
        return None
    walk.intent = getattr(result, "intent", None) or None
    prov: dict = {"n_citations": len(cites), "strategy": getattr(result, "strategy_used", "") or ""}
    if status:
        prov["verification"] = {"status": status, "confidence": float(getattr(ver, "confidence", 0.0) or 0.0)}
    walk.provenance = prov
    return walk


def walk_from_traverse(seed_entity_id: str, rows: Any, intent: Optional[str] = None) -> Optional[Walk]:
    """The best-scoring result of an intent traversal that has a structured path
    (``path_steps``, which trellion-intel keeps beside the rendered ``path``)."""
    if not isinstance(rows, list):
        return None
    names = {str(r.get("entity_id")): r for r in rows if isinstance(r, dict)}
    best = None
    for r in rows:
        steps = r.get("path_steps") if isinstance(r, dict) else None
        if isinstance(steps, list) and len(steps) >= 2 and (
            best is None or float(r.get("score") or 0) > float(best.get("score") or 0)
        ):
            best = r
    if best is None:
        return None
    steps = best["path_steps"]
    path, triples = [], []
    for i, s in enumerate(steps):
        eid = str(s.get("entity_id"))
        row = names.get(eid) or {}
        rel = str(s.get("rel_type") or "")
        path.append({
            "entity_id": eid,
            "entity_name": str(row.get("name") or ""),
            "entity_type": str(row.get("type") or ""),
            "edge_type": "" if i == 0 else rel,
            "edge_confidence": 1.0,
            "direction": "seed" if i == 0 else "outgoing",
        })
        if i:
            triples.append([str(steps[i - 1].get("entity_id")), rel, eid])
    outcome = max(0.0, min(1.0, float(best.get("score") or 0.0)))
    return Walk(path, triples, [], outcome, intent, "{intent} traversal from {seed}")


# ----------------------------------------------------------------------
# The per-account switch
# ----------------------------------------------------------------------


async def save_enabled(account: str) -> bool:
    """``walks.save_threads`` for ``account``: True unless the account turned it off.

    Fail CLOSED. A setting that cannot be read is not "on": an opted-out user's
    walk must never be saved because a database hiccup made the switch invisible.
    """
    from .common import _get_conversation_store

    store = _get_conversation_store()
    engine = getattr(store, "_engine", None)
    if engine is None:
        log.warning("walk_save.setting_unreadable", reason="no conversation store on this worker")
        return False
    try:
        from sqlalchemy import text

        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    text("SELECT value FROM noo_user_settings WHERE username = :u AND key = :k"),
                    {"u": account, "k": SETTING_KEY},
                )
            ).first()
    except Exception as e:  # noqa: BLE001 - see docstring
        log.warning("walk_save.setting_unreadable", error=str(e)[:200])
        return False
    if row is None:
        return True
    value = row[0]
    return value is not False and str(value).lower() != "false"


# ----------------------------------------------------------------------
# Saving
# ----------------------------------------------------------------------


def _thread_id(request: dict) -> Optional[str]:
    """The conversation/thread the request names, when it carries one and it is a UUID.

    Today none of the graph or rag routes sets one (the agent loop has it, the
    door sessions do not), so this is usually None: phase 3 groups threads
    without an id by idle gap. A client MAY send ``conversation_id`` /
    ``thread_id``; it only labels the sender's own walk.
    """
    params = request.get("params") if isinstance(request.get("params"), dict) else {}
    for src in (request, params):
        for key in ("conversation_id", "thread_id"):
            raw = src.get(key)
            if raw:
                try:
                    return str(uuid.UUID(str(raw)))
                except ValueError:
                    return None
    return None


def schedule_save(
    request: dict, *, via: str, query: str, walk: Optional[Walk], provenance: Optional[dict] = None
) -> "Optional[asyncio.Task]":
    """Fire-and-forget: save ``walk`` as the asker's thread. Never raises, never awaits.

    Call this from a handler once it HAS its reply, immediately before
    returning it. Returns the task (tests await :func:`drain`); None when
    nothing is scheduled (no asker, no walk, no query).
    """
    try:
        account = asker_account(request)
        if account is None or walk is None or not ((query or "").strip() or walk.query_template):
            return None
        thread_id = _thread_id(request)
        task = asyncio.get_running_loop().create_task(
            _save_guarded(
                account, (query or "").strip(), walk, via, {**walk.provenance, **(provenance or {})}, thread_id
            )
        )
        _pending.add(task)
        task.add_done_callback(_pending.discard)
        return task
    except Exception as e:  # noqa: BLE001 - a save must never fail the request
        log.warning("walk_save.schedule_failed", via=via, error=str(e)[:200])
        return None


def keep(request: dict, *, via: str, query: Optional[str], build, provenance: Optional[dict] = None):
    """:func:`schedule_save` for a handler: builds the walk only when there is
    an asker (an internal call pays nothing) and swallows every error, so the
    reply a handler already holds is never put at risk by the save."""
    try:
        if asker_account(request) is None:
            return None
        return schedule_save(request, via=via, query=query or "", walk=build(), provenance=provenance)
    except Exception as e:  # noqa: BLE001
        log.warning("walk_save.schedule_failed", via=via, error=str(e)[:200])
        return None


async def drain() -> None:
    """Wait for every scheduled save (tests, orderly shutdown)."""
    if _pending:
        await asyncio.gather(*list(_pending), return_exceptions=True)


async def _save_guarded(account, query, walk, via, provenance, thread_id) -> "dict | None":
    try:
        return await save_thread(account, query, walk, via=via, provenance=provenance, thread_id=thread_id)
    except Exception as e:  # noqa: BLE001
        log.warning("walk_save.failed", via=via, error=str(e)[:300], exc_info=True)
        return None


async def _resolve_walk(engine, store, walk: Walk) -> "tuple[list[str], Optional[datetime]]":
    """Fill in step names, and find the documents the walk's edges are drawn
    from and when the newest of that evidence was recorded. One batch each."""
    from sqlalchemy import text

    missing = [s["entity_id"] for s in walk.path if not s.get("entity_name")]
    if missing:
        try:
            found = await store.get_entities_by_ids(missing)
            for s in walk.path:
                ent = found.get(s["entity_id"]) if isinstance(found, dict) else None
                if ent and not s.get("entity_name"):
                    s["entity_name"] = str(ent.get("canonical_name") or "")
                    s["entity_type"] = s.get("entity_type") or str(ent.get("type") or "")
        except Exception as e:  # noqa: BLE001 - a nameless step is still a valid step
            log.debug("walk_save.names_unresolved", error=str(e)[:200])
    docs = list(walk.doc_ids)
    newest: Optional[datetime] = None
    if walk.triples:
        async with engine.connect() as conn:
            res = await conn.execute(
                text(
                    "WITH t AS (SELECT * FROM unnest(CAST(:s AS text[]), CAST(:r AS text[]), "
                    "CAST(:d AS text[])) AS t(src, rel, dst)) "
                    "SELECT e.evidence_json->>'doc_id', e.created_at FROM t JOIN edges e ON "
                    "e.rel_type = t.rel AND ((e.src_entity_id::text = t.src AND e.dst_entity_id::text = t.dst) "
                    " OR (e.src_entity_id::text = t.dst AND e.dst_entity_id::text = t.src))"
                ),
                {"s": [t[0] for t in walk.triples], "r": [t[1] for t in walk.triples],
                 "d": [t[2] for t in walk.triples]},
            )
            for doc, created in res.all():
                if doc:
                    docs.append(str(doc))
                if created is not None and (newest is None or created > newest):
                    newest = created
        docs = list(dict.fromkeys(docs))
        if docs:
            async with engine.connect() as conn:
                created = (
                    await conn.execute(
                        text("SELECT max(created_at) FROM docs WHERE doc_id::text = ANY(CAST(:ids AS text[]))"),
                        {"ids": docs},
                    )
                ).scalar()
            if created is not None and (newest is None or created > newest):
                newest = created
    return docs, newest


async def stage_over_cap(engine, account: str, cap: int) -> int:
    """Make room for ONE more thread: keep the ``cap - 1`` most valuable active
    threads (most recalled, then newest) and stage the rest. Returns rows staged."""
    from sqlalchemy import text

    async with engine.begin() as conn:
        res = await conn.execute(
            text(
                "UPDATE trellion_traversal_records SET status = 'staged', updated_at = NOW() "
                "WHERE id IN (SELECT id FROM trellion_traversal_records "
                "  WHERE user_id = :u AND kind = 'thread' AND status = 'active' "
                "  ORDER BY recall_count DESC, COALESCE(last_recalled_at, created_at) DESC, created_at DESC "
                "  OFFSET :keep)"
            ),
            {"u": account, "keep": max(0, int(cap) - 1)},
        )
    return res.rowcount or 0


async def save_thread(
    account: str,
    query: str,
    walk: Walk,
    *,
    via: str,
    provenance: Optional[dict] = None,
    thread_id: Optional[str] = None,
) -> dict:
    """The save itself (awaited by the background task). Returns ``{"saved": bool, ...}``."""
    from .common import _get_rag

    if not await save_enabled(account):
        return {"saved": False, "reason": "opted_out_or_unreadable"}
    rag = _get_rag()
    if rag is None or getattr(rag, "store", None) is None or getattr(rag, "embedder", None) is None:
        return {"saved": False, "reason": "rag_unavailable"}
    from ..config import get_config

    cfg = get_config().walks
    engine = rag.store._engine
    docs, newest = await _resolve_walk(engine, rag.store, walk)
    if not query and walk.query_template and walk.path:
        seed = walk.path[0]
        query = walk.query_template.format(
            intent=walk.intent or "exploratory", seed=seed.get("entity_name") or seed.get("entity_id")
        )
    vec = await rag.embedder.embed_text(query)
    if not vec:
        return {"saved": False, "reason": "no_embedding"}
    evidence: dict = {"triples": walk.triples, "doc_ids": docs}
    if newest is not None:
        evidence["newest_evidence_at"] = newest.isoformat()
    prov = {"via": via, **(provenance or {})}
    staged = await stage_over_cap(engine, account, cfg.max_threads_per_user)
    if staged:
        log.info("walk_save.staged_over_cap", staged=staged, cap=cfg.max_threads_per_user)
    from trellion.live.recall import TraversalArchiver

    # min_outcome_score=0.0: log first. The archiver's 0.6 gate would silently
    # decide what a user's history keeps before anyone has seen the scores.
    out = await TraversalArchiver("", engine, min_outcome_score=0.0).capture(
        "default",
        query,
        walk.intent,
        walk.path,
        walk.outcome,
        query_embedding=list(vec),
        user_id=account,
        kind="thread",
        thread_id=thread_id,
        provenance=prov,
        evidence=evidence,
        expires_at=datetime.now(timezone.utc) + timedelta(days=cfg.thread_ttl_days),
        embedding_model=getattr(rag.embedder, "model", None),
    )
    if not out or not out.get("archived"):
        log.warning("walk_save.failed", via=via, error=str((out or {}).get("reason") or "archiver error"))
        return {"saved": False, "reason": "archiver"}
    log.info("walk_save.saved", walk_id=out.get("traversal_id"), via=via, steps=len(walk.path))
    return {"saved": True, "id": out.get("traversal_id")}
