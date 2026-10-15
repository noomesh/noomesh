# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Episodic-recall handlers (worker.recall.*).

Renamed 2026-08-29 from the retired vidmem subjects (in place, dev-only): the subsystem is
episodic recall — a Postgres+pgvector store of episodes (proven graph
traversals), recalled by similarity + prominence. Old subject names died
with the rename; gateway, worker and trellion images roll together from
this repo, so no aliases are needed.

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


from .registry import worker_handler

log = structlog.get_logger(__name__)

# ═══════════════════════════════════════════════════════════════════════
# Recall memory handlers
# ═══════════════════════════════════════════════════════════════════════

def _get_recall_memory():
    """Get the VideoMemoryManager instance the worker pool initialised."""
    try:
        from ..gateway.deps import services
        if getattr(services, "recall_memory", None) is not None:
            return services.recall_memory
    except Exception:
        pass
    return None


def _trellion_engine():
    """The trellion async DB engine, or None when it is not importable/wired."""
    try:
        from trellion.db.engine import get_async_engine
        return get_async_engine()
    except Exception:
        return None


def _body_arg(request: dict, key: str, default: Any = None) -> Any:
    """Read ``key`` from the flat body the Rust route forwards verbatim,
    falling back to the legacy ``params`` envelope."""
    if key in request:
        return request[key]
    params = request.get("params")
    if isinstance(params, dict) and key in params:
        return params[key]
    return default


def _clamp_top_k(value: Any, default: int, maximum: int = 100) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(n, maximum))


def _record_kind(record_type: Any) -> str:
    return "traversal" if str(record_type or "") == "traversal" else str(record_type or "conversation")


# One projection for both doors. An episode row only carries a summary; for a
# traversal the readable body is the proven query + intent in
# trellion_traversal_records (joined on video_frame_id).
_EPISODE_SELECT = (
    "SELECT e.id::text, e.record_type, e.index_name, e.content_summary, "
    "       e.prominence_score, e.access_count, e.metadata, "
    "       t.query_text, t.intent, t.outcome_score "
    "FROM trellion_episodes e "
    "LEFT JOIN trellion_traversal_records t ON t.video_frame_id = e.id "
)


def _episode_view(row: Any) -> dict:
    """Door projection of one episode row: always says what KIND of record it
    is and where its text came from, so an empty body is explained, not silent."""
    (rid, rtype, iname, summary, prom, access, meta, qtext, intent, outcome) = tuple(row)
    kind = _record_kind(rtype)
    meta = dict(meta) if isinstance(meta, dict) else {}
    if kind == "traversal":
        if intent is not None:
            meta.setdefault("intent", intent)
        if outcome is not None:
            meta.setdefault("outcome", float(outcome))
    text = (qtext if kind == "traversal" and qtext else summary) or ""
    return {
        "record_id": str(rid),
        "kind": kind,
        "record_type": str(rtype or ""),
        "source_index": str(iname or ""),
        "text": str(text),
        "prominence": float(prom) if prom is not None else None,
        "access_count": int(access) if access is not None else None,
        "metadata": meta,
    }


async def _episode_views(engine: Any, ids: list[str]) -> dict[str, dict]:
    from sqlalchemy import bindparam, text as _text
    if not ids:
        return {}
    stmt = _text(_EPISODE_SELECT + "WHERE e.id::text IN :ids").bindparams(
        bindparam("ids", expanding=True))
    async with engine.connect() as conn:
        rows = (await conn.execute(stmt, {"ids": ids})).all()
    return {v["record_id"]: v for v in (_episode_view(r) for r in rows)}


@worker_handler("worker.recall.search")
async def _recall_search(request: dict) -> Any:
    """Handle recall memory search delegation."""
    vm = _get_recall_memory()
    if not vm or not getattr(vm, "_started", False):
        # Bare-list contract (the Rust route forwards it verbatim), so there
        # is nowhere to hang a reason: an unstarted manager stays [].
        return []
    # Was: `except Exception: pass` → [], so a search that BLEW UP was
    # reported as "no matches". Let it propagate — the worker pool wraps
    # handler exceptions as {"success": false, "error": ...}.
    #
    # The Rust route forwards the POST body flat ({query, top_k}); this used
    # to read request["params"]["query"] (always "") and hardcode top_k=5, so
    # neither argument ever took effect.
    query = _body_arg(request, "query", "") or ""
    top_k = _clamp_top_k(_body_arg(request, "top_k", 5), 5)
    results = list(await vm.search(query, top_k=top_k) or [])[:top_k]
    out = [dict(r.__dict__) for r in results]

    # trellion's search() returns bare frame hits (text "", metadata {}); fill
    # the body from the episode / traversal tables and name the kind.
    engine = _trellion_engine() if out else None
    views: dict[str, dict] = {}
    if engine is not None:
        try:
            ids = [str(o.get("record_id") or o.get("frame_id") or "") for o in out]
            views = await _episode_views(engine, [i for i in ids if i])
        except Exception as e:
            log.warning("recall_search_enrich_failed", error=str(e))
    for o in out:
        v = views.get(str(o.get("record_id") or o.get("frame_id") or ""))
        if v:
            o["kind"] = v["kind"]
            if not o.get("text"):
                o["text"] = v["text"]
            o["metadata"] = {**v["metadata"], **(o.get("metadata") or {})}
        else:
            o["kind"] = _record_kind(o.get("record_type"))
            o.setdefault("text", "")
        if not o.get("text"):
            o["text_unavailable"] = (
                "traversal record: no stored text body" if o["kind"] == "traversal"
                else "no stored text body for this record")
    return out


# ═══════════════════════════════════════════════════════════════════════
# Recall memory (existing handler continues below)
# ═══════════════════════════════════════════════════════════════════════

@worker_handler("worker.recall.packs")
async def _recall_packs(request: dict) -> Any:
    """Search recall memory (System 1 compressed recall)."""
    vm = _get_recall_memory()
    if vm is None or not getattr(vm, "_started", False):
        # Not an error (recall memory is opt-in and off by default), but it
        # is not "we searched and found nothing" either — the old reply was
        # byte-identical to a genuine empty result. Flag the reason.
        return {"success": True, "data": {
            "packs": [], "unavailable": "recall_memory not initialized"}}
    try:
        query = request.get("query", "")
        top_k = request.get("top_k", 3)

        results = await vm.search(query, top_k=top_k)
        packs = []
        for r in (results or []):
            packs.append({
                "summary": getattr(r, "summary", str(r))[:500],
                "score": getattr(r, "score", 0.0),
            })
        return {"success": True, "data": {"packs": packs}}
    except Exception as e:
        # Was: success:True + packs:[] — a failed search reported as "no
        # relevant memories".
        log.warning("recall_search_failed", error=str(e))
        return {"success": False, "error": f"recall memory search failed: {e}"}


@worker_handler("worker.recall.status")
async def _recall_status(request: dict) -> Any:
    """Return rich recall-memory status for the dashboard.

    Combines `VideoMemoryManager.status()` (started flag, backend type) with
    direct DB counts from the trellion-backed tables that the manager
    actually writes to. The Rust gateway's /api/v1/recall/status
    delegates to this so it sees the trellion-backed truth instead of
    scanning a legacy file-based directory that's no longer populated.
    """
    try:
        from sqlalchemy import text as _text

        vm = _get_recall_memory()
        # Use trellion's engine accessor — same pattern used elsewhere in
        # this file (line 137).
        engine = None
        try:
            from trellion.db.engine import get_async_engine
            engine = get_async_engine()
        except Exception:
            engine = None

        # Base status from the manager (sparse — just lifecycle flags)
        if vm is None:
            base = {"started": False, "version": 2, "backend": "postgres+faiss"}
        else:
            base = vm.status() if hasattr(vm, "status") else {"started": getattr(vm, "_started", False)}

        # Counts from the trellion-backed tables. Was: initialised to 0 with
        # `except Exception: pass`, so a missing table or a DB error rendered
        # as "recall memory is empty" — indistinguishable from a real zero.
        # Now: None (unmeasured) plus the reason, so callers can tell "no
        # records" from "could not count".
        frames_count: int | None = None
        traversals_count: int | None = None
        count_errors: dict[str, str] = {}
        # Live (not tombstoned) episodes by record_type; None until measured.
        episodes_live: int | None = None
        episodes_tombstoned: int | None = None
        by_type: dict[str, int] = {}
        if engine is None:
            count_errors["engine"] = "trellion DB engine unavailable"
        else:
            try:
                async with engine.connect() as conn:
                    r = await conn.execute(_text(
                        "SELECT record_type, is_tombstoned, COUNT(*) "
                        "FROM trellion_episodes GROUP BY record_type, is_tombstoned"
                    ))
                    frames_count = 0
                    episodes_live = 0
                    episodes_tombstoned = 0
                    for rtype, tomb, n in r.all():
                        n = int(n)
                        frames_count += n
                        if tomb:
                            episodes_tombstoned += n
                        else:
                            episodes_live += n
                            by_type[str(rtype)] = by_type.get(str(rtype), 0) + n
            except Exception as _e:
                count_errors["trellion_episodes"] = f"{type(_e).__name__}: {_e}"[:200]
            try:
                async with engine.connect() as conn:
                    r = await conn.execute(_text("SELECT COUNT(*) FROM trellion_traversal_records"))
                    traversals_count = int(r.scalar() or 0)
            except Exception as _e:
                count_errors["trellion_traversal_records"] = f"{type(_e).__name__}: {_e}"[:200]

        # Storage size if the manager exposes a storage_dir
        from ..config import recall_memory_path_env
        storage_dir = base.get("storage_dir") or recall_memory_path_env() or ""
        total_size_bytes = 0
        try:
            import os as _os
            if _os.path.isdir(storage_dir):
                for root, _dirs, files in _os.walk(storage_dir):
                    for f in files:
                        try:
                            total_size_bytes += _os.path.getsize(_os.path.join(root, f))
                        except OSError:
                            pass
        except Exception:
            pass

        # Derive the config-backed fields from the manager's actual config
        # (RecallMemoryConfig — see noomesh.config). Every value below used
        # to be a hardcoded literal presented as measured system state:
        # enabled=True, engine="python+rust", storage_backend=
        # "PostgresFAISSStorage", embedding_dim=768, promotion_threshold=0.6
        # and lifecycle.archive_interval_min=10 were printed identically
        # whether or not recall memory was configured that way — or
        # configured at all. Anything with no config field behind it is now
        # None rather than a plausible-looking constant.
        cfg = getattr(vm, "config", None)
        storage_obj = getattr(vm, "storage", None)

        data: dict[str, Any] = {
            "started":             base.get("started", False),
            # From RecallMemoryConfig.enabled; None when no manager/config
            # is wired (we cannot know, so we do not claim True).
            "enabled":             bool(cfg.enabled) if cfg is not None and hasattr(cfg, "enabled") else None,
            # No config or manager field records an "engine" — it was a
            # decorative literal. Report unknown rather than invent one.
            "engine":              None,
            "version":             base.get("version", 2),
            "backend":             base.get("backend", "postgres+faiss"),
            "storage_backend":     type(storage_obj).__name__ if storage_obj is not None else None,
            "storage_dir":         storage_dir,
            "video_count":         frames_count,    # historical naming — frames are the "videos"
            "total_records":       frames_count,
            "total_size_mb":       round(total_size_bytes / (1024 * 1024), 2),
            # `videos: []` sat next to a non-zero video_count in the same
            # payload — a self-contradicting response. The per-video list is
            # served by worker.recall.videos; omit it here unless the
            # manager actually supplied one.
            "traversals":          {
                "count": traversals_count,
                # Was 0: the archiver's in-memory buffer depth is not read
                # anywhere here, so 0 was a guess that read as "nothing
                # pending".
                "buffered": None,
            },
            "lifecycle":           {
                "archive_interval_min": getattr(cfg, "archive_interval_minutes", None)
                if cfg is not None else None,
                "live_records": episodes_live,
                "tombstoned_records": episodes_tombstoned,
            },
            "episodes_by_type":    by_type if episodes_live is not None else None,
            "embedding_dim":       getattr(cfg, "embedding_dim", None) if cfg is not None else None,
            "promotion_threshold": getattr(cfg, "promotion_confidence_threshold", None)
            if cfg is not None else None,
        }
        if isinstance(base.get("videos"), list):
            data["videos"] = base["videos"]
        if count_errors:
            data["count_errors"] = count_errors
        return {"success": True, "data": data}
    except Exception as e:
        log.warning("recall_status_failed", error=str(e))
        return {"success": False, "error": str(e)}


@worker_handler("worker.recall.archive")
async def _recall_archive(request: dict) -> Any:
    """Trigger a recall-memory archive cycle.

    Driven by the Rust gateway's recall_memory_archive loop on a periodic
    interval (default 10 min). Mirrors the dashboard "Archive Now" button
    so the loop and the manual button share the same code path.
    """
    try:
        vm = _get_recall_memory()
        if vm is None or not getattr(vm, "_started", False):
            return {"success": False, "error": "recall_memory not initialized", "archived": 0}

        # archive_all covers both conversation recall and traversal intuition
        # streams. archive_conversations is conversation-only — pick whichever
        # the manager exposes; archive_all is preferred when present.
        if hasattr(vm, "archive_all"):
            result = await vm.archive_all()
        elif hasattr(vm, "archive_conversations"):
            result = await vm.archive_conversations()
        else:
            return {"success": False, "error": "no archive method on VideoMemoryManager", "archived": 0}

        # Manager methods return varying shapes — normalize to a count if possible.
        archived = 0
        if isinstance(result, dict):
            archived = int(result.get("archived", result.get("count", 0)))
        elif isinstance(result, int):
            archived = result
        return {"success": True, "data": {"archived": archived}}
    except Exception as e:
        log.warning("recall_archive_failed", error=str(e))
        return {"success": False, "error": str(e), "archived": 0}


# ═══════════════════════════════════════════════════════════════════════
# Recall memory — additional NATS handlers (added 2026-04-29 alongside
# Rust gateway-rust/src/routes/recall.rs route expansions). Each wraps a
# single VideoMemoryManager method and returns a defensive default if the
# manager isn't started yet (gateway warming up, Trellion not yet wired).
# ═══════════════════════════════════════════════════════════════════════

def _get_recall_manager_or_none():
    """Return the live VideoMemoryManager from the service registry, or None."""
    try:
        vm = _get_recall_memory()
        if vm is None or not getattr(vm, "_started", False):
            return None
        return vm
    except Exception:
        return None


# videos/archive_status/lifecycle*/refresh/prominent added 2026-04-29
# alongside the Rust routes/recall.rs expansion — they mirror the Python
# video_router.py endpoints formerly served via FastAPI
# Depends(get_recall_memory). Now: Rust HTTP route → NATS.
@worker_handler("worker.recall.videos")
async def _recall_videos(request: dict) -> Any:
    """List video files (path + records + size). Mirrors GET /api/v1/recall/videos."""
    vm = _get_recall_manager_or_none()
    if vm is None:
        return {"success": True, "data": {
            "videos": [], "unavailable": "recall_memory not initialized"}}
    try:
        status = vm.status()
        return {"success": True, "data": {"videos": status.get("videos", [])}}
    except Exception as e:
        # Was: success:True + videos:[] — a broken status() call looked like
        # "no videos stored".
        log.warning("recall_videos_failed", error=str(e))
        return {"success": False, "error": f"video list unavailable: {e}"}


@worker_handler("worker.recall.archive_status")
async def _recall_archive_status(request: dict) -> Any:
    """Return unarchived conversation count. Mirrors GET /archive-status."""
    # Both the "no manager" and the exception path used to return
    # success:True + unarchived_count:0 — so an archiver that was missing or
    # throwing reported a clean, fully-archived backlog, and the
    # archive-backlog alarm built on this number could never fire. A backlog
    # we cannot measure must read as a failure, not as zero.
    vm = _get_recall_manager_or_none()
    if vm is None:
        return {"success": False, "error": "recall_memory not initialized — "
                                           "unarchived count not measurable"}
    if not getattr(vm, "archiver", None):
        return {"success": False, "error": "recall_memory archiver not wired — "
                                           "unarchived count not measurable"}
    try:
        count = await vm.archiver.get_unarchived_count()
        return {"success": True, "data": {"unarchived_count": count}}
    except Exception as e:
        log.warning("recall_archive_status_failed", error=str(e))
        return {"success": False, "error": f"unarchived count query failed: {e}"}


@worker_handler("worker.recall.lifecycle")
async def _recall_lifecycle(request: dict) -> Any:
    """Run a full lifecycle cycle (prune→elevate→compact). Mirrors POST /lifecycle."""
    vm = _get_recall_manager_or_none()
    if vm is None:
        # Was: zeros with success:True — "no manager" reported as "a
        # lifecycle cycle ran and changed nothing".
        return {"success": True, "data": {
            "pruned": None, "elevated": None, "compacted": None,
            "unavailable": "recall_memory not initialized"}}
    try:
        result = await vm.run_lifecycle()
        return {"success": True, "data": result}
    except Exception as e:
        log.warning("recall_lifecycle_failed", error=str(e))
        return {"success": False, "error": str(e)}


@worker_handler("worker.recall.lifecycle_stats")
async def _recall_lifecycle_stats(request: dict) -> Any:
    """Return lifecycle health metrics. Mirrors GET /lifecycle-stats."""
    vm = _get_recall_manager_or_none()
    if vm is None:
        return {"success": True, "data": {
            "unavailable": "recall_memory not initialized"}}
    try:
        stats = vm.get_lifecycle_stats()
        return {"success": True, "data": stats}
    except Exception as e:
        # Was: success:True + {} — "lifecycle stats failed" and "no
        # lifecycle activity" were the same reply.
        log.warning("recall_lifecycle_stats_failed", error=str(e))
        return {"success": False, "error": f"lifecycle stats unavailable: {e}"}


@worker_handler("worker.recall.refresh")
async def _recall_refresh(request: dict) -> Any:
    """Archive new conversations + run lifecycle. Mirrors POST /refresh."""
    vm = _get_recall_manager_or_none()
    if vm is None:
        # Was: bare {} with success:True — "refresh did nothing" and "there
        # is nothing to refresh with" were the same reply.
        return {"success": True, "data": {"unavailable": "recall_memory not initialized"}}
    try:
        result = await vm.refresh()
        return {"success": True, "data": result}
    except Exception as e:
        log.warning("recall_refresh_failed", error=str(e))
        return {"success": False, "error": str(e)}


@worker_handler("worker.recall.lifecycle_preview")
async def _recall_lifecycle_preview(request: dict) -> Any:
    """Dry-run lifecycle. Mirrors GET /lifecycle-preview.

    Reproduces the Python video_router preview by walking vm.indices and
    computing would_prune / would_elevate / would_compact without mutating.
    """
    vm = _get_recall_manager_or_none()
    if vm is None:
        # Was: all-empty/zero with success:True — a dry run that never ran
        # reported as "nothing would change".
        return {"success": True, "data": {
            "would_prune": [], "would_elevate": [], "would_compact": [],
            "prune_count": None, "elevate_count": None, "compact_count": None,
            "unavailable": "recall_memory not initialized",
        }}
    try:
        cfg = vm.config
        would_prune: list = []
        would_elevate: list = []
        would_compact: list = []
        for idx_path, index in (vm.indices or {}).items():
            for rec in index.get_stale_records(
                cfg.prune_after_days,
                prominence_floor=cfg.prune_prominence_floor,
            ):
                meta = rec.get("metadata", {})
                would_prune.append({
                    "record_id": rec.get("record_id", ""),
                    "record_type": meta.get("record_type", ""),
                    "text_preview": meta.get("text_preview", "")[:120],
                    "prominence": rec.get("prominence", 0.0),
                    "access_count": rec.get("access_count", 0),
                    "created_at": rec.get("created_at", ""),
                    "last_accessed_at": rec.get("last_accessed_at", ""),
                })
            for rec in index.get_elevation_candidates(
                prominence_ceiling=cfg.elevate_prominence_ceiling,
                prominence_floor=cfg.prune_prominence_floor,
                min_access=cfg.elevate_min_access,
            ):
                meta = rec.get("metadata", {})
                would_elevate.append({
                    "record_id": rec.get("record_id", ""),
                    "record_type": meta.get("record_type", ""),
                    "text_preview": meta.get("text_preview", "")[:120],
                    "prominence": rec.get("prominence", 0.0),
                    "access_count": rec.get("access_count", 0),
                    "created_at": rec.get("created_at", ""),
                    "last_accessed_at": rec.get("last_accessed_at", ""),
                })
            if index.tombstone_ratio >= cfg.compact_tombstone_ratio:
                would_compact.append(idx_path)
        return {"success": True, "data": {
            "would_prune": would_prune,
            "would_elevate": would_elevate,
            "would_compact": would_compact,
            "prune_count": len(would_prune),
            "elevate_count": len(would_elevate),
            "compact_count": len(would_compact),
        }}
    except Exception as e:
        log.warning("recall_lifecycle_preview_failed", error=str(e))
        return {"success": False, "error": str(e)}


@worker_handler("worker.recall.prominent")
async def _recall_prominent(request: dict) -> Any:
    """Return top-K prominent records (live episodes, traversals included).

    Was: ``vm.get_prominent_records(...) if hasattr(...) else []`` -- trellion's
    manager has no such method, so this answered ``records: []`` for every
    store, however many episodes it held. Reads trellion_episodes directly.
    """
    vm = _get_recall_manager_or_none()
    if vm is None:
        return {"success": True, "data": {
            "records": [], "unavailable": "recall_memory not initialized"}}
    try:
        top_k = _clamp_top_k(_body_arg(request, "top_k", 20), 20)
        engine = _trellion_engine()
        if engine is None:
            return {"success": False, "error": "prominent records unavailable: trellion DB engine unavailable"}
        from sqlalchemy import text as _text
        async with engine.connect() as conn:
            rows = (await conn.execute(
                _text(_EPISODE_SELECT +
                      "WHERE e.is_tombstoned = FALSE "
                      "ORDER BY e.prominence_score DESC, e.access_count DESC, e.created_at DESC "
                      "LIMIT :k"),
                {"k": top_k},
            )).all()
        records = [_episode_view(r) for r in rows]
        return {"success": True, "data": {"records": records}}
    except Exception as e:
        # Was: success:True + records:[] -- a failed lookup read as "nothing
        # is prominent".
        log.warning("recall_prominent_failed", error=str(e))
        return {"success": False, "error": f"prominent records unavailable: {e}"}
