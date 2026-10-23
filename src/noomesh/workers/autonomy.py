# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Autonomy condition checks + custom-location evaluator (worker.autonomy.*).

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


from .common import _trellion_engine
from .registry import worker_handler

log = structlog.get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# Autonomy condition checks — Trellion-side dispatch from Rust
# autonomy_loop. Rust MESH owns the loop + cluster-state evaluators;
# anything that touches Trellion's PageIndex tables comes through here.
# ═══════════════════════════════════════════════════════════════════════

# Autonomy CRUD + loop are native Rust (routes/intelligence.rs +
# autonomy_loop.rs); the Rust loop dispatches Trellion-side condition
# checks to these subjects. NB: there is no self-heal SSH revive anywhere
# any more. The cluster-executor sidecar that held the operator's keys was
# deleted 2026-09-11 with the controller->node SSH lane, and no
# `revive_node` proposal is written. An agent that answers is restarted
# over the agent rail (POST /restart); an agent that does not answer raises
# an operator alert carrying the command to run ON the node. See
# gateway-rust/src/autonomy_evaluators.rs.
# ═══════════════════════════════════════════════════════════════════════
# Autonomy handlers
# ═══════════════════════════════════════════════════════════════════════


HELD_COLUMN_LOOKUP = (
    "SELECT EXISTS (SELECT 1 FROM information_schema.columns "
    "WHERE table_name = 'docs' AND column_name = 'held_at' "
    "AND table_schema = ANY (current_schemas(false)))"
)


async def _has_held_column(conn) -> bool:
    """Whether trellion's migration 105 (docs.held_at) has run."""
    from sqlalchemy import text as _text

    try:
        return bool((await conn.execute(_text(HELD_COLUMN_LOOKUP))).scalar())
    except Exception:  # noqa: BLE001 - unknown means the plain form, which is always safe
        return False


@worker_handler("worker.autonomy.check_rag")
async def _autonomy_check_rag(request: dict) -> Any:
    """RAG-store health check for the Rust autonomy loop's self-heal path.

    The Rust loop dispatched this subject for rag/memory/knowledge issue
    categories, but no handler existed — the loop reported "healing" while
    nothing ran (fixed 2026-07-18). Combines the two neighbouring checks:
    unembedded-page count and page→entity gap, same SQL + timeout
    discipline as _autonomy_unembedded_documents above.
    """
    async def _query():
        from sqlalchemy import text as _text
        try:
            engine = _trellion_engine()
        except Exception:
            engine = None
        if engine is None:
            # Was: return all-zero counts, which the wrapper below then
            # dressed up as {"success": True, ...}. So "the KB database is
            # unreachable" reached the Rust self-heal loop as
            # "unembedded_pages=0, entity_gap=0" — i.e. nothing to do — and
            # it stood down. An unmeasurable KB is a failure, not an empty
            # one. Raise so the wrapper's except returns success=False.
            raise RuntimeError(
                "trellion DB engine unavailable — KB counts not measurable"
            )
        async with engine.connect() as conn:
            # Held documents (docs.held_at) are kept out of embedding and
            # extraction on purpose, so their pages are neither a backlog
            # nor an entity gap. Trellion's migration 105 adds the column;
            # before it has run the plain form is used (a query naming a
            # missing column would fail the whole check).
            not_held = "d.held_at IS NULL" if await _has_held_column(conn) else "TRUE"
            pages = int((await conn.execute(_text(
                "SELECT COUNT(*) FROM pages p JOIN docs d ON d.doc_id = p.doc_id "
                f"WHERE {not_held}"
            ))).scalar() or 0)
            try:
                entities = int((await conn.execute(_text("SELECT COUNT(*) FROM entities"))).scalar() or 0)
            except Exception:
                entities = 0
            unembedded = int((await conn.execute(_text(
                # "Unembedded" means no usable vector: either no row at
                # all, or a row whose embedding is NULL. The NULL case is
                # what a dimension migration leaves behind (rows kept for
                # their ids/metadata, vectors blanked), and matching only
                # on a missing row reported "no work" for a corpus that was
                # entirely unembedded — so the re-embed never started.
                "SELECT COUNT(*) FROM pages p "
                "JOIN docs d ON d.doc_id = p.doc_id "
                "LEFT JOIN page_embeddings pe ON pe.page_id = p.page_id "
                f"WHERE {not_held} "
                "AND (pe.page_id IS NULL OR pe.embedding IS NULL)"
            ))).scalar() or 0)
        return {"pages": pages, "entities": entities,
                "unembedded_pages": unembedded,
                "entity_gap": max(0, pages - entities)}
    try:
        import asyncio
        stats = await asyncio.wait_for(_query(), timeout=15.0)
        return {"success": True, "data": stats}
    except asyncio.TimeoutError:
        log.warning("autonomy_check_rag_timeout",
                    note="SQL took >15s — likely connection-pool contention")
        return {"success": False, "error": "check_rag timed out"}
    except Exception as e:
        log.debug("autonomy_check_rag_failed", error=str(e))
        return {"success": False, "error": str(e)}
