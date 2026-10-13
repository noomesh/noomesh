# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Shared service accessors used across worker handler modules.

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


import structlog


log = structlog.get_logger(__name__)

def _get_conversation_store():
    """The ConversationStore the worker pool initialised, or None."""
    try:
        from ..gateway.deps import services
        if getattr(services, "conversation_store", None) is not None:
            return services.conversation_store
    except Exception:
        pass
    return None


def _get_coordinator():
    """The CoordinatorAgent on services, or None (gateway/coordinator.py is gone)."""
    try:
        from ..gateway.deps import services
        if getattr(services, "coordinator", None) is not None:
            return services.coordinator
    except Exception:
        pass
    return None


def _get_rag():
    """The PageIndexRAG instance ``_init_python_services`` set, or None.

    (The fallbacks to ``noomesh.gateway.app`` / ``gateway.coordinator``
    module globals were removed: both modules were deleted in the Rust port.)"""
    try:
        from ..gateway.deps import services
        if getattr(services, "pageindex_rag", None) is not None:
            return services.pageindex_rag
    except Exception:
        pass
    return None


def _trellion_engine():
    """Lazy-init trellion's async engine for the snapshot handlers.

    The Rust gateway owns its own native sqlx pool and doesn't run
    noomesh's Python ``init_db`` lifespan, so trellion's engine
    globals never get set via ``set_engines()``. We bootstrap them on
    first use from ``NOO_TRELLION_DATABASE_URL`` (the scoped
    ``noo_trellion`` role — set in the noo-trellion container from
    WP-T23 phase 3, mirrors ``NOO_EVOLVE_DATABASE_URL``), falling back
    to ``DATABASE_URL`` / ``PAGEINDEX_DSN`` when unset (in-gateway
    worker pool — unchanged behavior).
    """
    import os
    from trellion.db.engine import get_async_engine, init_engine
    try:
        return get_async_engine()
    except RuntimeError:
        dsn = (
            os.environ.get("NOO_TRELLION_DATABASE_URL")
            or os.environ.get("DATABASE_URL")
            or os.environ.get("PAGEINDEX_DSN")
            or os.environ.get("PGVECTOR_URL")
        )
        if not dsn:
            raise RuntimeError("trellion engine: no DSN in env")
        init_engine(dsn)
        return get_async_engine()


def _unwrap_body(request: dict) -> dict:
    """Resolve the body shape variants the worker pool can receive.

    The Rust catch-all forwards bodies as-is (top-level keys); other
    callers wrap inside ``{"params": {...}}``. Treat the unwrapped form
    as the source of truth.
    """
    if isinstance(request, dict) and "params" in request and isinstance(request["params"], dict):
        # Merge so top-level keys (label, etc.) survive too
        merged = dict(request["params"])
        for k, v in request.items():
            if k != "params" and k not in merged:
                merged[k] = v
        return merged
    return request or {}
