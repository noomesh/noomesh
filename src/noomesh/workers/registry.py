# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Worker-handler registry — the canonical registration idiom for NATS
``worker.*`` subjects (mirrors ``pipeline/core.py``'s ``@capability``).

Domain modules under ``noomesh.workers`` declare handlers with::

    @worker_handler("worker.rag.query")
    async def _rag_query(request: dict) -> Any: ...

The handler receives the decoded JSON request body (the same ``dict``
the old ``worker_pool._HANDLERS`` dispatch passed) and returns a
JSON-serialisable payload. The dispatch shell in
``noomesh.gateway.worker_pool`` wraps the return value in the
``{"success": True, "data": ...}`` / ``{"success": False, "error": ...}``
reply envelope — handlers never touch the NATS message directly.

Discovery: ``noomesh.workers.__init__`` imports every domain module,
so importing the package populates this registry eagerly. Modules must
stay cheap to import (heavy deps remain lazy inside handler bodies).
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict, Optional

WorkerHandler = Callable[[dict], Awaitable[Any]]

_REGISTRY: Dict[str, WorkerHandler] = {}


def worker_handler(subject: str) -> Callable[[WorkerHandler], WorkerHandler]:
    """Register an async handler for a NATS worker subject.

    Decorators stack for handlers that serve multiple subjects (e.g.
    ``_tool_generic``). Re-registering the *same* function under the same
    subject is a no-op; registering a *different* function for an
    already-claimed subject raises — silent subject collisions were only
    survivable in the old single-file dict because Python name shadowing
    made them invisible.
    """

    def _register(fn: WorkerHandler) -> WorkerHandler:
        existing = _REGISTRY.get(subject)
        if existing is not None and existing is not fn:
            raise ValueError(
                f"duplicate worker handler for {subject!r}: "
                f"{existing.__module__}.{existing.__qualname__} vs "
                f"{fn.__module__}.{fn.__qualname__}"
            )
        _REGISTRY[subject] = fn
        return fn

    return _register


def get_handler(subject: str) -> Optional[WorkerHandler]:
    """Return the handler registered for ``subject``, or None."""
    return _REGISTRY.get(subject)


def all_handlers() -> Dict[str, WorkerHandler]:
    """Snapshot of subject -> handler (copy; safe to iterate/mutate)."""
    return dict(_REGISTRY)
