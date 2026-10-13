# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Backward-compat shim — memory lives in the add-on packages now.

Phase 4 extracted the memory subsystem from
``noomesh.memory`` to ``trellion.live`` (a separate repo). This shim
re-exports the public API so existing ``from noomesh.memory.X import Y``
imports keep working.

New code should import from ``trellion.live`` (or ``trellion`` for the
top-level facade) directly. This shim will be removed once all internal
import sites have been updated.

WHAT IS NOT HERE
----------------

Capabilities an add-on supplies (graph traversal, graph ranking, the temporal
graph, retrieval feedback and the like) are NOT served through this name.
They are asked for by role (``noomesh.addon_roles``), and the add-on declares
what fills each. A caller that needs one asks for the role; an install
without the add-on gets the "not available" path the caller already has.

What IS an error is a module this shim advertises that trellion does not
supply: those are named, once, at WARNING.
"""
from __future__ import annotations

import sys as _sys

# Re-export every name trellion.live exposes
from trellion.live import *  # noqa: F401, F403

# Bind submodules so `from noomesh.memory.X import Y` resolves to the
# implementation, wherever it now lives. Each submodule is registered under
# both names in `sys.modules` so absolute imports work.
import trellion.live as _live  # noqa: E402

_SUBMODULES = (
    "_messaging",
    "_tls",
    "context_files",
    "conversation_store",
    "embedding_worker",
    "evidence",
    "graph_builder",
    "graph_extractor",
    "manager",
    "pageindex_embedder",
    "pageindex_ingestion",
    "pageindex_retriever",
    "pageindex_schema",
    "pageindex_store",
    "persona",
    "pgvector_store",
    "rag_generator",
    "rag_integration",
    "rag_orchestrator",
    "rag_verifier",
    "store",
    "video",
)

def _resolve_submodule(name: str):
    """The ``trellion.live`` submodule *name*, or ``None``."""
    import importlib

    try:
        return importlib.import_module(f"trellion.live.{name}")
    except ImportError:
        return None


def _bind_submodules(live) -> "list[str]":
    """Register every advertised submodule. Returns the names nobody supplied.

    *live* is passed in, and `sys` imported here, rather than both being read
    from module scope: the module ends by deleting its private aliases, so a
    function closing over them would be correct at import time and a
    `NameError` on any later call. Ruff caught exactly that (F821).
    """
    import sys

    missing: list[str] = []
    for _name in _SUBMODULES:
        _mod = getattr(live, _name, None) or _resolve_submodule(_name)
        if _mod is None:
            missing.append(_name)
            continue
        sys.modules[f"noomesh.memory.{_name}"] = _mod
    return missing


_MISSING = _bind_submodules(_live)

if _MISSING:
    import structlog as _structlog

    _structlog.get_logger(__name__).warning(
        "memory.submodules_unresolved",
        missing=_MISSING,
        detail=(
            "these names are advertised by noomesh.memory and supplied by "
            "trellion.live; imports of them will raise ModuleNotFoundError"
        ),
    )

del _sys, _live
