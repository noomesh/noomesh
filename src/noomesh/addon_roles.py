# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The roles noomesh asks an installed add-on to fill, and how it asks.

noomesh never names an add-on's package, module or class. It asks for a ROLE
by a generic name; an add-on that fills the role declares it, and the lookup
returns what it declared. Two seams carry this:

* trellion's provider mapping (``trellion.live._intel.addon_provider``): the
  add-on trellion discovers declares ``TRELLION_PROVIDERS`` at its package root,
  role name -> ``"module:attribute"``. The roles below that trellion also uses
  carry trellion's own names.
* noomesh's extension mapping (:func:`extensions`), for add-ons that extend
  noomesh itself (CLI groups, MCP tool definitions): an installed package that
  declares ``NOOMESH_EXTENSIONS`` the same way, found through the
  ``noomesh.addons`` entry-point group or the ``NOOMESH_ADDON_PACKAGES``
  environment list (for a package that is mounted rather than installed).

Absent add-on, a role the add-on does not declare, or a declaration that does
not resolve all read the same to the caller: ``provider`` raises ImportError,
``extensions`` returns nothing. A declared extension that fails to load is
logged at WARNING; an absent one is silent, because absence is a tier.
"""
from __future__ import annotations

import importlib
import os
from typing import Any

import structlog

log = structlog.get_logger(__name__)

# -- Roles trellion defines (same names as ``trellion.live._intel``) ----------
#: ``factory(store)`` -> object with ``compute_signals(force_full=...)``.
GRAPH_METRICS = "graph_metrics"
#: ``factory()`` -> object with ``get_graph_boosted_entities(query=, seed_entity_ids=, store=, top_k=)``.
GRAPH_RANKER = "graph_ranker"

# -- Roles noomesh defines (an add-on declares each in its provider mapping) --
#: ``factory(engine)`` -> the temporal graph store the extractor writes to.
TEMPORAL_GRAPH_STORE = "temporal_graph_store"
#: ``factory(graph_store=, llm_url=, model=, ...)`` -> conversation triple extractor.
CONVERSATION_EXTRACTOR = "conversation_extractor"
#: ``fn(persist_path=...)`` starts the retrieval-feedback tracker in this process.
RETRIEVAL_TRACKER_INIT = "retrieval_tracker_init"
#: Module-like object: ``supports(op)`` plus the audience-filtered graph reads.
AUDIENCE_SCOPE = "audience_scope"
#: Module-like object: the saved-walks reads and ``WalkPolicy``.
WALK_STORE = "walk_store"
#: ``fn(None, query)`` -> query intent (read-only, unbound on purpose).
QUERY_CLASSIFIER = "query_classifier"

#: Extension kinds an add-on may contribute to noomesh itself.
CLI_GROUPS = "cli_groups"
MCP_TOOL_DEFS = "mcp_tool_defs"

ENTRY_POINT_GROUP = "noomesh.addons"
ENV_PACKAGES = "NOOMESH_ADDON_PACKAGES"
EXTENSIONS_ATTR = "NOOMESH_EXTENSIONS"


def provider(role: str) -> Any:
    """What the installed add-on declares for ``role``; ImportError when nothing does."""
    from trellion.live._intel import addon_provider

    return addon_provider(role)


def _resolve(ref: str) -> Any:
    module, _, attr = str(ref).partition(":")
    obj: Any = importlib.import_module(module)
    for part in filter(None, attr.split(".")):
        obj = getattr(obj, part)
    return obj


def _declared_packages() -> "list[str]":
    names: list[str] = []
    try:
        from importlib.metadata import entry_points

        names += [ep.value.partition(":")[0].strip() for ep in entry_points(group=ENTRY_POINT_GROUP)]
    except Exception:  # noqa: BLE001 - metadata backends differ across runtimes
        pass
    names += [n.strip() for n in os.getenv(ENV_PACKAGES, "").split(",")]
    seen: list[str] = []
    for n in names:
        if n and n not in seen:
            seen.append(n)
    return seen


def extensions(kind: str) -> "list[tuple[str, Any]]":
    """``(name, object)`` for every declared extension of ``kind``, in discovery order.

    Each add-on package declares ``NOOMESH_EXTENSIONS = {kind: {name: "module:attr"}}``.
    A package that is not importable is skipped silently (not installed);
    one that is importable but whose declaration does not resolve is skipped
    with a WARNING (installed and broken must not look like absent).
    """
    found: list[tuple[str, Any]] = []
    for package in _declared_packages():
        try:
            declared = getattr(importlib.import_module(package), EXTENSIONS_ATTR, None) or {}
        except ImportError:
            continue
        except Exception as e:  # noqa: BLE001
            log.warning("addon.extensions_unreadable", package=package, error=repr(e))
            continue
        refs = declared.get(kind) if isinstance(declared, dict) else None
        for name, ref in (refs or {}).items():
            try:
                found.append((name, _resolve(ref)))
            except Exception as e:  # noqa: BLE001
                log.warning("addon.extension_failed", kind=kind, name=name, error=repr(e))
    return found
