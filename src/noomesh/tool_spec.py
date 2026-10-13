# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Shared types for tool specs + registry.

⚠️ NOT THE PRODUCTION TOOL SCHEMA SOURCE.
The authoritative tool definitions are the ``@tool`` declarations in
``noomesh/tools/defs/`` (see ``noomesh/tools/decl.py``). The flow is:

    @tool declaration → `noo tools export` → config/tools.json
        → Rust coordinator (gateway-rust/src/state.rs caches the schemas;
          coordinator/backend.rs::get_tool_nats_subject routes calls)
        → NATS worker.* → @worker_handler in noomesh/workers/

This Python ``ToolSpec`` / ``ToolRegistry`` survives only for in-process
Python tool execution paths (plugins, tests, non-Rust deployments — the
``tools/custom/`` drop-in loader was removed; sandboxed
extension code is a skill now). The ``handler`` callable on a ``ToolSpec`` is
invoked on the *worker* side (``workers/tools.py::_tool_generic``), not
by a coordinator reading this registry.

To add or modify a tool the LLM can call: see "How to add a tool" in
``noomesh/tools/decl.py``.

Lives at the top level (NOT inside `tools/` or `cluster/`) so it can be
imported by both planes without creating a cross-boundary dependency:

    (archived: legacy/python-cluster-reference/tool_registry.py) ──┐
                                 ├──→ noomesh.tool_spec  (this file)
    tools/base.py + registry.py ─┘

Per the design's coupling audit, this is the load-bearing piece that
makes the harness/cluster split possible: MESH no longer imports from
tools/ (HARNESS), and HARNESS still gets its types via re-export.

What lives here:
- ToolSpec          — metadata + handler (agnostic of which harness)
- ToolRegistry      — register/get/list (the cluster-relevant operations)

What stays in tools/registry.py:
- ToolRegistry (harness variant) — BM25/jaccard ``select_for_prompt`` +
  agent-loop-specific helpers (HARNESS concern: how an agent picks tools
  given a prompt)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List


@dataclass
class ToolSpec:
    """A tool the cluster knows about. Both HARNESS and MESH see the same shape."""
    name: str
    description: str
    parameters: Dict[str, Any]
    handler: Callable[[Dict[str, Any]], str]

    def to_ollama(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


class ToolRegistry:
    """Minimal registry — register/get/list. Cluster-side routing reads
    this to know which tools exist; harnesses register tools into it.

    Intentionally does NOT contain agent-loop concerns (intent inference,
    BM25 selection). Those live in the HARNESS-side ``tools.registry.ToolRegistry``
    (same interface plus ``select_for_prompt``).
    """

    def __init__(self) -> None:
        self._tools: Dict[str, ToolSpec] = {}

    def register(self, tool: ToolSpec) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> ToolSpec:
        if name not in self._tools:
            raise KeyError(f"Unknown tool: {name}")
        return self._tools[name]

    def list(self) -> Iterable[ToolSpec]:
        return self._tools.values()

    def to_ollama_tools(self) -> List[dict]:
        return [tool.to_ollama() for tool in self._tools.values()]
