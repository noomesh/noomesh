# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Declarative tool registry — the authoritative source for ``config/tools.json``.

The ``@tool`` declarations in ``noomesh/tools/defs/`` are the single
place tool schemas are defined. ``noo tools export`` renders the registry
to ``config/tools.json``, which the Rust coordinator reads at startup
(``gateway-rust/src/state.rs`` caches the schemas for the LLM;
``coordinator/backend.rs::get_tool_nats_subject`` uses ``nats_subject``
to route tool calls to the Python worker pool over NATS).

Flow::

    @tool declaration (tools/defs/)          [authoritative]
        │  noo tools export
        ▼
    config/tools.json                        [generated artifact]
        │  read at startup
        ▼
    Rust coordinator → LLM sees schema → tool call
        │  nats_subject (default worker.tool.generic)
        ▼
    NATS → @worker_handler in noomesh/workers/  (executes the tool)

How to add a tool
-----------------
1. Declare the schema in ``noomesh/tools/defs/`` (pick the module that
   matches the domain, or add one and import it from ``defs/__init__``)::

       from ..decl import tool

       tool(
           name="my_tool",
           description="What the LLM should know about it.",
           parameters={
               "type": "object",
               "properties": {"arg": {"type": "string", "description": "..."}},
               "required": ["arg"],
           },
           tags=["core", "mydomain"],
           speed="fast",                      # "fast" | "slow"
           nats_subject="worker.tool.generic",  # omit to use the generic fallback
       )

2. Make sure something executes it. The Rust coordinator executes its
   native set in-process first (``gateway-rust/src/tools.rs
   execute_native`` — the design ported the core noo_*/web_search tools
   there); everything else arrives at the NATS subject from step 1, where
   the generic handlers in ``noomesh/workers/tools.py``
   (``worker.tool.generic`` / ``worker.tool.python``) dispatch by tool
   name to the MCP ToolDef registry and legacy executors. (The
   ``tools/custom/`` drop-in rung was removed — in-process
   extension code is deprecated in favor of sandboxed skills; start from
   ``noo skills scaffold``.) If your tool needs a dedicated subject + handler, declare
   both together — the decorators stack::

       from noomesh.workers.registry import worker_handler
       from noomesh.tools.decl import tool

       @tool(
           name="my_tool",
           description="...",
           parameters={...},
           nats_subject="worker.tool.my_tool",
       )
       @worker_handler("worker.tool.my_tool")
       async def _my_tool(request: dict) -> Any:
           ...

3. Regenerate the artifact: ``noo tools export`` (or ``--check`` in CI to
   verify the file matches the registry). Restart the Rust gateway to pick
   up the new schema.

Plugins register :class:`~noomesh.tool_spec.ToolSpec` objects through the
Plugin API; ``PluginManager`` mirrors them into this registry with
``export=False`` so plugin tools are visible here without leaking into the
generated ``config/tools.json``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

# Header fields of the generated file — kept identical to the historical
# hand-maintained config/tools.json so the export is drop-in.
TOOLS_JSON_VERSION = "1.0"
TOOLS_JSON_DESCRIPTION = (
    "Tool schemas shared between Python and Rust gateways. Single source of truth."
)


@dataclass
class ToolDecl:
    """A declared tool: LLM-facing schema + coordinator routing metadata.

    Instances are created via :func:`tool` (which registers them). Calling
    the instance as a decorator binds a Python handler, so ``@tool(...)``
    stacks naturally above ``@worker_handler(...)``.
    """

    name: str
    description: str
    parameters: Dict[str, Any]
    tags: List[str] = field(default_factory=list)
    speed: str = "fast"
    nats_subject: Optional[str] = None
    handler: Optional[Callable[..., Any]] = None
    export: bool = True  # False → visible in-process only (e.g. plugin tools)
    source: str = "builtin"

    def __call__(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Decorator form: bind ``fn`` as the local handler, return it unchanged."""
        self.handler = fn
        return fn

    def to_schema(self) -> Dict[str, Any]:
        """OpenAI function-calling schema (what the LLM sees)."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_tools_json_entry(self) -> Dict[str, Any]:
        """Full ``core_tools`` entry, key order matching config/tools.json."""
        entry = self.to_schema()
        entry["tags"] = list(self.tags)
        entry["speed"] = self.speed
        if self.nats_subject:
            entry["nats_subject"] = self.nats_subject
        return entry


@dataclass
class ToolGroup:
    """An ``extended_tool_groups`` entry: named tools + activation keywords.

    Group members are tool *names* (schemas are discovered at runtime via
    ``noo_tool_search`` / the MCP catalog), matching the consumed format.
    """

    name: str
    tools: List[str]
    keywords: List[str]


# Registration order is preserved (dicts are ordered) and IS the export
# order, so declaration order in defs/ modules is deterministic output order.
_DECLS: Dict[str, ToolDecl] = {}
_GROUPS: Dict[str, ToolGroup] = {}


def tool(
    *,
    name: str,
    description: str,
    parameters: Dict[str, Any],
    tags: Sequence[str] = (),
    speed: str = "fast",
    nats_subject: Optional[str] = None,
    export: bool = True,
    source: str = "builtin",
) -> ToolDecl:
    """Declare a tool. Usable standalone (schema-only) or as a decorator.

    Raises on a conflicting re-registration (same guard as
    ``workers.registry.worker_handler`` — silent collisions are bugs).
    """
    decl = ToolDecl(
        name=name,
        description=description,
        parameters=parameters,
        tags=list(tags),
        speed=speed,
        nats_subject=nats_subject,
        export=export,
        source=source,
    )
    existing = _DECLS.get(name)
    if existing is not None:
        if existing.to_tools_json_entry() == decl.to_tools_json_entry():
            return existing  # idempotent re-declaration (module reload)
        raise ValueError(f"duplicate tool declaration for {name!r} (from {existing.source})")
    _DECLS[name] = decl
    return decl


def tool_group(name: str, *, tools: Sequence[str], keywords: Sequence[str]) -> ToolGroup:
    """Declare an extended tool group (lazy-loaded tools + match keywords)."""
    group = ToolGroup(name=name, tools=list(tools), keywords=list(keywords))
    existing = _GROUPS.get(name)
    if existing is not None:
        if (existing.tools, existing.keywords) == (group.tools, group.keywords):
            return existing
        raise ValueError(f"duplicate tool group declaration for {name!r}")
    _GROUPS[name] = group
    return group


def register_plugin_tool(spec: Any, source: str) -> Optional[ToolDecl]:
    """Mirror a plugin-registered ToolSpec into this registry (export=False).

    Idempotent: returns None if the name is already declared.
    """
    if spec.name in _DECLS:
        return None
    decl = ToolDecl(
        name=spec.name,
        description=spec.description,
        parameters=spec.parameters,
        handler=getattr(spec, "handler", None),
        export=False,
        source=source,
    )
    _DECLS[spec.name] = decl
    return decl


def all_tools() -> Dict[str, ToolDecl]:
    """Snapshot of name -> declaration (copy; safe to iterate)."""
    return dict(_DECLS)


def all_groups() -> Dict[str, ToolGroup]:
    """Snapshot of name -> group (copy; safe to iterate)."""
    return dict(_GROUPS)


def get_tool(name: str) -> Optional[ToolDecl]:
    return _DECLS.get(name)


def _load_defs() -> None:
    """Import the built-in declarations (idempotent via module cache)."""
    from . import defs  # noqa: F401


def export_tools_dict() -> Dict[str, Any]:
    """Render the registry to the config/tools.json structure."""
    _load_defs()
    return {
        "_version": TOOLS_JSON_VERSION,
        "_description": TOOLS_JSON_DESCRIPTION,
        "core_tools": [
            decl.to_tools_json_entry() for decl in _DECLS.values() if decl.export
        ],
        "extended_tool_groups": {
            group.name: {"tools": list(group.tools), "keywords": list(group.keywords)}
            for group in _GROUPS.values()
        },
    }


def render_tools_json() -> str:
    """Deterministic serialization: insertion-order keys, 2-space indent."""
    return json.dumps(export_tools_dict(), indent=2, ensure_ascii=False) + "\n"


def default_tools_json_path() -> Path:
    """Locate config/tools.json (existing deployment paths, then repo layout)."""
    candidates = [
        Path("/app/config/tools.json"),
        Path("config/tools.json"),
        Path(__file__).resolve().parents[3] / "config" / "tools.json",
    ]
    for path in candidates:
        if path.exists():
            return path
    return candidates[-1]


def tools_json_matches(path: Optional[Path] = None) -> bool:
    """Normalized deep-equal between the registry export and the file on disk.

    Byte formatting may differ; parsed content may not (dict key order is
    irrelevant to ``==``; list order is significant and intentional).
    """
    target = path or default_tools_json_path()
    on_disk = json.loads(target.read_text(encoding="utf-8"))
    return on_disk == export_tools_dict()
