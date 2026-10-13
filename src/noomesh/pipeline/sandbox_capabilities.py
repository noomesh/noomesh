# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Sandbox capabilities — container-executed capabilities folded into the pipeline registry.

Each ``manifest.yml`` under ``skills/builtins/*/`` or ``~/.noo/skills/*/``
(``$NOO_SKILLS_DIR``) declares a *sandbox capability*: I/O params, container
config, and permissions. This module scans those manifests (via the existing
:class:`noomesh.skills.SandboxCapabilityRegistry`) and registers each one as
a pipeline ``@capability`` named ``sandbox.<name>``, whose implementation is
the existing Docker-sandbox execution path
(:class:`noomesh.skills.SandboxExecutor` → node-agent ``POST /api/skills/run``).

That makes a sandboxed capability a first-class pipeline step:

    Step(capability="sandbox.text_summarizer",
         config={"style": "bullet_points"},
         inputs={"text": "article_text"},
         output="summary")

A generic ``sandbox_run`` capability is also registered for dynamic
composition (config: ``{name, inputs?, node_id?}``).

The step's merged config *is* the capability's input dict (reserved pipeline
keys stripped); required inputs are validated against the manifest by the
executor. On failure the capability raises, so Step ``retries`` /
``on_error`` / ``validate`` semantics apply as with any other capability.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

import structlog

from .core import capability, registered_capabilities

log = structlog.get_logger("pipeline.sandbox")

# Config keys consumed by the wrapper itself, never forwarded as inputs.
_RESERVED_KEYS = {"node_id"}

_PREFIX = "sandbox."


async def execute_sandbox_capability(
    name: str,
    inputs: Dict[str, Any],
    node_id: Optional[str] = None,
):
    """Execute a sandbox capability by manifest name; returns a SandboxResult.

    Shared by the pipeline ``@capability`` wrappers and the
    ``worker.tool.skill`` tool bridge (gateway ``SkillToolExecutor``) so both
    surfaces run the exact same path: registry lookup → SandboxExecutor →
    node-agent container run.
    """
    from ..skills import get_sandbox_executor, get_sandbox_registry
    from ..skills.skill_executor import SandboxResult

    registry = get_sandbox_registry()
    manifest = registry.get(name)
    if not manifest:
        return SandboxResult(success=False, error=f"Unknown skill: {name}")
    executor = get_sandbox_executor()
    return await executor.execute_skill(manifest, inputs, node_id=node_id)


async def run_sandbox_capability(
    name: str,
    inputs: Dict[str, Any],
    node_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute a sandbox capability and return its output dict; raise on failure."""
    result = await execute_sandbox_capability(name, inputs, node_id=node_id)
    if not result.success:
        raise RuntimeError(f"sandbox capability '{name}' failed: {result.error}")
    return result.output


def _make_capability(manifest_name: str):
    async def _sandbox_cap(ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        cfg = dict(config)
        node_id = cfg.pop("node_id", None)
        inputs = {k: v for k, v in cfg.items() if k not in _RESERVED_KEYS}
        return await run_sandbox_capability(manifest_name, inputs, node_id=node_id)

    _sandbox_cap.__name__ = f"sandbox_{manifest_name}"
    _sandbox_cap.__doc__ = f"Sandbox capability '{manifest_name}' (container-executed; see its manifest.yml)."
    return _sandbox_cap


@capability("sandbox_run")
async def sandbox_run(ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Generic sandbox runner. config: {name, inputs?, node_id?}.

    When ``inputs`` is omitted, all remaining config keys are forwarded as
    the capability's inputs.
    """
    cfg = dict(config)
    name = cfg.pop("name", None)
    if not name:
        raise ValueError("sandbox_run requires config['name']")
    node_id = cfg.pop("node_id", None)
    inputs = cfg.pop("inputs", None)
    if inputs is None:
        inputs = cfg
    return await run_sandbox_capability(name, inputs, node_id=node_id)


def register_sandbox_capabilities(rescan: bool = False) -> int:
    """Scan manifest directories and register each as ``sandbox.<name>``.

    Idempotent — re-registering an existing name just overwrites it with an
    equivalent wrapper. Returns the number of sandbox capabilities registered.
    """
    from ..skills import get_sandbox_registry

    registry = get_sandbox_registry()
    if rescan:
        registry.scan()

    count = 0
    for name in registry.names():
        capability(_PREFIX + name)(_make_capability(name))
        count += 1
    log.info("sandbox_capabilities_registered", count=count,
             names=[_PREFIX + n for n in registry.names()])
    return count


def sandbox_capability_names() -> list[str]:
    """Registered pipeline capability names that are sandbox-backed."""
    return [n for n in registered_capabilities() if n.startswith(_PREFIX)]
