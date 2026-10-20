# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Lazy singleton facade over :class:`AgentOrchestrator` for worker handlers.

The Rust-primary port (95f2af2) wrote worker_pool NATS handlers against
``from ..agents.orchestrator import get_orchestrator`` — a module that never
existed. The equivalent wiring lived only in gateway/app.py's FastAPI
lifespan, which never runs under Rust-primary, so /api/agent/run,
/api/agents/collaborate and /api/agents/roles all returned
"No module named 'noomesh.agents.orchestrator'". This module is that
missing home: a lazily-built orchestrator plus thin adapter methods matching
exactly what the worker_pool handlers call.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger()

_singleton: Optional["_OrchestratorFacade"] = None


def _resolve_llm():
    """The orchestrator's LLM: the gateway's ``/v1/chat/completions``.

    Mesh-routed with failover, ``model: default`` (any live chat node). It
    used to dial ``PAGEINDEX_LLM_URL`` (the controller's own vLLM) with
    ``VLLM_MODEL``: one node, no fallback (i145). ``None`` only when the
    client cannot be built; AgentOrchestrator then falls back to config Ollama.
    """
    from .. import llm_purposes
    from ..cluster.cluster_auth import internal_gateway_headers
    from ..config import get_config
    from ..llm.openai_compat import OpenAICompatClient

    try:
        return OpenAICompatClient(
            base_url=llm_purposes.gateway_url(),
            model="default",
            options=get_config().ollama.options,
            headers=internal_gateway_headers("orchestrator"),
        )
    except Exception as e:
        logger.warning("orchestrator_llm_resolve_failed", error=str(e))
    return None  # AgentOrchestrator falls back to config Ollama


class _OrchestratorFacade:
    """Adapts the worker_pool handler call shapes onto AgentOrchestrator."""

    def __init__(self) -> None:
        from ..config import get_config
        from .multi_agent import AgentOrchestrator

        self._orch = AgentOrchestrator(get_config(), llm_factory=_resolve_llm)

    def list_roles(self) -> List[Dict[str, str]]:
        from .multi_agent import AgentRole

        return [{"role": r.value, "name": r.name.title()} for r in AgentRole]

    def list_backends(self) -> List[str]:
        client = _resolve_llm()
        return [type(client).__name__] if client else ["ollama (config fallback)"]

    async def run_agent(self, prompt: str, role: str = "") -> Dict[str, Any]:
        from .multi_agent import AgentRole

        preferred = None
        if role:
            try:
                preferred = AgentRole(role.lower())
            except ValueError:
                return {"error": f"unknown role '{role}'",
                        "known_roles": [r.value for r in AgentRole]}
        response = await self._orch.route_task(prompt, preferred_role=preferred)
        return {"response": response, "role": preferred.value if preferred else "auto"}

    async def collaborate(self, prompt: str, roles: Optional[List[str]] = None) -> Dict[str, Any]:
        from .multi_agent import AgentRole

        try:
            workflow = [AgentRole(r.lower()) for r in (roles or [])]
        except ValueError as e:
            return {"error": f"unknown role in {roles}: {e}",
                    "known_roles": [r.value for r in AgentRole]}
        if not workflow:
            workflow = [AgentRole.RESEARCHER, AgentRole.ANALYST]
        result = await self._orch.collaborate(prompt, workflow=workflow)
        # Dict[AgentRole, str] → JSON-safe str keys
        return {"results": {role.value: text for role, text in result.items()}}


def get_orchestrator() -> Optional[_OrchestratorFacade]:
    """Lazy singleton — heavy agent stack only loads on first agent request."""
    global _singleton
    if _singleton is None:
        try:
            _singleton = _OrchestratorFacade()
            logger.info("agent_orchestrator_initialized", context="worker_pool")
        except Exception as e:
            logger.error("agent_orchestrator_init_failed", error=str(e))
            return None
    return _singleton
