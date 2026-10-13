# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Lazy singleton workflow registry for worker handlers.

Same port gap as agents/orchestrator.py: the old worker-pool workflows
handlers (archived in legacy/python-workers-reference/inference.py) were
written against ``workflows.registry``, which never existed — ``POST /api/workflows/run`` returned "No module named
'noomesh.workflows.registry'" while the executor and the built-in workflow
definitions sat unused in workflow.py. (``GET /api/workflows`` never noticed
because the Rust gateway serves the list natively from hard-coded templates
that mirror these three.)
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger()

_singleton: Optional["WorkflowRegistry"] = None


class WorkflowRegistry:
    """Name → Workflow lookup + execution via WorkflowExecutor."""

    def __init__(self) -> None:
        from .workflow import (
            CODE_DEVELOPMENT_WORKFLOW,
            DATA_ANALYSIS_WORKFLOW,
            RESEARCH_WORKFLOW,
        )

        self._workflows = {
            w.name: w
            for w in (RESEARCH_WORKFLOW, CODE_DEVELOPMENT_WORKFLOW, DATA_ANALYSIS_WORKFLOW)
        }

    def list_workflows(self) -> List[Dict[str, Any]]:
        return [w.model_dump() for w in self._workflows.values()]

    async def run_workflow(self, workflow_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        workflow = self._workflows.get(workflow_id)
        if workflow is None:
            return {
                "error": f"unknown workflow '{workflow_id}'",
                "known_workflows": sorted(self._workflows),
            }

        from ..config import get_config
        from ..factory import build_agent
        from .workflow import WorkflowExecutor
        from ..agents.orchestrator import _resolve_llm

        agent = build_agent(get_config(), llm_override=_resolve_llm())
        result = await WorkflowExecutor(agent).execute(workflow, inputs=params)

        return {
            "workflow": result.workflow_name,
            "status": result.status.value,
            "total_duration_ms": round(result.total_duration_ms, 1),
            "steps": [
                {
                    "name": s.step_name,
                    "status": s.status.value,
                    "output": s.output,
                    "error": s.error,
                    "duration_ms": round(s.duration_ms, 1),
                }
                for s in result.steps
            ],
            "context": result.context,
        }


def get_workflow_registry() -> Optional[WorkflowRegistry]:
    """Lazy singleton — workflow defs are cheap; the agent loads per run."""
    global _singleton
    if _singleton is None:
        try:
            _singleton = WorkflowRegistry()
            logger.info("workflow_registry_initialized", context="worker_pool")
        except Exception as e:
            logger.error("workflow_registry_init_failed", error=str(e))
            return None
    return _singleton
