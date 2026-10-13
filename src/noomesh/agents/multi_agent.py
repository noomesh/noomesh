# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Multi-agent collaboration system"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog

from ..agent import Agent
from ..config import AppConfig
from ..llm.base import LLMClient

_logger = structlog.get_logger(__name__)

# Guard parallel collaboration import
try:
    from .parallel_collab import ParallelCollaboration
    PARALLEL_AVAILABLE = True
except Exception:
    PARALLEL_AVAILABLE = False


class AgentRole(Enum):
    """Predefined agent roles"""
    RESEARCHER = "researcher"
    CODER = "coder"
    ANALYST = "analyst"
    PLANNER = "planner"
    REVIEWER = "reviewer"


@dataclass
class AgentSpec:
    """Specification for a specialized agent"""
    role: AgentRole
    system_prompt: str
    preferred_tools: List[str]
    max_tool_loops: int = 3


# Predefined agent specifications
AGENT_SPECS = {
    AgentRole.RESEARCHER: AgentSpec(
        role=AgentRole.RESEARCHER,
        system_prompt="""You are a research specialist. Your role is to:
        - Gather information from multiple sources
        - Verify facts and cross-reference data
        - Summarize findings clearly and concisely
        - Identify knowledge gaps and uncertainties
        Be thorough but efficient in your research.""",
        preferred_tools=["web_search", "local_files"],
        max_tool_loops=5
    ),

    AgentRole.CODER: AgentSpec(
        role=AgentRole.CODER,
        system_prompt="""You are a coding expert. Your role is to:
        - Write clean, efficient, well-documented code
        - Follow best practices and design patterns
        - Consider edge cases and error handling
        - Optimize for readability and maintainability
        Focus on quality over speed.""",
        preferred_tools=["python_exec", "local_files"],
        max_tool_loops=4
    ),

    AgentRole.ANALYST: AgentSpec(
        role=AgentRole.ANALYST,
        system_prompt="""You are a data analyst. Your role is to:
        - Analyze data patterns and trends
        - Generate insights and recommendations
        - Create clear visualizations when helpful
        - Identify correlations and anomalies
        Be precise and data-driven in your analysis.""",
        preferred_tools=["python_exec"],
        max_tool_loops=4
    ),

    AgentRole.PLANNER: AgentSpec(
        role=AgentRole.PLANNER,
        system_prompt="""You are a planning specialist. Your role is to:
        - Break down complex tasks into steps
        - Identify dependencies and ordering
        - Allocate work appropriately
        - Anticipate potential issues
        Create actionable, structured plans.""",
        preferred_tools=[],
        max_tool_loops=2
    ),

    AgentRole.REVIEWER: AgentSpec(
        role=AgentRole.REVIEWER,
        system_prompt="""You are a code reviewer. Your role is to:
        - Identify bugs, security issues, and code smells
        - Suggest improvements for clarity and performance
        - Verify adherence to requirements
        - Provide constructive feedback
        Be thorough but respectful in reviews.""",
        preferred_tools=["local_files"],
        max_tool_loops=2
    ),
}


class AgentOrchestrator:
    """
    Orchestrates multiple specialized agents for complex tasks

    Supports:
    - Task routing to appropriate specialists
    - Multi-agent collaboration workflows
    - Result aggregation
    """

    def __init__(
        self,
        base_config: AppConfig,
        llm_client: Optional[LLMClient] = None,
        llm_factory: Optional[Any] = None,
    ):
        """
        Initialize orchestrator

        Args:
            base_config: Base configuration for agents
            llm_client: Optional pre-built LLM client (supports vLLM, llama.cpp, Ollama).
                         If None, falls back to OllamaClient from config.
            llm_factory: Optional callable ``() -> LLMClient`` that resolves the
                         backend at request time.  Takes priority over *llm_client*
                         so the orchestrator always talks to whatever backend is
                         currently running.
        """
        self.base_config = base_config
        self._llm_client = llm_client
        self._llm_factory = llm_factory
        self.agents: Dict[AgentRole, Agent] = {}

    def _resolve_llm(self) -> Optional[LLMClient]:
        """Get the LLM client, resolving lazily via factory if available."""
        if self._llm_factory:
            try:
                client = self._llm_factory()
                _logger.debug("multi_agent_llm_resolved", client=type(client).__name__)
                return client
            except Exception as e:
                _logger.warning("multi_agent_llm_factory_failed", error=str(e))
        return self._llm_client

    def _create_agent(self, spec: AgentSpec) -> Agent:
        """
        Create specialized agent from specification

        Args:
            spec: Agent specification

        Returns:
            Configured Agent instance
        """
        from ..factory import build_agent

        # Clone config and customize
        config_dict = self.base_config.model_dump()
        config_dict["agent"]["system_prompt"] = spec.system_prompt
        config_dict["agent"]["max_tool_loops"] = spec.max_tool_loops

        # Pin preferred tools
        if spec.preferred_tools:
            config_dict["tools"]["always_include"] = spec.preferred_tools

        from ..config import AppConfig
        specialized_config = AppConfig.model_validate(config_dict)

        return build_agent(specialized_config, llm_override=self._resolve_llm())

    def get_agent(self, role: AgentRole, fresh: bool = False) -> Agent:
        """
        Get or create agent for role

        Args:
            role: Agent role
            fresh: If True, always create a new agent (e.g. when backend changed)

        Returns:
            Agent instance
        """
        if fresh or role not in self.agents:
            spec = AGENT_SPECS[role]
            self.agents[role] = self._create_agent(spec)

        return self.agents[role]

    async def route_task(self, task: str, preferred_role: Optional[AgentRole] = None) -> str:
        """
        Route task to appropriate agent

        Args:
            task: Task description
            preferred_role: Specific role to use (or None for auto-routing)

        Returns:
            Agent's response
        """
        if preferred_role:
            role = preferred_role
        else:
            role = self._classify_task(task)

        # Use fresh=True when we have a factory, so we always talk to whatever
        # backend is currently running (it may have changed since last call).
        agent = self.get_agent(role, fresh=bool(self._llm_factory))
        session = agent.new_session()

        return await asyncio.to_thread(agent.step, session, task)

    def _classify_task(self, task: str) -> AgentRole:
        """
        Classify task to determine best agent role

        Args:
            task: Task description

        Returns:
            Best matching agent role
        """
        task_lower = task.lower()

        # Simple keyword-based routing
        if any(kw in task_lower for kw in ["research", "find", "search", "learn about"]):
            return AgentRole.RESEARCHER
        elif any(kw in task_lower for kw in ["code", "implement", "write", "function", "class"]):
            return AgentRole.CODER
        elif any(kw in task_lower for kw in ["analyze", "data", "statistics", "trends"]):
            return AgentRole.ANALYST
        elif any(kw in task_lower for kw in ["plan", "organize", "break down", "steps"]):
            return AgentRole.PLANNER
        elif any(kw in task_lower for kw in ["review", "check", "verify", "audit"]):
            return AgentRole.REVIEWER
        else:
            # Default to researcher for general queries
            return AgentRole.RESEARCHER

    async def collaborate(
        self,
        task: str,
        workflow: List[AgentRole],
        force_sequential: bool = False,
    ) -> Dict[AgentRole, str]:
        """Execute task through multiple agents.

        By default, agents run **in parallel** with real-time token
        sharing via NATS (even on a single backend — vLLM batches
        concurrent requests).  Falls back to sequential handoff if
        parallel is unavailable or ``force_sequential=True``.

        Args:
            task: Initial task description.
            workflow: Ordered list of agent roles.
            force_sequential: Force sequential handoff mode.

        Returns:
            Dictionary mapping roles to their outputs.
        """
        if not force_sequential and PARALLEL_AVAILABLE:
            try:
                backends = ParallelCollaboration.discover_backends()
                if backends:
                    collab = ParallelCollaboration(self.base_config)
                    agent_results = await collab.run(task, workflow)
                    # Convert AgentResult objects to plain strings keyed by AgentRole
                    return {
                        AgentRole(role_name): ar.output
                        for role_name, ar in agent_results.items()
                    }
            except Exception as exc:
                _logger.warning("parallel_fallback", error=str(exc))

        return await self._sequential_collaborate(task, workflow)

    async def _sequential_collaborate(
        self,
        task: str,
        workflow: List[AgentRole],
    ) -> Dict[AgentRole, str]:
        """Execute task through multiple agents in sequence (original logic)."""
        results: Dict[AgentRole, str] = {}
        context = task

        # Budget for context passed between agents.  We give each
        # previous agent's output a fair share of the budget so the
        # prompt stays within reasonable token limits.
        _MAX_CONTEXT_CHARS = 12000

        # When using a factory, create fresh agents to pick up runtime
        # backend changes (e.g. BackendManager started vLLM since last call).
        _fresh = bool(self._llm_factory)

        for role in workflow:
            agent = self.get_agent(role, fresh=_fresh)
            session = agent.new_session()

            # Include previous results in context
            if results:
                per_agent = max(1000, _MAX_CONTEXT_CHARS // len(results))
                parts = []
                for r, output in results.items():
                    truncated = output[:per_agent]
                    if len(output) > per_agent:
                        truncated += "\n... (truncated)"
                    parts.append(f"[{r.value.upper()}]:\n{truncated}")
                context_summary = "\n\n".join(parts)
                prompt = f"Previous work:\n{context_summary}\n\nYour task: {context}"
            else:
                prompt = context

            result = await asyncio.to_thread(agent.step, session, prompt)
            results[role] = result
            context = result  # Next agent continues from this result

        return results

    async def research_code_analyze_workflow(self, task: str) -> Dict[str, str]:
        """
        Standard workflow: Research → Code → Analyze

        Args:
            task: Task description

        Returns:
            Dictionary with research, code, and analysis results
        """
        workflow = [AgentRole.RESEARCHER, AgentRole.CODER, AgentRole.ANALYST]
        results = await self.collaborate(task, workflow)

        return {
            "research": results[AgentRole.RESEARCHER],
            "implementation": results[AgentRole.CODER],
            "analysis": results[AgentRole.ANALYST],
        }

    async def plan_code_review_workflow(self, task: str) -> Dict[str, str]:
        """
        Standard workflow: Plan → Code → Review

        Args:
            task: Task description

        Returns:
            Dictionary with plan, code, and review results
        """
        workflow = [AgentRole.PLANNER, AgentRole.CODER, AgentRole.REVIEWER]
        results = await self.collaborate(task, workflow)

        return {
            "plan": results[AgentRole.PLANNER],
            "implementation": results[AgentRole.CODER],
            "review": results[AgentRole.REVIEWER],
        }
