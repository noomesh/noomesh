# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Multi-agent collaboration system."""

from .multi_agent import AgentOrchestrator, AgentRole, AgentSpec, AGENT_SPECS

__all__ = ["AgentOrchestrator", "AgentRole", "AgentSpec", "AGENT_SPECS"]

try:
    from .parallel_collab import ParallelCollaboration  # noqa: F401
    __all__.append("ParallelCollaboration")
except Exception:
    pass
