# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Central dependency container — replaces scattered globals and setter functions.

Built once during lifespan, attached to ``app.state.gateway``.
Route handlers access it via ``Depends(get_state)``.

This mirrors the Rust gateway's AppState pattern for symmetry across the stack.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fastapi import Request


@dataclass
class GatewayState:
    # ── Core ──
    config: dict = field(default_factory=dict)

    # ── Database / Memory ──
    conversation_store: Any = None
    memory_system: Any = None

    # ── Cluster ──
    backend_manager: Any = None
    node_registry: Any = None

    # ── Inference ──
    coordinator: Any = None
    cache_manager: Any = None
    tool_registry: Any = None

    # ── Knowledge ──
    pageindex_rag: Any = None
    recall_memory: Any = None

    # ── Scheduling ──
    heartbeat_scheduler: Any = None
    scheduler: Any = None

    # ── Communication ──
    channel_manager: Any = None

    # ── Embedding ──
    embedding_worker: Any = None

    # ── Cloud ──
    cloud_manager: Any = None

    # (No MCP slot: the doors are Rust — mcp_local.rs / mcp_external.rs. The
    # `mcp_hub` field held the retired Python MCPHub and had no readers left.)

    # ── Settings ──
    settings_store: Any = None

    # ── Autonomy ──
    autonomy_engine: Any = None

    # ── Agents ──
    agent_orchestrator: Any = None
    agent_factory: Any = None
    persona_registry: Any = None
    coding_manager: Any = None
    proactive_agent: Any = None
    browser_tool: Any = None

    # ── Observability ──
    loki_url: str = ""
    health_monitor: Any = None


def get_state(request: Request) -> GatewayState:
    """FastAPI dependency — extracts GatewayState from app.state."""
    return request.app.state.gateway
