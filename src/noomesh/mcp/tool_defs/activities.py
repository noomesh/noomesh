# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Agent activities — long-running pursuits the agent tracks across runs.

Phase A (current): manual CRUD via these tools. User or agent creates
activities; agent appends progress as related work completes.

See `gateway-rust/src/agent_activities.rs` + migration 008 for the
backend. See the security documentation for the future
autonomous-pursuit roadmap.
"""
from __future__ import annotations

from typing import Any, ClassVar, List, Optional

from pydantic import Field

from ..tool_models import HttpMethod, RiskLevel, ToolDef, register


@register
class PaiActivityCreate(ToolDef):
    """Create a long-running activity — a pursuit the agent tracks across runs.

    Use when you (or the user) want to track work that spans multiple
    days/weeks and decomposes into many tasks. Examples:
      - "Research the field of agentic AI in 3D worlds" (kind=research)
      - "Clean up duplicate pages in PageIndex" (kind=knowledge_curation)
      - "Investigate why cluster_health keeps over-firing" (kind=investigation)

    Activities differ from heartbeat tasks: tasks are single recurring
    actions; activities are *goals* that may schedule several tasks to
    pursue them.

    Valid kinds: research, knowledge_curation, investigation,
                 monitoring, user_pursuit, other."""

    name: ClassVar[str] = "noo_activity_create"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/activities"
    tags: ClassVar[List[str]] = ["activity", "meta-loop"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    name_field: str = Field(alias="name", description="Short title for the activity")
    kind: str = Field(
        default="other",
        description=(
            "Activity kind: research | knowledge_curation | investigation | "
            "monitoring | user_pursuit | other"
        ),
    )
    # Aliased like name_field above: a field literally named `description`
    # shadows the ClassVar tool metadata (Pydantic v2) and breaks every
    # catalog build with AttributeError.
    description_field: str = Field(
        default="",
        alias="description",
        description="Plain-English description of what the activity pursues",
    )
    success_when: Optional[str] = Field(
        default=None,
        description="Plain-English completion criterion (e.g. 'KB has 20+ pages on topic')",
    )
    created_by: Optional[str] = Field(
        default="agent",
        description="Who created this activity (auto-injected, agent default)",
    )

    class Config:
        populate_by_name = True

    def format_response(self, data: Any) -> str:
        if isinstance(data, dict) and data.get("ok"):
            return f"Activity created: id={data.get('activity_id', '?')}"
        return str(data)


@register
class PaiActivityList(ToolDef):
    """List agent activities. Optional filters: status, kind."""

    name: ClassVar[str] = "noo_activity_list"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/activities"
    tags: ClassVar[List[str]] = ["activity", "meta-loop"]

    status: Optional[str] = Field(
        default=None,
        description="Filter: active | paused | completed | abandoned",
    )
    kind: Optional[str] = Field(default=None, description="Filter by activity kind")
    limit: Optional[int] = Field(default=50, description="Max activities to return")


@register
class PaiActivityProgress(ToolDef):
    """Record progress on an activity. Appends a structured entry to
    the activity's progress.entries array and bumps last_activity_at.

    Entry shape (free-form, but consistent shapes are easier to query):
      { "at": "<iso>", "kind": "milestone"|"finding"|"note",
        "summary": "...", "details": {...} }"""

    name: ClassVar[str] = "noo_activity_progress"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/activities/{activity_id}/progress"
    tags: ClassVar[List[str]] = ["activity", "meta-loop"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    activity_id: str = Field(description="UUID of the activity to update")
    summary: str = Field(description="One-line summary of the progress event")
    entry_kind: Optional[str] = Field(
        default="note",
        description="Entry kind: milestone | finding | note | failure",
    )


@register
class PaiActivityComplete(ToolDef):
    """Mark an activity terminal (completed or abandoned)."""

    name: ClassVar[str] = "noo_activity_complete"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/activities/{activity_id}/complete"
    tags: ClassVar[List[str]] = ["activity", "meta-loop"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    activity_id: str = Field(description="UUID of the activity to close")
    final_status: Optional[str] = Field(
        default="completed",
        description="'completed' (success) or 'abandoned' (giving up)",
    )
    note: Optional[str] = Field(
        default=None, description="Final note appended to progress entries"
    )
