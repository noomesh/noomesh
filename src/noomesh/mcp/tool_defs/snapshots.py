# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Snapshot consolidation MCP tools.

These let the coordinator agent trigger snapshot builds, diff snapshots,
and ask deterministic questions over a snapshot DAG without any LLM cost
on the answer side.
"""
from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional

from pydantic import Field

from ..tool_models import HttpMethod, RiskLevel, ToolDef, register
from .ops import ASYNC_NOTE


@register
class PaiConsolidateNow(ToolDef):
    """Manually trigger a consolidation cycle — slice the live KG and snapshot it.

    Slice kinds:
    - topic: params={entity_type, canonical_name, hops?}
    - time_window: params={from, to}  (ISO-8601 datetime strings)
    - user_attention: params={user_id, days?}
    """

    name: ClassVar[str] = "noo_consolidate_now"
    description: ClassVar[str] = __doc__ + ASYNC_NOTE
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/snapshots/consolidate"
    # Temporal-graph extraction over a slice. The route is operation-backed: a few seconds'
    # wait, then an op handle; the door only has to outlast MAX_WAIT_SECS (25).
    timeout_secs: ClassVar[int] = 60
    tags: ClassVar[List[str]] = ["snapshots", "trellion", "memory"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    kind: str = Field(description="Slice kind: topic | time_window | user_attention")
    params: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Slice-specific params")
    label: Optional[str] = Field(default=None, description="Human-readable label")


@register
class PaiSnapshotDiff(ToolDef):
    """Compare two snapshots — what crystallized between consolidation cycles."""

    name: ClassVar[str] = "noo_snapshot_diff"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/snapshots/diff"
    tags: ClassVar[List[str]] = ["snapshots", "trellion", "memory"]

    snapshot_a: str = Field(description="First snapshot id (older)")
    snapshot_b: str = Field(description="Second snapshot id (newer)")


@register
class PaiCurriculumQuery(ToolDef):
    """Pure-traversal answer over a snapshot DAG — zero LLM cost.

    Use when you need a deterministic prerequisite/structure answer like
    'what should I learn before X?' from a topic-scoped snapshot.
    """

    name: ClassVar[str] = "noo_curriculum_query"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/snapshots/{snapshot_id}/curriculum"
    tags: ClassVar[List[str]] = ["snapshots", "trellion", "memory", "query"]

    snapshot_id: str = Field(description="The snapshot to query")
    q: str = Field(description="Natural-language question (terms get fuzzy-matched against concept names)")


@register
class PaiSnapshotsList(ToolDef):
    """List recent snapshots, optionally filtered by kind or status."""

    name: ClassVar[str] = "noo_snapshots_list"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/snapshots"
    tags: ClassVar[List[str]] = ["snapshots", "trellion", "memory"]

    kind: Optional[str] = Field(default=None, description="Filter by slice kind")
    status: Optional[str] = Field(default=None, description="Filter by status: building | complete | failed")
    limit: int = Field(default=20, description="Max rows to return")
