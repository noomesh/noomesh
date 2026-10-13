# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Autonomy engine tools — status, audit, locations, enable/disable."""
from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional

from pydantic import Field

from ..tool_models import HttpMethod, RiskLevel, ToolDef, register


@register
class PaiAutonomyStatus(ToolDef):
    """Get autonomy engine status: enabled state, active locations, last patrol time."""

    name: ClassVar[str] = "noo_autonomy_status"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/autonomy/status"
    tags: ClassVar[List[str]] = ["autonomy", "status"]

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict):
            return str(data)
        enabled = data.get("enabled", False)
        last_patrol = data.get("last_patrol", "never")
        lines = [
            f"Autonomy engine: {'ENABLED' if enabled else 'DISABLED'}",
            f"Last patrol: {last_patrol}",
        ]
        locations = data.get("locations", [])
        if locations:
            lines.append(f"\nLocations ({len(locations)}):")
            for loc in locations:
                name = loc.get("name", "?")
                loc_enabled = loc.get("enabled", False)
                last_check = loc.get("last_check", "never")
                status_icon = "ON" if loc_enabled else "OFF"
                lines.append(f"  [{status_icon}] {name} (last check: {last_check})")
        return "\n".join(lines)


@register
class PaiAutonomyAudit(ToolDef):
    """View the autonomy audit log — recent actions taken by the engine."""

    name: ClassVar[str] = "noo_autonomy_audit"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/autonomy/audit"
    tags: ClassVar[List[str]] = ["autonomy", "audit"]

    limit: Optional[int] = Field(default=None, description="Maximum number of audit entries to return")


@register
class PaiAutonomyAddLocation(ToolDef):
    """Add a new monitoring location to the autonomy engine."""

    name: ClassVar[str] = "noo_autonomy_add_location"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/autonomy/locations"
    tags: ClassVar[List[str]] = ["autonomy"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    name_field: str = Field(alias="name", description="Unique location name")
    type: str = Field(description="Location type: endpoint, rag_store, cluster, filesystem, scheduler, custom")
    check_interval: Optional[int] = Field(default=None, description="Check interval in seconds")
    config: Optional[Dict[str, Any]] = Field(default=None, description="Location-specific configuration")
    enabled: bool = Field(default=True, description="Whether the location starts enabled")

    class Config:
        populate_by_name = True


@register
class PaiAutonomyEnable(ToolDef):
    """Enable the autonomy engine (starts periodic monitoring patrols)."""

    name: ClassVar[str] = "noo_autonomy_enable"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/autonomy/enable"
    tags: ClassVar[List[str]] = ["autonomy"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM


@register
class PaiAutonomyDisable(ToolDef):
    """Disable the autonomy engine (stops all monitoring patrols)."""

    name: ClassVar[str] = "noo_autonomy_disable"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/autonomy/disable"
    tags: ClassVar[List[str]] = ["autonomy"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
