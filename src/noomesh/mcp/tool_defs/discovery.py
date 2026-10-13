# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tool discovery — search available tools by keyword."""
from __future__ import annotations

from typing import Any, ClassVar, List, Optional

from pydantic import Field

from ..tool_models import HttpMethod, ToolDef, register


@register
class PaiToolSearch(ToolDef):
    """Search available PAI tools by keyword. Returns matching tool names and descriptions.
    Use this to discover which tools are available for a task."""

    name: ClassVar[str] = "noo_tool_search"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/tools/search"
    tags: ClassVar[List[str]] = ["core", "discovery"]

    query: str = Field(description="Search keyword(s) to match against tool names and descriptions")
    max_results: Optional[int] = Field(default=5, description="Maximum number of results to return")

    def format_response(self, data: Any) -> str:
        if not isinstance(data, (dict, list)):
            return str(data)
        tools = data if isinstance(data, list) else data.get("tools", data.get("results", []))
        if not tools:
            return "No tools matched the query."
        lines = [f"Matching tools ({len(tools)}):\n"]
        for t in tools:
            name = t.get("name", "?")
            desc = t.get("description", "")
            # Truncate long descriptions
            if len(desc) > 120:
                desc = desc[:117] + "..."
            lines.append(f"  {name}")
            if desc:
                lines.append(f"    {desc}")
        return "\n".join(lines)
