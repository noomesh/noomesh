# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Configuration management tools — get and set runtime config sections."""
from __future__ import annotations

from typing import Any, ClassVar, Dict, List

from pydantic import Field

from ..tool_models import HttpMethod, RiskLevel, ToolDef, register


@register
class PaiConfigGet(ToolDef):
    """Get runtime configuration. Returns full config if section is omitted,
    or a specific section (cluster, services, cache, terminal, etc.)."""

    name: ClassVar[str] = "noo_config_get"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/config/{section}"
    tags: ClassVar[List[str]] = ["config"]

    section: str = Field(default="", description="Config section name (empty for full config)")


@register
class PaiConfigSet(ToolDef):
    """Update runtime configuration for a specific section. Changes are persisted
    to noomesh.yaml."""

    name: ClassVar[str] = "noo_config_set"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.PUT
    path: ClassVar[str] = "/api/config/{section}"
    tags: ClassVar[List[str]] = ["config"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    # PUT /api/config/{section} deep-merges the request body INTO the
    # section, so the body must be the key/value pairs themselves. The generic
    # shape wrapped them under this field's own name: a `kb.source_roles`
    # update landed as `kb.updates.source_roles` and the rule never took
    # effect, while the call reported success because the route merged what it
    # was given and the response echoed the section back.
    #
    # Declared as DATA rather than a `get_body` override because the Rust MCP
    # doors build the request from the generated manifest and never run this
    # class — an override fixes `mcp/server.py` and leaves both live doors
    # wrapping. `noo_user_propose` nests on purpose (its route reads `action`
    # and `payload` as named fields) and simply does not set this.
    body_field: ClassVar[str] = "updates"

    section: str = Field(description="Config section to update (cluster, services, cache, etc.)")
    updates: Dict[str, Any] = Field(description="Key-value pairs to update in the section")

