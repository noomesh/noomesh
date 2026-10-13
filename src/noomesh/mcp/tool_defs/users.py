# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""User-management tools — propose account changes for human approval.

The agent has NO direct user-mutation tools by design: the users admin
API rejects internal callers. These tools file proposals that a
logged-in operator approves in the dashboard Admin view or via
``noo security user decide``.
"""
from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional

from pydantic import Field

from ..tool_models import HttpMethod, RiskLevel, ToolDef, register


@register
class PaiUserPropose(ToolDef):
    """Request a user-account change (create user, change scopes,
    disable/enable, grant KB roles) for HUMAN APPROVAL. Nothing happens
    until an operator approves in the dashboard. Never include a
    password — one is generated at approval time. Use when someone asks
    to add a user, give someone access, or change what a user can see."""

    name: ClassVar[str] = "noo_user_propose"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/users/propose"
    tags: ClassVar[List[str]] = ["users", "admin", "approval", "self-modify"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.HIGH

    action: str = Field(description="One of: create, scopes, disable, grant_roles")
    payload: Dict[str, Any] = Field(
        description="Action payload. create: {username, scopes?}; "
                    "scopes: {username, scopes}; disable: {username, disabled}; "
                    "grant_roles: {username, roles} (roles like team:research)")
    note: Optional[str] = Field(
        default=None, description="Why this change is needed — shown to the approver")

    def format_response(self, data: Any) -> str:
        if isinstance(data, dict) and data.get("proposal_id"):
            notified = ", ".join(data.get("notified") or []) or "no channels configured"
            return (f"Proposal #{data['proposal_id']} filed and pending operator "
                    f"approval (notified: {notified}). It will NOT take effect "
                    f"until approved in the dashboard Admin view.")
        return str(data)


@register
class PaiUserProposals(ToolDef):
    """List user-management proposals and their status (pending, approved,
    denied, failed). Use to check whether a requested account change has
    been approved yet."""

    name: ClassVar[str] = "noo_user_proposals"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/users/proposals"
    tags: ClassVar[List[str]] = ["users", "admin", "approval"]

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict) or "proposals" not in data:
            return str(data)
        props = data["proposals"]
        if not props:
            return "No user-management proposals."
        lines = [f"{data.get('pending', 0)} pending / {len(props)} recent:"]
        for p in props[:15]:
            payload = p.get("payload") or {}
            lines.append(
                f"#{p['id']} [{p['status']}] {p['action']} "
                f"{payload.get('username', '?')} (by {p.get('requested_by')})")
        return "\n".join(lines)
