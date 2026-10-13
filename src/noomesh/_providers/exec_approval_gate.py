# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Exec approval gate provider — risk-based tool execution gating.

Replaces direct imports of:
    from noomesh.gateway.exec_approval import get_approval_manager, ToolCall

Consumers:
    - tools/local_files.py       — 2 sites (lines 312, 393)

Why: gating policy is HARNESS-side (whether a tool needs approval depends
on the harness's risk model + UI). Letting consumers inject the gate
means a third-party harness can plug in its own approval flow without
inheriting PAI's defaults.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Protocol, runtime_checkable


@dataclass(frozen=True)
class ApprovalRequest:
    """A request to execute a tool with given args. Field names mirror
    ``gateway/exec_approval.py::ToolCall`` so the default impl can pass
    them through without translation."""
    name: str                         # tool name (e.g. "local_files")
    arguments: Dict[str, Any] = field(default_factory=dict)
    action: str = ""                  # e.g. "read", "write", "delete"
    raw_text: str = ""                # human-readable description for the UI


@dataclass(frozen=True)
class ApprovalDecision:
    """Result of an approval check. ``approved=True`` means proceed.
    Field names mirror ``gateway/exec_approval.py::ApprovalResult``."""
    approved: bool
    reason: str = ""
    request_id: Optional[str] = None  # for async approval flows


@runtime_checkable
class ExecApprovalGate(Protocol):
    """Provider for risk-based tool execution gating."""

    async def check(self, request: ApprovalRequest) -> ApprovalDecision:
        """Decide whether to allow ``request``. May block briefly for
        approval flows (channel prompt, UI banner, etc.)."""
        ...


class GatewayExecApprovalGate:
    """Default impl that delegates to ``gateway.exec_approval``.

    Lazy import + fail-open semantics: if the gateway module isn't
    available (tests, no-harness deployment), allow the call. The
    consumer is the safety net of last resort, not this provider.
    """

    async def check(self, request: ApprovalRequest) -> ApprovalDecision:
        try:
            from ..gateway.exec_approval import (
                get_approval_manager, ToolCall as EAToolCall,
            )
            mgr = get_approval_manager()
            if mgr is None:
                return ApprovalDecision(approved=True, reason="manager_not_initialised")
            tc = EAToolCall(
                name=request.name,
                arguments=request.arguments,
                action=request.action,
                raw_text=request.raw_text,
            )
            result = await mgr.check(tc)
            approved = bool(getattr(result, "approved", True))
            reason = str(getattr(result, "reason", ""))
            req_id = getattr(result, "id", None)
            return ApprovalDecision(approved=approved, reason=reason, request_id=req_id)
        except Exception as e:
            # Fail-open with reason — caller logs but proceeds.
            return ApprovalDecision(
                approved=True,
                reason=f"gate_unavailable: {type(e).__name__}",
            )


def default_exec_approval_gate() -> ExecApprovalGate:
    """Back-compat default: delegates to gateway.exec_approval."""
    return GatewayExecApprovalGate()
