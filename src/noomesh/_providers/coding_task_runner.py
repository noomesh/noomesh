# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Coding task runner provider — Claude Code subprocess delegation.

Replaces the direct import:
    from noomesh.gateway.coding_tool import get_coding_manager

Consumers:
    - mcp/tools_legacy.py × 2 sites (noo_coding_task, noo_coding_status)

Why: the coding-task subprocess is a HARNESS-side feature (it runs
Claude Code as a subprocess of the harness process). HARNESS replacements
may use a different coding agent or skip the feature entirely.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol, runtime_checkable


@runtime_checkable
class CodingTaskRunner(Protocol):
    """Provider for the coding-task subprocess feature."""

    def manager(self) -> Optional[Any]:
        """Return the live ``CodingTaskManager`` instance, or None if the
        feature is disabled / not yet initialised."""
        ...


class GatewayCodingTaskRunner:
    """Default impl that delegates to ``gateway.coding_tool``."""

    def manager(self) -> Optional[Any]:
        try:
            from ..gateway.coding_tool import get_coding_manager
            return get_coding_manager()
        except Exception:
            return None


def default_coding_task_runner() -> CodingTaskRunner:
    return GatewayCodingTaskRunner()
