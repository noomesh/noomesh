# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Built-in tool declarations — importing this package populates the
declarative registry in ``noomesh.tools.decl``.

Module split:
- ``core``   — the always-visible core tools (``core_tools`` in tools.json)
- ``groups`` — extended tool groups (``extended_tool_groups``): lazy tools
  surfaced via ``noo_tool_search`` keyword matching

Declaration order here is the export order of ``noo tools export``.
"""

from . import core, groups  # noqa: F401

__all__ = ["core", "groups"]
