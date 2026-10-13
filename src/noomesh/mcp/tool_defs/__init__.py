# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""PAI tool definitions — Pydantic models registered with FastMCP.

Import all category modules to trigger @register decorators.
Add-on features use guarded imports so the open release works without them.
"""
# ── Core tools (always available) ──
from . import rag          # noqa: F401
from . import graph        # noqa: F401
from . import memory       # noqa: F401
from . import cluster      # noqa: F401
from . import inference    # noqa: F401
from . import scheduler    # noqa: F401
from . import channels     # noqa: F401
from . import heartbeat    # noqa: F401
from . import autonomy     # noqa: F401
from . import skills       # noqa: F401
from . import devices      # noqa: F401
from . import config       # noqa: F401
from . import discovery    # noqa: F401
from . import snapshots    # noqa: F401
from . import self_admin   # noqa: F401
from . import activities   # noqa: F401
from . import users         # noqa: F401
from . import ops           # noqa: F401

# ── Tool definitions an installed add-on delivers ──
# An add-on declares an ``mcp_tool_defs`` extension (see ``noomesh.addon_roles``):
# a module whose import registers ToolDef subclasses through ``register``.
# Resolving the declaration is the import. With no add-on declaring any, or
# the add-on not installed, those tools simply don't exist in the registry.
from ...addon_roles import MCP_TOOL_DEFS, extensions as _addon_extensions  # noqa: E402

_addon_extensions(MCP_TOOL_DEFS)
