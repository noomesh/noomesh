# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

# ToolSpec moved to noomesh.tool_spec so the cluster runtime can
# import it without depending on the harness package. This module
# re-exports it for back-compat — existing `from .base import ToolSpec`
# still works.
from ..tool_spec import ToolSpec  # noqa: F401

__all__ = ["ToolSpec"]
