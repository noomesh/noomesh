# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Plugin system for extending Mesh."""
from .plugin_manager import Plugin, PluginManager, PluginMetadata

__all__ = ["Plugin", "PluginManager", "PluginMetadata"]
