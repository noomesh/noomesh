# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Plugin system for extending Mesh"""
from __future__ import annotations

import importlib
import importlib.util
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

from ..tools.registry import ToolRegistry

log = structlog.get_logger(__name__)


@dataclass
class PluginMetadata:
    """Plugin metadata"""
    name: str
    version: str
    description: str
    author: str
    dependencies: List[str] = field(default_factory=list)


class Plugin(ABC):
    """
    Base plugin class

    Plugins can:
    - Register custom tools
    - Hook into lifecycle events
    - Extend agent capabilities
    """

    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Plugin metadata"""
        pass

    def register_tools(self, registry: ToolRegistry) -> None:
        """
        Register custom tools with the agent

        Args:
            registry: Tool registry to register tools with
        """
        pass

    def register_hooks(self, hooks: Dict[str, Any]) -> None:
        """
        Register lifecycle hooks

        Available hooks:
        - on_agent_start: Called when agent starts
        - on_agent_stop: Called when agent stops
        - on_tool_execute: Called before tool execution
        - on_llm_call: Called before LLM call

        Args:
            hooks: Dictionary to register hooks in
        """
        pass

    def on_load(self) -> None:
        """Called when plugin is loaded"""
        pass

    def on_unload(self) -> None:
        """Called when plugin is unloaded"""
        pass


class PluginManager:
    """Manages plugin lifecycle and registration"""

    def __init__(self, plugin_dir: Optional[Path] = None):
        """
        Initialize plugin manager

        Args:
            plugin_dir: Directory containing plugins
        """
        self.plugin_dir = plugin_dir or Path("plugins")
        self.plugins: Dict[str, Plugin] = {}
        self.hooks: Dict[str, List[Any]] = {
            "on_agent_start": [],
            "on_agent_stop": [],
            "on_tool_execute": [],
            "on_llm_call": [],
        }

    def discover_plugins(self) -> List[str]:
        """
        Auto-discover plugins in plugin directory

        Returns:
            List of discovered plugin names
        """
        if not self.plugin_dir.exists():
            return []

        discovered = []

        for plugin_path in self.plugin_dir.glob("*/plugin.py"):
            plugin_name = plugin_path.parent.name
            discovered.append(plugin_name)

        return discovered

    def load_plugin(
        self,
        name: str,
        registry: Optional[ToolRegistry] = None
    ) -> Optional[Plugin]:
        """
        Load and register a plugin

        Args:
            name: Plugin name
            registry: Tool registry for tool registration

        Returns:
            Loaded plugin instance or None if failed
        """
        if name in self.plugins:
            return self.plugins[name]

        # Import plugin module
        plugin_path = self.plugin_dir / name / "plugin.py"
        if not plugin_path.exists():
            return None

        try:
            spec = importlib.util.spec_from_file_location(
                f"plugins.{name}.plugin",
                plugin_path
            )
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Instantiate plugin
                if hasattr(module, "Plugin"):
                    plugin = module.Plugin()

                    # Register tools (and mirror them into the declarative
                    # tool registry so plugin tools are visible alongside
                    # the @tool declarations — export=False keeps them out
                    # of the generated config/tools.json)
                    if registry:
                        plugin.register_tools(registry)
                        self._mirror_tools_to_decl_registry(registry, name)

                    # Register hooks
                    plugin.register_hooks(self.hooks)

                    # Call on_load
                    plugin.on_load()

                    self.plugins[name] = plugin
                    return plugin

        except Exception as e:
            log.warning("plugin.load_failed", plugin=name, error=str(e))
            return None

    @staticmethod
    def _mirror_tools_to_decl_registry(registry: ToolRegistry, plugin_name: str) -> None:
        """Feed plugin-registered ToolSpecs into noomesh.tools.decl.

        Idempotent per tool name; failures never break plugin loading.
        """
        try:
            from ..tools.decl import register_plugin_tool
            for spec in registry.list():
                register_plugin_tool(spec, source=f"plugin:{plugin_name}")
        except Exception as e:
            log.warning("plugin.tool_mirror_failed", plugin=plugin_name, error=str(e))

    def unload_plugin(self, name: str) -> bool:
        """
        Unload a plugin

        Args:
            name: Plugin name

        Returns:
            Success status
        """
        if name not in self.plugins:
            return False

        plugin = self.plugins[name]
        plugin.on_unload()

        # Remove from hooks
        for hook_list in self.hooks.values():
            hook_list[:] = [h for h in hook_list if not hasattr(h, "__self__") or h.__self__ != plugin]

        del self.plugins[name]
        return True

    def get_plugin(self, name: str) -> Optional[Plugin]:
        """
        Get loaded plugin by name

        Args:
            name: Plugin name

        Returns:
            Plugin instance or None
        """
        return self.plugins.get(name)

    def list_plugins(self) -> List[str]:
        """
        List all loaded plugins

        Returns:
            List of plugin names
        """
        return list(self.plugins.keys())

    def trigger_hook(self, hook_name: str, *args, **kwargs) -> None:
        """
        Trigger lifecycle hook

        Args:
            hook_name: Hook name
            *args: Positional arguments
            **kwargs: Keyword arguments
        """
        if hook_name in self.hooks:
            for hook in self.hooks[hook_name]:
                try:
                    hook(*args, **kwargs)
                except Exception as e:
                    # Don't let plugin errors break the system
                    log.warning("plugin.hook_error", hook=hook_name, error=str(e))
