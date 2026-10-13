# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for plugin manager."""
from pathlib import Path

from noomesh.plugins.plugin_manager import PluginManager, PluginMetadata


class TestPluginManagerInit:
    """Test PluginManager initialization."""

    def test_default_dir(self):
        pm = PluginManager()
        assert pm.plugin_dir == Path("plugins")

    def test_custom_dir(self, tmp_path):
        pm = PluginManager(plugin_dir=tmp_path / "my_plugins")
        assert pm.plugin_dir == tmp_path / "my_plugins"

    def test_hooks_initialized(self):
        pm = PluginManager()
        assert "on_agent_start" in pm.hooks
        assert "on_agent_stop" in pm.hooks
        assert "on_tool_execute" in pm.hooks
        assert "on_llm_call" in pm.hooks


class TestDiscoverPlugins:
    """Test plugin discovery."""

    def test_discover_in_empty_dir(self, tmp_path):
        pm = PluginManager(plugin_dir=tmp_path)
        assert pm.discover_plugins() == []

    def test_discover_nonexistent_dir(self, tmp_path):
        pm = PluginManager(plugin_dir=tmp_path / "nonexistent")
        assert pm.discover_plugins() == []

    def test_discover_plugins(self, tmp_path):
        # Create plugin directory structure
        (tmp_path / "my_plugin").mkdir()
        (tmp_path / "my_plugin" / "plugin.py").write_text("# plugin")
        (tmp_path / "other_plugin").mkdir()
        (tmp_path / "other_plugin" / "plugin.py").write_text("# plugin")
        # Dir without plugin.py should be ignored
        (tmp_path / "not_a_plugin").mkdir()

        pm = PluginManager(plugin_dir=tmp_path)
        discovered = pm.discover_plugins()
        assert sorted(discovered) == ["my_plugin", "other_plugin"]


class TestLoadPlugin:
    """Test plugin loading."""

    def test_load_missing_plugin(self, tmp_path):
        pm = PluginManager(plugin_dir=tmp_path)
        result = pm.load_plugin("nonexistent")
        assert result is None

    def test_load_already_loaded(self, tmp_path):
        pm = PluginManager(plugin_dir=tmp_path)
        # Simulate pre-loaded plugin
        from unittest.mock import MagicMock
        mock_plugin = MagicMock()
        pm.plugins["test"] = mock_plugin
        result = pm.load_plugin("test")
        assert result is mock_plugin


class TestUnloadPlugin:
    """Test plugin unloading."""

    def test_unload_loaded_plugin(self):
        from unittest.mock import MagicMock
        pm = PluginManager()
        mock_plugin = MagicMock()
        pm.plugins["test"] = mock_plugin
        result = pm.unload_plugin("test")
        assert result is True
        assert "test" not in pm.plugins
        mock_plugin.on_unload.assert_called_once()

    def test_unload_nonexistent(self):
        pm = PluginManager()
        assert pm.unload_plugin("nonexistent") is False


class TestListAndGetPlugins:
    """Test plugin listing and retrieval."""

    def test_list_plugins(self):
        from unittest.mock import MagicMock
        pm = PluginManager()
        pm.plugins["a"] = MagicMock()
        pm.plugins["b"] = MagicMock()
        assert sorted(pm.list_plugins()) == ["a", "b"]

    def test_get_plugin(self):
        from unittest.mock import MagicMock
        pm = PluginManager()
        mock = MagicMock()
        pm.plugins["test"] = mock
        assert pm.get_plugin("test") is mock

    def test_get_plugin_missing(self):
        pm = PluginManager()
        assert pm.get_plugin("nonexistent") is None


class TestTriggerHook:
    """Test hook triggering."""

    def test_trigger_hook(self):
        pm = PluginManager()
        called = []
        pm.hooks["on_agent_start"].append(lambda: called.append(True))
        pm.trigger_hook("on_agent_start")
        assert called == [True]

    def test_trigger_hook_with_args(self):
        pm = PluginManager()
        results = []
        pm.hooks["on_tool_execute"].append(lambda name, args: results.append((name, args)))
        pm.trigger_hook("on_tool_execute", "search", {"q": "test"})
        assert results == [("search", {"q": "test"})]

    def test_trigger_hook_error_isolation(self):
        pm = PluginManager()
        pm.hooks["on_agent_start"].append(lambda: 1/0)
        # Should not raise
        pm.trigger_hook("on_agent_start")

    def test_trigger_unknown_hook(self):
        pm = PluginManager()
        # Should not raise
        pm.trigger_hook("unknown_hook")


class TestPluginMetadata:
    """Test PluginMetadata dataclass."""

    def test_creation(self):
        meta = PluginMetadata(
            name="test",
            version="1.0.0",
            description="A test plugin",
            author="tester",
        )
        assert meta.name == "test"
        assert meta.version == "1.0.0"
        assert meta.dependencies == []
