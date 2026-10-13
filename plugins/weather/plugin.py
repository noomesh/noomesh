# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Example weather plugin"""
from noomesh.plugins.plugin_manager import Plugin, PluginMetadata
from noomesh.tools.base import ToolSpec
from noomesh.tools.registry import ToolRegistry


def get_weather(args: dict) -> str:
    """Mock weather tool"""
    location = args.get("location", "Unknown")
    # In real plugin, would call weather API
    return f"Weather in {location}: Sunny, 72°F"


class WeatherPlugin(Plugin):
    """Example weather plugin"""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="weather",
            version="1.0.0",
            description="Weather lookup plugin",
            author="PAI Team",
            dependencies=[]
        )

    def register_tools(self, registry: ToolRegistry) -> None:
        """Register weather tool"""
        weather_tool = ToolSpec(
            name="get_weather",
            description="Get current weather for a location",
            parameters={
                "type": "object",
                "properties": {
                    "location": {
                        "type": "string",
                        "description": "City name or ZIP code"
                    }
                },
                "required": ["location"]
            },
            handler=get_weather
        )
        registry.register(weather_tool)

    def on_load(self) -> None:
        print("Weather plugin loaded!")

    def on_unload(self) -> None:
        print("Weather plugin unloaded!")


# Required: Plugin class must be named "Plugin"
Plugin = WeatherPlugin
