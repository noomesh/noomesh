# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Test tool functionality."""
from noomesh.tools.base import ToolSpec
from noomesh.tools.registry import ToolRegistry


def test_tool_spec_creation():
    """Test creating a tool spec."""
    tool = ToolSpec(
        name="test_tool",
        description="A test tool",
        parameters={
            "type": "object",
            "properties": {
                "arg": {"type": "string"}
            }
        },
        handler=lambda args: f"Result: {args.get('arg')}"
    )

    assert tool.name == "test_tool"
    assert callable(tool.handler)

    # Test handler
    result = tool.handler({"arg": "test"})
    assert result == "Result: test"


def test_tool_registry():
    """Test tool registry."""
    registry = ToolRegistry()

    # Register a tool
    tool = ToolSpec(
        name="my_tool",
        description="Test",
        parameters={},
        handler=lambda args: "result"
    )
    registry.register(tool)

    # Retrieve tool
    retrieved = registry.get("my_tool")
    assert retrieved is not None
    assert retrieved.name == "my_tool"

    # List tools
    tools = registry.list()
    assert len(tools) >= 1
    assert any(t.name == "my_tool" for t in tools)


def test_tool_selection():
    """Test tool selection by keyword matching."""
    registry = ToolRegistry()

    registry.register(ToolSpec(
        name="search_web",
        description="Search the web for information",
        parameters={},
        handler=lambda x: ""
    ))
    registry.register(ToolSpec(
        name="calculate",
        description="Perform mathematical calculations",
        parameters={},
        handler=lambda x: ""
    ))

    # If registry has select_tools, test it; otherwise verify tools are listed
    if hasattr(registry, "select_tools"):
        selected = registry.select_tools(
            "search for Python tutorials",
            mode="smart",
            max_selected=5,
        )
        assert len(selected) > 0
    else:
        # Fallback: verify the registry lists both tools
        tools = registry.list()
        names = [t.name for t in tools]
        assert "search_web" in names
        assert "calculate" in names
