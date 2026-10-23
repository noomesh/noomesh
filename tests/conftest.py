# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Pytest configuration and fixtures."""
from pathlib import Path

import pytest
from unittest.mock import AsyncMock, MagicMock

from noomesh.config import AppConfig
from noomesh.gateway.tools_executor import ToolResult
from noomesh.channels.base import ChannelMessage

# "A skip in CI must be explained" (see docs/development/developer-guide.md).
# The guard lives in its own module (tests/_ci_skip_guard.py) so
# tests/test_ci_skip_guard.py can register the same hooks into an isolated
# nested pytest session via `pytester`, without pulling in the noomesh.*
# imports above. TESTS_DIR must be set BEFORE pytest calls pytest_configure,
# since that is what tells the guard where ci_skip_allowlist.txt lives
# (relative to this conftest.py, never the process cwd).
from . import _ci_skip_guard as _ci_skip_guard  # noqa: E402

_ci_skip_guard.TESTS_DIR = Path(__file__).resolve().parent

pytest_configure = _ci_skip_guard.pytest_configure
pytest_sessionfinish = _ci_skip_guard.pytest_sessionfinish


@pytest.fixture
def test_config():
    """Test configuration."""
    return AppConfig(
        ollama={"base_url": "http://localhost:11434", "model": "gpt-oss:20b"},
        agent={"system_prompt": "Test assistant", "max_tool_loops": 2},
        tools={"enabled": ["python_exec"], "selection_mode": "all"},
        memory={"enabled": False},
    )


@pytest.fixture
def temp_config_file(tmp_path):
    """Create temporary config file."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text("""
ollama:
  model: gpt-oss:20b
  base_url: http://localhost:11434

agent:
  system_prompt: Test
  max_tool_loops: 2

tools:
  enabled: []
  selection_mode: all
""")
    return config_file


# The node/cluster fixtures (_make_node, make_node, node_registry) went away
# with cluster/node.py (fu 58 round 2; history in git log before 2026-08-08) — the registry was an empty shell nobody populated.


@pytest.fixture
def tool_result_ok():
    return ToolResult(success=True, output="ok result")


@pytest.fixture
def tool_result_fail():
    return ToolResult(success=False, output="", error="something broke")


# ── Tool-related fixtures ────────────────────────────────────────


@pytest.fixture
def mock_tool_registry():
    """ToolRegistry with an async mock execute_tool method."""
    from noomesh.gateway.tools_executor import ToolRegistry

    registry = MagicMock(spec=ToolRegistry)
    registry.execute_tool = AsyncMock(
        return_value=ToolResult(success=True, output="mock ok")
    )
    return registry


# ── Channel fixtures ─────────────────────────────────────────────


@pytest.fixture
def sample_channel_message():
    """A normalized ChannelMessage for testing."""
    return ChannelMessage(
        channel="telegram",
        sender_id="12345",
        sender_name="Test User",
        text="Hello, what is the weather?",
        thread_id=None,
        raw={"message": {"text": "Hello, what is the weather?"}},
    )


@pytest.fixture
def sample_telegram_update():
    """Raw Telegram update dict for webhook parsing tests."""
    return {
        "update_id": 100,
        "message": {
            "message_id": 1,
            "from": {
                "id": 42,
                "is_bot": False,
                "first_name": "Alice",
                "last_name": "Smith",
                "username": "asmith",
            },
            "chat": {
                "id": 42,
                "type": "private",
                "first_name": "Alice",
            },
            "date": 1700000000,
            "text": "Hello bot!",
        },
    }
