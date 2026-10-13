# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for event bus system."""
from unittest.mock import AsyncMock

from noomesh.events import Event, EventBus, EventType


class TestEvent:
    """Test Event data model."""

    def test_to_dict_with_enum_type(self):
        e = Event(type=EventType.AGENT_STARTED, data={"key": "val"})
        d = e.to_dict()
        assert d["type"] == "agent.started"
        assert d["data"] == {"key": "val"}
        assert "timestamp" in d

    def test_to_dict_with_string_type(self):
        e = Event(type="custom.event", data={"x": 1})
        d = e.to_dict()
        assert d["type"] == "custom.event"

    def test_session_and_correlation_ids(self):
        e = Event(
            type=EventType.LLM_CALL_START,
            session_id="sess-1",
            correlation_id="corr-1",
        )
        d = e.to_dict()
        assert d["session_id"] == "sess-1"
        assert d["correlation_id"] == "corr-1"


class TestEventBusSubscription:
    """Test subscribe/unsubscribe."""

    def test_subscribe_exact_match(self):
        bus = EventBus()
        handler = AsyncMock()
        bus.subscribe(EventType.AGENT_STARTED, handler)
        assert len(bus.subscribers["agent.started"]) == 1

    def test_subscribe_string_key(self):
        bus = EventBus()
        handler = AsyncMock()
        bus.subscribe("custom.event", handler)
        assert "custom.event" in bus.subscribers

    def test_unsubscribe(self):
        bus = EventBus()
        handler = AsyncMock()
        bus.subscribe(EventType.AGENT_STARTED, handler)
        bus.unsubscribe(EventType.AGENT_STARTED, handler)
        assert len(bus.subscribers["agent.started"]) == 0

    def test_subscribe_priority_order(self):
        bus = EventBus()
        low = AsyncMock()
        high = AsyncMock()
        bus.subscribe("test", low, priority=1)
        bus.subscribe("test", high, priority=10)
        # High priority should be first
        assert bus.subscribers["test"][0][0] is high
        assert bus.subscribers["test"][1][0] is low


class TestEventBusDispatch:
    """Test event dispatching."""

    async def test_dispatch_exact_match(self):
        bus = EventBus()
        handler = AsyncMock()
        bus.subscribe(EventType.TOOL_EXECUTION_START, handler)

        event = Event(type=EventType.TOOL_EXECUTION_START, data={"tool": "search"})
        await bus._dispatch_event(event)
        handler.assert_awaited_once_with(event)

    async def test_dispatch_wildcard(self):
        bus = EventBus()
        handler = AsyncMock()
        bus.subscribe("tool.*", handler)

        event = Event(type=EventType.TOOL_EXECUTION_COMPLETE, data={})
        await bus._dispatch_event(event)
        handler.assert_awaited_once()

    async def test_dispatch_wildcard_no_match(self):
        bus = EventBus()
        handler = AsyncMock()
        bus.subscribe("llm.*", handler)

        event = Event(type=EventType.TOOL_EXECUTION_START, data={})
        await bus._dispatch_event(event)
        handler.assert_not_awaited()

    async def test_dispatch_error_isolation(self):
        bus = EventBus()
        bad_handler = AsyncMock(side_effect=RuntimeError("boom"))
        good_handler = AsyncMock()
        bus.subscribe("test", bad_handler)
        bus.subscribe("test", good_handler)

        event = Event(type="test", data={})
        await bus._dispatch_event(event)
        # Good handler still called despite bad handler raising
        good_handler.assert_awaited_once()
        assert bus.stats["handler_errors"] >= 1


class TestEventBusPublish:
    """Test publishing and stats."""

    async def test_publish_increments_stats(self):
        bus = EventBus()
        event = Event(type=EventType.AGENT_STARTED, data={})
        await bus.publish(event)
        assert bus.stats["events_published"] == 1

    async def test_publish_sync_creates_event(self):
        bus = EventBus()
        await bus.publish_sync(EventType.LLM_CALL_START, {"model": "test"}, session_id="s1")
        assert bus.stats["events_published"] == 1
        # Check the event was queued
        event = await bus.queue.get()
        assert event.session_id == "s1"
        assert event.data["model"] == "test"

    def test_get_stats(self):
        bus = EventBus()
        stats = bus.get_stats()
        assert stats["events_published"] == 0
        assert stats["queue_size"] == 0
        assert stats["subscribers_count"] == 0
