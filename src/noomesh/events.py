# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Event-driven architecture for agent activities"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional
from collections import defaultdict


class EventType(Enum):
    """Standard event types"""
    # Agent events
    AGENT_STARTED = "agent.started"
    AGENT_STOPPED = "agent.stopped"
    AGENT_STEP_START = "agent.step.start"
    AGENT_STEP_COMPLETE = "agent.step.complete"
    AGENT_ERROR = "agent.error"

    # LLM events
    LLM_CALL_START = "llm.call.start"
    LLM_CALL_COMPLETE = "llm.call.complete"
    LLM_CALL_ERROR = "llm.call.error"
    LLM_STREAM_TOKEN = "llm.stream.token"

    # Tool events
    TOOL_EXECUTION_START = "tool.execution.start"
    TOOL_EXECUTION_COMPLETE = "tool.execution.complete"
    TOOL_EXECUTION_ERROR = "tool.execution.error"

    # Memory events
    MEMORY_STORE = "memory.store"
    MEMORY_RETRIEVE = "memory.retrieve"

    # Session events
    SESSION_CREATED = "session.created"
    SESSION_RESET = "session.reset"
    SESSION_ENDED = "session.ended"

    # System events
    SYSTEM_HEALTH_CHECK = "system.health_check"
    SYSTEM_CACHE_HIT = "system.cache.hit"
    SYSTEM_CACHE_MISS = "system.cache.miss"


@dataclass
class Event:
    """Event with metadata"""
    type: EventType | str
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "type": self.type.value if isinstance(self.type, EventType) else self.type,
            "data": self.data,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "correlation_id": self.correlation_id,
        }


# Type alias for event handlers
EventHandler = Callable[[Event], Coroutine[Any, Any, None]]


class EventBus:
    """
    Pub/sub event bus for decoupled communication

    Features:
    - Subscribe to specific event types
    - Wildcard subscriptions (e.g., "llm.*")
    - Async event processing
    - Event queuing
    - Handler priority
    - Error isolation (handlers don't affect each other)
    """

    def __init__(self, queue_size: int = 1000):
        """
        Initialize event bus

        Args:
            queue_size: Maximum events in queue
        """
        self.subscribers: Dict[str, List[tuple[EventHandler, int]]] = defaultdict(list)
        self.queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=queue_size)
        self.running = False
        self.processor_task: Optional[asyncio.Task] = None
        self.stats = {
            "events_published": 0,
            "events_processed": 0,
            "handler_errors": 0,
        }

    def subscribe(
        self,
        event_type: EventType | str,
        handler: EventHandler,
        priority: int = 0
    ) -> None:
        """
        Subscribe to event type

        Args:
            event_type: Event type or pattern (e.g., "llm.*")
            handler: Async function to handle events
            priority: Handler priority (higher = earlier execution)
        """
        key = event_type.value if isinstance(event_type, EventType) else event_type
        self.subscribers[key].append((handler, priority))
        # Sort by priority (descending)
        self.subscribers[key].sort(key=lambda x: x[1], reverse=True)

    def unsubscribe(
        self,
        event_type: EventType | str,
        handler: EventHandler
    ) -> None:
        """
        Unsubscribe from event type

        Args:
            event_type: Event type
            handler: Handler to remove
        """
        key = event_type.value if isinstance(event_type, EventType) else event_type
        self.subscribers[key] = [
            (h, p) for h, p in self.subscribers[key] if h != handler
        ]

    async def publish(self, event: Event) -> None:
        """
        Publish event to subscribers

        Args:
            event: Event to publish
        """
        try:
            await self.queue.put(event)
            self.stats["events_published"] += 1
        except asyncio.QueueFull:
            # Queue full, drop oldest event (could also block)
            pass

    async def publish_sync(
        self,
        event_type: EventType | str,
        data: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> None:
        """
        Publish event synchronously

        Args:
            event_type: Type of event
            data: Event data
            **kwargs: Additional event fields (session_id, etc.)
        """
        event = Event(
            type=event_type,
            data=data or {},
            session_id=kwargs.get("session_id"),
            correlation_id=kwargs.get("correlation_id"),
        )
        await self.publish(event)

    async def start(self) -> None:
        """Start event processor"""
        if self.running:
            return

        self.running = True
        self.processor_task = asyncio.create_task(self._process_events())

    async def stop(self) -> None:
        """Stop event processor"""
        self.running = False
        if self.processor_task:
            self.processor_task.cancel()
            try:
                await self.processor_task
            except asyncio.CancelledError:
                pass

    async def _process_events(self) -> None:
        """Process events from queue"""
        while self.running:
            try:
                event = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                await self._dispatch_event(event)
                self.stats["events_processed"] += 1
            except asyncio.TimeoutError:
                continue
            except Exception:
                # Log error but keep processing
                self.stats["handler_errors"] += 1

    async def _dispatch_event(self, event: Event) -> None:
        """
        Dispatch event to matching subscribers

        Args:
            event: Event to dispatch
        """
        event_key = event.type.value if isinstance(event.type, EventType) else event.type

        # Find matching subscribers
        handlers_to_call = []

        # Exact match
        if event_key in self.subscribers:
            handlers_to_call.extend([h for h, _ in self.subscribers[event_key]])

        # Wildcard match (e.g., "llm.*" matches "llm.call.start")
        for pattern, handlers in self.subscribers.items():
            if "*" in pattern:
                pattern_prefix = pattern.replace("*", "")
                if event_key.startswith(pattern_prefix):
                    handlers_to_call.extend([h for h, _ in handlers])

        # Call all matching handlers concurrently
        if handlers_to_call:
            await asyncio.gather(
                *[self._safe_call_handler(handler, event) for handler in handlers_to_call],
                return_exceptions=True
            )

    async def _safe_call_handler(
        self,
        handler: EventHandler,
        event: Event
    ) -> None:
        """
        Safely call handler with error isolation

        Args:
            handler: Handler function
            event: Event to pass
        """
        try:
            await handler(event)
        except Exception:
            # Isolate handler errors
            self.stats["handler_errors"] += 1

    def get_stats(self) -> Dict[str, Any]:
        """
        Get event bus statistics

        Returns:
            Statistics dictionary
        """
        return {
            **self.stats,
            "queue_size": self.queue.qsize(),
            "subscribers_count": sum(len(handlers) for handlers in self.subscribers.values()),
        }


# Global event bus instance
_global_event_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """
    Get global event bus instance

    Returns:
        Global EventBus instance
    """
    global _global_event_bus
    if _global_event_bus is None:
        _global_event_bus = EventBus()
    return _global_event_bus


async def publish_event(
    event_type: EventType | str,
    data: Optional[Dict[str, Any]] = None,
    **kwargs
) -> None:
    """
    Convenience function to publish event to global bus.

    Automatically injects trace_id from OpenTelemetry into correlation_id
    if tracing is active and no correlation_id is provided.

    Args:
        event_type: Type of event
        data: Event data
        **kwargs: Additional event fields
    """
    # Bridge: inject OTel trace_id as correlation_id
    if "correlation_id" not in kwargs or kwargs["correlation_id"] is None:
        try:
            from .tracing import current_trace_id
            trace_id = current_trace_id()
            if trace_id:
                kwargs["correlation_id"] = trace_id
        except ImportError:
            pass

    bus = get_event_bus()
    await bus.publish_sync(event_type, data, **kwargs)


# Convenience event publishers

async def publish_agent_step(
    step_number: int,
    tools_called: List[str],
    duration_ms: float,
    session_id: Optional[str] = None
) -> None:
    """Publish agent step completion"""
    await publish_event(
        EventType.AGENT_STEP_COMPLETE,
        {
            "step_number": step_number,
            "tools_called": tools_called,
            "duration_ms": duration_ms,
        },
        session_id=session_id,
    )


async def publish_llm_call(
    model: str,
    messages_count: int,
    tools_count: int,
    duration_ms: float,
    success: bool = True,
    error: Optional[str] = None,
    session_id: Optional[str] = None
) -> None:
    """Publish LLM call completion"""
    event_type = EventType.LLM_CALL_COMPLETE if success else EventType.LLM_CALL_ERROR
    await publish_event(
        event_type,
        {
            "model": model,
            "messages_count": messages_count,
            "tools_count": tools_count,
            "duration_ms": duration_ms,
            "success": success,
            "error": error,
        },
        session_id=session_id,
    )


async def publish_tool_execution(
    tool_name: str,
    args: Dict[str, Any],
    duration_ms: float,
    success: bool = True,
    error: Optional[str] = None,
    session_id: Optional[str] = None
) -> None:
    """Publish tool execution completion"""
    event_type = EventType.TOOL_EXECUTION_COMPLETE if success else EventType.TOOL_EXECUTION_ERROR
    await publish_event(
        event_type,
        {
            "tool_name": tool_name,
            "args": {k: str(v)[:100] for k, v in args.items()},  # Truncate
            "duration_ms": duration_ms,
            "success": success,
            "error": error,
        },
        session_id=session_id,
    )


async def publish_memory_retrieval(
    query: str,
    results_count: int,
    duration_ms: float,
    scoring_method: str,
    session_id: Optional[str] = None
) -> None:
    """Publish memory retrieval"""
    await publish_event(
        EventType.MEMORY_RETRIEVE,
        {
            "query": query[:100],  # Truncate
            "results_count": results_count,
            "duration_ms": duration_ms,
            "scoring_method": scoring_method,
        },
        session_id=session_id,
    )


# Example event handlers

async def log_event_handler(event: Event) -> None:
    """Simple logging handler"""
    import structlog
    logger = structlog.get_logger("noo.events")
    logger.info(f"Event: {event.type.value if isinstance(event.type, EventType) else event.type}", extra=event.to_dict())


async def metrics_handler(event: Event) -> None:
    """Example metrics collection handler"""
    # Could send to Prometheus, StatsD, etc.
    pass


async def audit_handler(event: Event) -> None:
    """Example audit logging handler"""
    # Could write to audit log file or database
    pass
