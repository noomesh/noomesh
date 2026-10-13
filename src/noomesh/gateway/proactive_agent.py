# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Proactive agent loop -- event-driven and scheduled outbound messaging.

Subscribes to the event bus for trigger events (backend.*, rag.*, job.*,
node.*) and evaluates proactive rules on events AND on a periodic schedule.
When a rule fires it dispatches messages through the ChannelDispatcher
protocol so messages reach WhatsApp, Google Chat, or any registered channel.

Integrates with the autonomy engine audit log and reasoning engine for
LLM-composed messages.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import httpx
import structlog

from .deps import ssl_verify, client_cert
from ..channels.base import ChannelDispatcher
from ..events import Event, EventBus

logger = structlog.get_logger(__name__)

# Redis heartbeat key read by the Rust gateway's GET /api/proactive/status
# (gateway-rust/src/routes/ui.rs). Written with a short TTL from the schedule
# loop so a dead worker honestly reads as stopped.
STATUS_KEY = "noo:proactive:status"
STATUS_TTL_SECONDS = 30


# -- Data model ----------------------------------------------------------------

class TriggerType(str, Enum):
    EVENT = "event"
    SCHEDULE = "schedule"
    CONDITION = "condition"


class ActionType(str, Enum):
    CHANNEL_MESSAGE = "channel_message"
    LOG = "log"
    API_CALL = "api_call"


@dataclass
class ProactiveRule:
    """A single proactive rule: trigger -> action."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str = ""
    trigger_type: TriggerType = TriggerType.EVENT
    trigger_pattern: str = ""          # event glob (e.g. "backend.*") or cron-like
    channel_targets: list[str] = field(default_factory=lambda: ["*"])
    recipient: str = "broadcast"       # recipient ID or "broadcast"
    action_type: ActionType = ActionType.CHANNEL_MESSAGE
    template: str = ""                 # message template with {key} placeholders
    use_reasoning: bool = False        # use LLM to compose message
    cooldown_seconds: int = 300
    enabled: bool = True
    schedule_seconds: int = 0          # for TriggerType.SCHEDULE: interval in seconds
    condition_endpoint: str = ""       # for TriggerType.CONDITION: GET endpoint
    condition_metric: str = ""
    condition_operator: str = "gt"
    condition_threshold: Any = 0


@dataclass
class RuleFiring:
    """Audit record of a rule firing."""
    timestamp: float
    rule_id: str
    rule_name: str
    trigger_event: str
    message: str
    channels_sent: list[str]
    success: bool


# -- Default rules -------------------------------------------------------------

DEFAULT_RULES: list[ProactiveRule] = [
    ProactiveRule(
        id="backend_down",
        name="Backend down alert",
        trigger_type=TriggerType.CONDITION,
        trigger_pattern="backend.stopped",
        condition_endpoint="/api/cluster/backends",
        condition_metric="running_count",
        condition_operator="eq",
        condition_threshold=0,
        template="[PAI Alert] No inference backends are running. The cluster cannot serve requests until a backend is started.",
        cooldown_seconds=600,
        schedule_seconds=60,
    ),
    ProactiveRule(
        id="rag_ingest_complete",
        name="RAG ingest complete",
        trigger_type=TriggerType.EVENT,
        trigger_pattern="rag.ingest.*",
        template="[PAI] Document ingestion complete: {doc_title} ({pages} pages indexed).",
        cooldown_seconds=30,
    ),
    ProactiveRule(
        id="job_failed",
        name="Job failure alert",
        trigger_type=TriggerType.EVENT,
        trigger_pattern="job.failed",
        template="[PAI Alert] Job failed: {job_type} -- {error}",
        cooldown_seconds=60,
    ),
    ProactiveRule(
        id="daily_summary",
        name="Daily cluster summary",
        trigger_type=TriggerType.SCHEDULE,
        schedule_seconds=86400,
        use_reasoning=True,
        template="Generate a brief daily summary of the Mesh cluster status. Include: nodes online, backends running, jobs processed, RAG documents indexed.",
        cooldown_seconds=82800,
    ),
    ProactiveRule(
        id="node_degraded",
        name="Node health degraded",
        trigger_type=TriggerType.CONDITION,
        trigger_pattern="node.health.*",
        condition_endpoint="/api/cluster/nodes",
        condition_metric="offline_count",
        condition_operator="gt",
        condition_threshold=0,
        template="[PAI Alert] {offline_count} node(s) are offline. Online: {online_count}/{total_nodes}.",
        cooldown_seconds=600,
        schedule_seconds=120,
    ),
]


# -- Condition operators (reused from autonomy) --------------------------------

_OPS: dict[str, Any] = {
    "gt": lambda a, b: a > b,
    "lt": lambda a, b: a < b,
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "gte": lambda a, b: a >= b,
    "lte": lambda a, b: a <= b,
}


# -- ProactiveAgent ------------------------------------------------------------

class ProactiveAgent:
    """Main proactive agent loop.

    Listens to the event bus, evaluates rules periodically, and dispatches
    messages through the ChannelDispatcher.
    """

    def __init__(
        self,
        event_bus: EventBus,
        dispatcher: ChannelDispatcher,
        gateway_url: str = "https://localhost:8080",
        rules: list[ProactiveRule] | None = None,
    ) -> None:
        self._event_bus = event_bus
        self._dispatcher = dispatcher
        self._gateway_url = gateway_url.rstrip("/")
        self._rules: list[ProactiveRule] = list(rules or DEFAULT_RULES)
        self._cooldowns: dict[str, float] = {}
        self._last_schedule: dict[str, float] = {}
        self._history: list[RuleFiring] = []
        self._max_history = 200
        self._running = False
        self._schedule_task: Optional[asyncio.Task] = None
        self._redis_client: Any = None
        self._http = httpx.AsyncClient(
            timeout=15.0,
            verify=ssl_verify(),
            cert=client_cert(),
        )

    # -- Lifecycle -------------------------------------------------------------

    async def start(self) -> None:
        self._running = True
        # Subscribe to wildcard patterns for event-triggered rules
        patterns = set()
        for rule in self._rules:
            if rule.trigger_type == TriggerType.EVENT and rule.enabled:
                prefix = rule.trigger_pattern.replace("*", "")
                if prefix:
                    patterns.add(rule.trigger_pattern)
        # Also subscribe to broad wildcards
        for p in ("backend.*", "rag.*", "job.*", "node.*"):
            patterns.add(p)
        for pattern in patterns:
            self._event_bus.subscribe(pattern, self._on_event)
        # Start the schedule loop
        self._schedule_task = asyncio.create_task(self._schedule_loop())
        await self._write_status_heartbeat()
        logger.info("proactive_agent_started", rules=len(self._rules))

    async def stop(self) -> None:
        self._running = False
        if self._schedule_task:
            self._schedule_task.cancel()
            try:
                await self._schedule_task
            except asyncio.CancelledError:
                pass
        await self._http.aclose()
        # Clear the dashboard heartbeat key so status flips to stopped
        # immediately rather than waiting out the TTL.
        try:
            r = self._get_redis()
            if r is not None:
                await r.delete(STATUS_KEY)
        except Exception:
            pass
        logger.info("proactive_agent_stopped")

    # -- Status heartbeat --------------------------------------------------
    #
    # The Rust gateway's GET /api/proactive/status (routes/ui.rs) reports
    # running=true only while Redis key `noo:proactive:status` == "running".
    # Refreshing it with a short TTL from the live schedule loop means a
    # dead/never-started agent honestly shows stopped once the TTL lapses.

    def _get_redis(self) -> Any:
        """Lazy Redis client (same pattern as HeartbeatScheduler._get_redis).
        Returns None when Redis is unavailable — callers degrade gracefully."""
        if self._redis_client is not None:
            return self._redis_client
        try:
            import redis.asyncio as aioredis
            from ..cache import (
                _apply_redis_tls,
                _inject_redis_password,
                _redis_ssl_kwargs,
            )
            from ..config import env_or_yaml
            url = _apply_redis_tls(
                _inject_redis_password(env_or_yaml(
                    "REDIS_URL", lambda c: c.services.redis_url, "rediss://redis:6379"))
            )
            self._redis_client = aioredis.from_url(
                url, encoding="utf-8", decode_responses=True, **_redis_ssl_kwargs()
            )
        except ValueError as exc:
            # _apply_redis_tls refuses a plaintext redis:// URL with the
            # reason (Redis is TLS-only). Say so once instead of running
            # silently without Redis.
            if not getattr(self, "_redis_refusal_logged", False):
                logger.error("redis_url_refused", error=str(exc))
                self._redis_refusal_logged = True
            self._redis_client = None
        except Exception:
            self._redis_client = None
        return self._redis_client

    async def _write_status_heartbeat(self) -> None:
        """Best-effort SET noo:proactive:status running EX 30."""
        try:
            r = self._get_redis()
            if r is not None:
                await r.set(STATUS_KEY, "running", ex=STATUS_TTL_SECONDS)
        except Exception:
            pass

    # -- Event handler ---------------------------------------------------------

    async def _on_event(self, event: Event) -> None:
        event_key = event.type.value if hasattr(event.type, "value") else str(event.type)
        for rule in self._rules:
            if not rule.enabled:
                continue
            if rule.trigger_type != TriggerType.EVENT:
                continue
            if not self._pattern_matches(rule.trigger_pattern, event_key):
                continue
            if self._is_cooled_down(rule.id):
                continue
            await self._fire_rule(rule, event_key, event.data)

    # -- Schedule loop ---------------------------------------------------------

    async def _schedule_loop(self) -> None:
        while self._running:
            await self._write_status_heartbeat()
            now = time.monotonic()
            for rule in self._rules:
                if not rule.enabled:
                    continue
                if rule.trigger_type == TriggerType.SCHEDULE:
                    if rule.schedule_seconds <= 0:
                        continue
                    last = self._last_schedule.get(rule.id, 0)
                    if (now - last) >= rule.schedule_seconds:
                        self._last_schedule[rule.id] = now
                        if not self._is_cooled_down(rule.id):
                            await self._fire_rule(rule, "schedule", {})
                elif rule.trigger_type == TriggerType.CONDITION:
                    interval = rule.schedule_seconds or 60
                    last = self._last_schedule.get(rule.id, 0)
                    if (now - last) >= interval:
                        self._last_schedule[rule.id] = now
                        metrics = await self._check_condition(rule)
                        if metrics is not None and not self._is_cooled_down(rule.id):
                            await self._fire_rule(rule, "condition", metrics)
            await asyncio.sleep(5)

    # -- Condition checking ----------------------------------------------------

    async def _check_condition(self, rule: ProactiveRule) -> dict | None:
        if not rule.condition_endpoint:
            return None
        try:
            from ..cluster.cluster_auth import internal_gateway_headers
            resp = await self._http.get(
                f"{self._gateway_url}{rule.condition_endpoint}",
                headers=internal_gateway_headers("proactive_agent"),
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            # Flatten: if data is a dict with nested keys, handle top-level
            if isinstance(data, dict):
                # Try to extract the metric
                nodes = data.get("nodes", [])
                if isinstance(nodes, list) and rule.condition_metric in ("offline_count", "online_count", "total_nodes"):
                    total = len(nodes)
                    online = sum(1 for n in nodes if n.get("status") == "online")
                    data = {"total_nodes": total, "online_count": online, "offline_count": total - online}
                backends = data.get("backends", [])
                if isinstance(backends, list) and rule.condition_metric == "running_count":
                    data["running_count"] = len(backends)
            value = data.get(rule.condition_metric)
            if value is None:
                return None
            op = _OPS.get(rule.condition_operator)
            if op and op(value, rule.condition_threshold):
                return data
        except Exception as e:
            logger.debug("proactive_condition_check_failed", rule=rule.id, error=str(e))
        return None

    # -- Rule firing -----------------------------------------------------------

    async def _fire_rule(self, rule: ProactiveRule, trigger: str, data: dict) -> None:
        message = self._render_template(rule.template, data)

        if rule.use_reasoning:
            message = await self._compose_with_reasoning(rule, data, message)

        channels_sent: list[str] = []
        success = False

        if rule.action_type == ActionType.CHANNEL_MESSAGE:
            channels_sent, success = await self._dispatch_to_channels(rule, message)
        elif rule.action_type == ActionType.LOG:
            logger.info("proactive_rule_log", rule=rule.name, message=message)
            success = True
        elif rule.action_type == ActionType.API_CALL:
            success = await self._api_call(rule, data)

        self._update_cooldown(rule.id)
        firing = RuleFiring(
            timestamp=time.time(),
            rule_id=rule.id,
            rule_name=rule.name,
            trigger_event=trigger,
            message=message,
            channels_sent=channels_sent,
            success=success,
        )
        self._history.append(firing)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]
        logger.info(
            "proactive_rule_fired",
            rule=rule.name,
            trigger=trigger,
            channels=channels_sent,
            success=success,
        )

    async def _dispatch_to_channels(
        self, rule: ProactiveRule, message: str
    ) -> tuple[list[str], bool]:
        channels_sent: list[str] = []
        any_ok = False

        targets = rule.channel_targets
        if "*" in targets:
            # Discover available channels from the dispatcher
            if hasattr(self._dispatcher, "list_channels"):
                targets = self._dispatcher.list_channels()
            else:
                targets = ["whatsapp", "google_chat"]

        for channel in targets:
            try:
                # Resolve "broadcast" to the default saved recipient for this
                # channel.  If no default is configured, skip silently.
                recipient = rule.recipient
                if hasattr(self._dispatcher, "resolve_recipient"):
                    resolved = await self._dispatcher.resolve_recipient(
                        channel, recipient,
                    )
                    if resolved is None:
                        logger.debug(
                            "proactive_dispatch_skipped",
                            channel=channel,
                            reason="no default recipient configured",
                        )
                        continue
                    recipient = resolved

                ok = await self._dispatcher.dispatch(
                    channel=channel,
                    recipient=recipient,
                    message=message,
                )
                if ok:
                    channels_sent.append(channel)
                    any_ok = True
            except Exception as e:
                logger.warning(
                    "proactive_dispatch_failed",
                    channel=channel,
                    error=str(e),
                )
        return channels_sent, any_ok

    async def _compose_with_reasoning(
        self, rule: ProactiveRule, data: dict, fallback: str
    ) -> str:
        """Use the gateway inference API to compose an intelligent message."""
        try:
            prompt = (
                f"You are Mesh, the cluster assistant. Compose a brief, helpful "
                f"notification message for the operator. Context: {rule.template} "
                f"Current data: {data}. Keep it under 200 words."
            )
            from ..cluster.cluster_auth import internal_gateway_headers
            resp = await self._http.post(
                f"{self._gateway_url}/api/inference",
                json={"prompt": prompt, "stream": False},
                headers=internal_gateway_headers("proactive_agent"),
                timeout=30.0,
            )
            if resp.status_code == 200:
                result = resp.json()
                return result.get("response", result.get("text", fallback))
        except Exception as e:
            logger.warning("proactive_reasoning_failed", error=str(e))
        return fallback

    async def _api_call(self, rule: ProactiveRule, data: dict) -> bool:
        try:
            from ..cluster.cluster_auth import internal_gateway_headers
            path = rule.template  # reuse template as the API path for api_call action
            resp = await self._http.post(
                f"{self._gateway_url}{path}",
                json=data,
                headers=internal_gateway_headers("proactive_agent"),
            )
            return resp.status_code < 400
        except Exception:
            return False

    # -- Helpers ---------------------------------------------------------------

    @staticmethod
    def _pattern_matches(pattern: str, event_key: str) -> bool:
        if "*" in pattern:
            prefix = pattern.replace("*", "")
            return event_key.startswith(prefix)
        return pattern == event_key

    @staticmethod
    def _render_template(template: str, data: dict) -> str:
        try:
            return template.format_map(
                {k: v for k, v in data.items() if isinstance(v, (str, int, float, bool))}
            )
        except (KeyError, IndexError):
            return template

    def _is_cooled_down(self, rule_id: str) -> bool:
        last = self._cooldowns.get(rule_id, 0)
        rule = next((r for r in self._rules if r.id == rule_id), None)
        cd = rule.cooldown_seconds if rule else 300
        return (time.monotonic() - last) < cd

    def _update_cooldown(self, rule_id: str) -> None:
        self._cooldowns[rule_id] = time.monotonic()

    # -- Rule management -------------------------------------------------------

    def add_rule(self, rule: ProactiveRule) -> None:
        existing = next((r for r in self._rules if r.id == rule.id), None)
        if existing:
            self._rules.remove(existing)
        self._rules.append(rule)
        logger.info("proactive_rule_added", id=rule.id, name=rule.name)

    def remove_rule(self, rule_id: str) -> bool:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.id != rule_id]
        return len(self._rules) < before

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> bool:
        rule = next((r for r in self._rules if r.id == rule_id), None)
        if rule is None:
            return False
        rule.enabled = enabled
        return True

    # -- Status / history ------------------------------------------------------

    def get_status(self) -> dict:
        return {
            "running": self._running,
            "rules_total": len(self._rules),
            "rules_enabled": sum(1 for r in self._rules if r.enabled),
            "history_entries": len(self._history),
        }

    def get_rules(self) -> list[dict]:
        return [
            {
                "id": r.id,
                "name": r.name,
                "trigger_type": r.trigger_type.value,
                "trigger_pattern": r.trigger_pattern,
                "action_type": r.action_type.value,
                "channel_targets": r.channel_targets,
                "cooldown_seconds": r.cooldown_seconds,
                "enabled": r.enabled,
                "use_reasoning": r.use_reasoning,
                "template": r.template[:120],
            }
            for r in self._rules
        ]

    def get_history(self, limit: int = 50) -> list[dict]:
        entries = self._history[-limit:]
        return [
            {
                "timestamp": f.timestamp,
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "trigger_event": f.trigger_event,
                "message": f.message[:200],
                "channels_sent": f.channels_sent,
                "success": f.success,
            }
            for f in entries
        ]


# -- Global instance -----------------------------------------------------------

_agent: Optional[ProactiveAgent] = None


def get_proactive_agent() -> Optional[ProactiveAgent]:
    return _agent


def init_proactive_agent(
    event_bus: EventBus,
    dispatcher: ChannelDispatcher,
    gateway_url: str = "https://localhost:8080",
    rules: list[ProactiveRule] | None = None,
) -> ProactiveAgent:
    global _agent
    _agent = ProactiveAgent(
        event_bus=event_bus,
        dispatcher=dispatcher,
        gateway_url=gateway_url,
        rules=rules,
    )
    return _agent
