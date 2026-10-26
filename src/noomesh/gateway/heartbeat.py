# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Heartbeat Scheduler -- the Python executor for delegated heartbeat actions.

The Rust gateway owns cron firing (``gateway-rust/src/heartbeat_loop.rs``)
and channel delivery (``heartbeat_actions::notify_channels``, behind the
egress boundary). This module runs only the actions Rust delegates to it,
via ``run_task_now`` on ``worker.api.heartbeat.run``. The Python firing
loop (``start``/``_tick``, selected by ``GATEWAY_ENGINE=python``) and its
channel output route were retired: they posted result
text to ``/api/channels/send`` outside the Rust delivery path.

User-facing, scheduled actions (daily briefings, cluster health checks,
RAG reindexing, memory cleanup, custom prompts). Distinct from the
optional self-improvement loop, which handles internal meta-cognition.

Requires ``croniter`` for cron expression parsing (optional dependency).
"""
from __future__ import annotations

import asyncio
import difflib
from .. import json_fast as json
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree

import httpx
import structlog

from .deps import ssl_verify, client_cert
from ..ops_client import settle

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Optional dependency
# ---------------------------------------------------------------------------

try:
    from croniter import croniter
    CRONITER_AVAILABLE = True
except ImportError:
    croniter = None  # type: ignore[assignment,misc]
    CRONITER_AVAILABLE = False

try:
    import feedparser  # type: ignore[import-untyped]
    FEEDPARSER_AVAILABLE = True
except ImportError:
    feedparser = None  # type: ignore[assignment]
    FEEDPARSER_AVAILABLE = False


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Canonical definition lives in config.py so the CLI can mount the config
# model without importing this module's runtime deps. Re-exported here for
# existing importers (worker_pool).
from ..config import HeartbeatConfig  # noqa: E402


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class HeartbeatTask:
    """A single scheduled task."""
    id: str
    name: str
    schedule: str  # cron expression, e.g. "0 8 * * *"
    action: str = "custom_prompt"
    config: Dict[str, Any] = field(default_factory=dict)
    channels: List[str] = field(default_factory=list)
    recipients: List[str] = field(default_factory=list)
    enabled: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    created_by: str = "user"  # "user" | "agent" | "system"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "schedule": self.schedule,
            "action": self.action,
            "config": self.config,
            "channels": self.channels,
            "recipients": self.recipients,
            "enabled": self.enabled,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "created_by": self.created_by,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HeartbeatTask:
        last_run = None
        if data.get("last_run"):
            try:
                last_run = datetime.fromisoformat(data["last_run"])
            except (ValueError, TypeError):
                pass
        next_run = None
        if data.get("next_run"):
            try:
                next_run = datetime.fromisoformat(data["next_run"])
            except (ValueError, TypeError):
                pass

        return cls(
            id=data.get("id", str(uuid.uuid4())[:8]),
            name=data.get("name", "unnamed"),
            schedule=data.get("schedule", "0 8 * * *"),
            action=data.get("action", "custom_prompt"),
            config=data.get("config", {}),
            channels=data.get("channels", []),
            recipients=data.get("recipients", []),
            enabled=data.get("enabled", True),
            last_run=last_run,
            next_run=next_run,
            created_by=data.get("created_by", "user"),
        )


@dataclass
class TaskRunRecord:
    """Result of a single task execution."""
    run_id: str
    task_id: str
    task_name: str
    action: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str = "running"     # running | success | error
    result_text: str = ""
    error: str = ""
    duration_ms: int = 0
    notified_channels: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "task_id": self.task_id,
            "task_name": self.task_name,
            "action": self.action,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status,
            "result_text": self.result_text[:2000],
            "error": self.error,
            "duration_ms": self.duration_ms,
            "notified_channels": self.notified_channels,
            "artifacts": self.artifacts,
        }


# ========================================================================
# Workspace helpers
# ========================================================================

def _resolve_workspace_dir() -> str:
    """Return the configured workspace directory for heartbeat artifacts.

    The workspace is a dedicated writable directory separate from watched
    folders (which are read-only and auto-ingested).  Falls back to /tmp
    if no workspace is configured.
    """
    try:
        from ..config import get_config
        cfg = get_config()
        ws = cfg.workspace.path
        if ws:
            return ws
    except Exception:
        pass
    return "/tmp"


def confined_output_path(default_ws: str, ws_override: Any, filename: str) -> Path:
    """Where a heartbeat action may write `filename`: inside the workspace, or refuse.

    Task config is data an agent can author. `Path(workspace) / "/abs/file"` is `/abs/file`, so an
    absolute filename aimed a truncating write at any file the gateway can reach. The path must be
    relative, plain names only, under the resolved workspace (a `workspace_dir` override only if it is
    itself inside it), with no symlink on the way out. Mirror of `gateway-rust/src/confine.rs`.
    """
    if ws_override is not None and not isinstance(ws_override, str):
        raise ValueError("workspace_dir must be a string")
    if not isinstance(filename, str) or not filename or "\0" in filename:
        raise ValueError("filename must be a non-empty string")
    default = Path(default_ws)
    default.mkdir(parents=True, exist_ok=True)
    root = default.resolve()

    def walk(start: Path, rel: Path, shown: str) -> Path:
        cur = start
        for part in rel.parts:
            if part in ("", "."):
                continue
            if part == ".." or Path(part).is_absolute():
                raise ValueError(f"{shown!r} must be a relative path of plain names")
            cur = cur / part
            if cur.exists():
                real = cur.resolve()
                if real != root and root not in real.parents:
                    raise ValueError(f"{shown!r} leaves the workspace (through {cur})")
                if not real.is_dir():
                    raise ValueError(f"{cur} is not a directory")
                cur = real
            else:
                cur.mkdir()
        return cur

    base = root
    if ws_override:
        p = Path(ws_override)
        if p.is_absolute():
            try:
                rel = p.relative_to(root)
            except ValueError:
                try:
                    rel = p.relative_to(default)
                except ValueError:
                    raise ValueError(f"workspace_dir {ws_override!r} is outside the workspace {root}") from None
        else:
            rel = p
        base = walk(root, rel, ws_override)
    f = Path(filename)
    if f.is_absolute() or ".." in f.parts or not f.name:
        raise ValueError(f"{filename!r} must be a relative path of plain names")
    out_dir = walk(base, f.parent, filename)
    out = out_dir / f.name
    if out.is_symlink():
        raise ValueError(f"{out} is a symlink; refusing to write through it")
    return out


def open_confined(path: Path):
    """Open `path` (from `confined_output_path`) for writing without following a symlink.

    The path was checked a moment ago; between that check and the write, something else could swap a
    symlink in. `O_NOFOLLOW` makes the open itself refuse one, so the check and the write cannot be
    split. NOT truncated here: the caller truncates at write time (`f.truncate(0)`), so opening early,
    before a slow gather, does not leave an empty file behind if the run fails. The descriptor is
    closed on any error. Mirror of `confine::open_output` in Rust.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o644)
    try:
        return os.fdopen(fd, "w", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise


# Actions whose runs are agent turns (mirror of RUST_LLM_ACTIONS in heartbeat_actions.rs). A pipeline
# runs in Python, where an LLM step falls back to POST /api/agent/run with every tool, so a pipeline
# step may not be one: the Rust side limits an unauthorised task's tools, this path cannot.
_LLM_ACTIONS = frozenset({
    "research_report", "research_and_send", "custom_prompt", "daily_briefing", "chat_digest",
    "conversation_summarize", "news_scan", "channel_message", "goal_review",
    # not on the Rust LLM list, but also agent turns (task_guard.rs AGENT_TURN_EXTRA)
    "self_benchmark", "continue_pending_tasks",
})


# ========================================================================
# Cron helpers
# ========================================================================

def compute_next_run(cron_expr: str, base: Optional[datetime] = None) -> Optional[datetime]:
    """Compute the next run time from a cron expression."""
    if not CRONITER_AVAILABLE:
        logger.warning("heartbeat_croniter_missing",
                       message="Install croniter: pip install croniter")
        return None
    try:
        base = base or datetime.now(timezone.utc)
        it = croniter(cron_expr, base)
        return it.get_next(datetime).replace(tzinfo=timezone.utc)
    except (ValueError, KeyError) as e:
        logger.error("heartbeat_cron_parse_error", cron=cron_expr, error=str(e))
        return None


def validate_cron(cron_expr: str) -> bool:
    """Return True if the cron expression is syntactically valid."""
    if not CRONITER_AVAILABLE:
        return True
    try:
        croniter(cron_expr)
        return True
    except (ValueError, KeyError):
        return False


# ========================================================================
# Helpers
# ========================================================================

def _get_safe_eval():
    """Lazy accessor for workflows._safe_eval — importing workflows at module
    level drags agent→memory→torch into everything that imports heartbeat
    (config.py mounts HeartbeatConfig, so the CLI would pay ~2s per run)."""
    try:
        from ..workflows.workflow import _safe_eval
        return _safe_eval
    except ImportError:
        return None


def _resolve_config(config: Dict, context: Dict[str, str], date_str: str) -> Dict:
    """Recursively substitute ``{step_name}`` and ``{date}`` references in config values."""
    mapping = {**context, "date": date_str}

    def _sub(v: Any) -> Any:
        if isinstance(v, str):
            try:
                return v.format_map(mapping)
            except (KeyError, ValueError):
                return v
        if isinstance(v, dict):
            return {k: _sub(val) for k, val in v.items()}
        if isinstance(v, list):
            return [_sub(item) for item in v]
        return v

    return {k: _sub(v) for k, v in config.items()}


def _format_bytes(n: int) -> str:
    """Return a human-readable byte size string (e.g. '340 MB')."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} PB"


# ========================================================================
# Coordinator proxy — Rust-primary mode fallback
# ========================================================================

@dataclass
class _CoordResult:
    """Mimics CoordinatorAgent.run()'s return value (the bits heartbeat reads)."""
    response: str = ""


# System/scheduler pseudo-senders that are NOT real users — these must
# resolve to the operator identity so proactive tasks run with the operator's
# memory/KB context instead of fail-closing on a multi-account install (or
# scoping to a data-less "heartbeat" bucket). Trusted: these calls carry
# the cluster-HMAC header, i.e. they're the operator's own automation.
_SYSTEM_SENDERS = frozenset({"", "heartbeat", "heartbeat_scheduler", "scheduler", "system"})


def _operator_user() -> str:
    """The identity trusted internal/system callers act as. Defaults to the
    admin operator (NOO_ADMIN_USER); NOO_OPERATOR_USER overrides. Empty when
    unconfigured (then behaviour is unchanged — no scoping)."""
    return (os.getenv("NOO_OPERATOR_USER") or os.getenv("NOO_ADMIN_USER") or "").strip()


def _resolve_actor_user(sender_id: str | None) -> str:
    """Map a heartbeat sender_id to the user_id used for memory/KB scoping.
    Real user senders pass through; system/scheduler pseudo-senders become the
    operator. In single-user mode user_id is ignored downstream, so this is a
    no-op there."""
    sid = (sender_id or "").strip()
    if sid and sid not in _SYSTEM_SENDERS:
        return sid
    return _operator_user()


class _HttpCoordinatorProxy:
    """HTTP fallback that mimics ``CoordinatorAgent.run(...)``.

    Used when the in-process Python ``CoordinatorAgent`` isn't constructed
    (Rust-primary mode — channels and the agentic loop
    both moved to native Rust). Heartbeat actions still need *some*
    coordinator-shaped object; this proxy POSTs to ``/api/inference``,
    which the Rust gateway serves natively, and returns an object with
    ``.response`` so existing call sites don't need to change.

    Tracked.
    """

    def __init__(self, gateway_url: str, http_client_factory):
        self._gateway_url = gateway_url.rstrip("/")
        self._http_client_factory = http_client_factory

    def __bool__(self) -> bool:
        # Lots of `if self.coordinator:` guards in heartbeat.py — they
        # should treat the proxy as truthy.
        return True

    async def run(
        self,
        message: str | None = None,
        prompt: str | None = None,
        conversation_id: str | None = None,
        channel: str = "heartbeat",
        sender_id: str | None = None,
        sender_name: str | None = None,
        model: str | None = None,
        **_kwargs: Any,
    ) -> _CoordResult:
        text = message if message is not None else (prompt or "")
        client = self._http_client_factory()
        try:
            # /api/inference requires auth; loopback calls from in-process
            # heartbeat tasks need the cluster-HMAC header. Without it the
            # gateway returns 401 and the task completes in ~9ms with no
            # actual report generated. Mirrors the pattern used by
            # proactive_agent.py and the Rust heartbeat_actions.rs.
            from ..cluster.cluster_auth import internal_gateway_headers
            payload = {
                "prompt": text,
                "conversation_id": conversation_id or "",
                "channel": channel or "heartbeat",
                # System/scheduler senders resolve to the operator so proactive
                # tasks keep memory/KB context on a multi-account install
                # (where an unattributed read would fail closed).
                "user_id": _resolve_actor_user(sender_id),
            }
            # Optional model override — a claude-*/gpt-*/gemini-* prefix makes
            # native_inference route to the cloud provider. Research tasks set
            # this so a capable model reliably chains web_search (the local
            # gemma-4-12B doesn't). Omitted → local default backend.
            if model:
                payload["model"] = model
            r = await client.post(
                f"{self._gateway_url}/api/inference",
                json=payload,
                headers=internal_gateway_headers("heartbeat"),
                timeout=300.0,  # cron tasks can be long-running (research_report)
            )
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            logger.warning("heartbeat_http_coordinator_failed", error=str(e))
            return _CoordResult(response="")

        # /api/inference returns either {"success":true,"data":{...}} or
        # the bare data dict depending on path; tolerate both.
        if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict):
            data = data["data"]
        if isinstance(data, dict):
            response_text = (
                data.get("response")
                or data.get("text")
                or data.get("answer")
                or ""
            )
        else:
            response_text = str(data)
        return _CoordResult(response=response_text or "")


# ========================================================================
# Action executors
# ========================================================================

class HeartbeatActionExecutor:
    """Executes built-in heartbeat actions via the gateway HTTP API."""

    # Allowlisted cleanup targets for the detection-only disk_cleanup scan.
    # (The dashboard's POST /api/cleanup/run is gone; heartbeat_run_records
    # is pruned by the gateway's heartbeat_retention task.)
    CLEANUP_TARGETS = {
        "tmp_noo_files",
        "heartbeat_run_records",
        "docker_dangling_images",
        "container_logs",
    }

    _MAX_PIPELINE_DEPTH = 3

    def __init__(self, gateway_url: str, coordinator: Any = None):
        self.gateway_url = gateway_url.rstrip("/")
        # In Rust-primary mode the Python CoordinatorAgent is no longer
        # constructed (channels now call Rust coordinator::run() in-process).
        # Heartbeat tasks like research_report / chat_digest call
        # `self.coordinator.run(...)` though — so we install a thin HTTP
        # proxy that POSTs /api/inference. Same call shape, returns an
        # object with `.response`. Tracked.
        if coordinator is None:
            coordinator = _HttpCoordinatorProxy(self.gateway_url, self._get_http_client)
        self.coordinator = coordinator
        self._http_client: httpx.AsyncClient | None = None
        self._current_artifacts: List[str] = []
        self._pipeline_depth: int = 0

    def _get_http_client(self) -> httpx.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                timeout=30.0,
                verify=ssl_verify(),
                cert=client_cert(),
                limits=httpx.Limits(
                    max_keepalive_connections=20,
                    max_connections=100,
                    keepalive_expiry=30,
                ),
            )
        return self._http_client

    async def close_http_client(self):
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.close()

    # -- Lazy getters for gateway singletons --------------------------------

    def _get_conversation_store(self) -> Any:
        try:
            from ..memory.conversation_store import ConversationStore  # noqa: F401
            from .deps import services
            return getattr(services, "conversation_store", None)
        except Exception:
            return None

    def _get_pageindex_store(self) -> Any:
        try:
            from .deps import services
            rag = getattr(services, "pageindex_rag", None)
            return getattr(rag, "store", None) if rag else None
        except Exception:
            return None

    def _get_redis(self) -> Any:
        """Lazy Redis client for cross-run task state. Returns None when
        Redis is unavailable — callers must degrade gracefully."""
        if getattr(self, "_redis_client", None) is not None:
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

    # -- Dispatch -----------------------------------------------------------

    async def execute(self, task: HeartbeatTask) -> str:
        """Execute the action for a task and return the result text."""
        _dispatch: Dict[str, Any] = {
            "daily_briefing": self._daily_briefing,
            "cluster_health": self._cluster_health,
            "memory_cleanup": self._memory_cleanup,
            "idle_scaledown": self._idle_scaledown,
            "custom_prompt": self._custom_prompt,
            # Knowledge & Memory
            "knowledge_refresh": self._knowledge_refresh,
            "conversation_summarize": self._conversation_summarize,
            "graph_prune": self._graph_prune,
            "memory_relevance_audit": self._memory_relevance_audit,
            # Proactive Awareness
            "news_scan": self._news_scan,
            "goal_review": self._goal_review,
            "channel_keepalive": self._channel_keepalive,
            # Operational Resilience
            "model_cache_warm": self._model_cache_warm,
            "backup_knowledge": self._backup_knowledge,
            "disk_cleanup": self._disk_cleanup,
            "cost_report": self._cost_report,
            # Self-Assessment
            "self_benchmark": self._self_benchmark,
            "security_audit": self._security_audit,
            # Security Operations
            "cert_rotation_check": self._cert_rotation_check,
            "audit_log_rotate": self._audit_log_rotate,
            "cert_auto_rotate": self._cert_auto_rotate,
            # Logging
            "write_log": self._write_log,
            # External / outbound
            "research_report": self._research_report,
            "structured_research": self._structured_research,
            "research_and_send": self._research_and_send,
            "chat_digest": self._chat_digest,
            # Graph enrichment
            "graph_clustering": self._graph_clustering,
            "graph_signals": self._graph_signals,
            # System 1 rehearsal
            "thought_experiment": self._thought_experiment,
            # Async task coordinator
            "continue_pending_tasks": self._continue_pending_tasks,
            # Pipelines
            "pipeline": self._pipeline,
        }
        handler = _dispatch.get(task.action)
        if handler:
            return await handler(task)
        # RAISE, don't return. An unknown action means the task is doing nothing
        # at all — a typo, a renamed action, or a routing regression. Returning a
        # string recorded that as a SUCCESSFUL run, so the task reported healthy
        # forever while never executing. This is not hypothetical: during the
        # Rust port, Rust-native actions were mis-routed to Python and produced
        # "Unknown action: agent_self_check" — logged as success (see the note in
        # gateway-rust/src/routes/intelligence.rs).
        raise RuntimeError(
            f"Unknown heartbeat action: {task.action!r} (task {task.id!r}). "
            "The task is registered but no handler matches — check for a typo, "
            "a renamed action, or an action that should route to Rust."
        )

    async def _daily_briefing(self, task: HeartbeatTask) -> str:
        """Summarize system status, recent conversations, and pending items."""
        sections: List[str] = []

        client = self._get_http_client()
        try:
            r = await client.get(f"{self.gateway_url}/api/cluster/nodes")
            if r.status_code == 200:
                nodes = r.json()
                if isinstance(nodes, dict):
                    nodes = nodes.get("nodes", [])
                online = sum(1 for n in nodes if n.get("status") == "online")
                sections.append(
                    f"**Cluster**: {online}/{len(nodes)} nodes online"
                )
        except Exception:
            sections.append("**Cluster**: unable to fetch status")

        try:
            r = await client.get(f"{self.gateway_url}/api/v1/rag/status")
            if r.status_code == 200:
                rag = r.json()
                docs = rag.get("document_count", 0)
                pages = rag.get("page_count", 0)
                unembedded = rag.get("unembedded_pages", 0)
                sections.append(
                    f"**Knowledge Base**: {docs} docs, {pages} pages "
                    f"({unembedded} unembedded)"
                )
        except Exception:
            pass

        try:
            r = await client.get(f"{self.gateway_url}/api/cache/stats")
            if r.status_code == 200 and r.json().get("enabled", True) is not None:
                cache = r.json()
                hits = cache.get("hits", 0)
                misses = cache.get("misses", 0)
                total = hits + misses
                rate = round((hits / total) * 100, 1) if total > 0 else 0
                sections.append(f"**Cache**: {rate}% hit rate ({total} requests)")
        except Exception:
            pass

        try:
            r = await client.get(f"{self.gateway_url}/api/scheduler/status")
            if r.status_code == 200:
                sched = r.json()
                depth = sched.get("queue_depth", 0)
                active = sched.get("active_jobs", 0)
                if depth is None or active is None:
                    # Redis not connected: the gateway reports null, not 0.
                    sections.append("**Jobs**: not reported (queue unreadable)")
                else:
                    sections.append(f"**Jobs**: {active} active, {depth} queued")
        except Exception:
            pass

        if not sections:
            return "Daily briefing: unable to collect system metrics."

        header = (
            f"**Daily Briefing** "
            f"({datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')})"
        )
        return header + "\n\n" + "\n".join(sections)

    async def _cluster_health(self, task: HeartbeatTask) -> str:
        """Check node status and report any degraded nodes."""
        alert_threshold = task.config.get("alert_on_offline", True)

        client = self._get_http_client()
        try:
            r = await client.get(f"{self.gateway_url}/api/cluster/nodes")
            if r.status_code != 200:
                return "Cluster health: failed to fetch node list"
            nodes = r.json()
            if isinstance(nodes, dict):
                nodes = nodes.get("nodes", [])
        except Exception as e:
            raise RuntimeError(f"Cluster health: error fetching nodes: {e}") from e

        total = len(nodes)
        online = [n for n in nodes if n.get("status") == "online"]
        offline = [n for n in nodes if n.get("status") != "online"]

        lines = [f"**Cluster Health**: {len(online)}/{total} nodes online"]
        if offline and alert_threshold:
            for n in offline:
                hostname = n.get("hostname", n.get("id", "unknown"))
                lines.append(f"  - OFFLINE: {hostname}")
        else:
            lines.append("All nodes healthy.")

        try:
            client = self._get_http_client()
            r = await client.get(f"{self.gateway_url}/api/cluster/backends")
            if r.status_code == 200:
                backends = r.json().get("backends", [])
                lines.append(f"Active backends: {len(backends)}")
        except Exception:
            pass

        return "\n".join(lines)

    async def _memory_cleanup(self, task: HeartbeatTask) -> str:
        """Prune old conversation memory."""
        max_age_days = task.config.get("max_age_days", 90)

        client = self._get_http_client()
        try:
            r = await client.post(
                f"{self.gateway_url}/api/memory/cleanup",
                json={"max_age_days": max_age_days},
            )
            if r.status_code == 200:
                result = r.json()
                removed = result.get("removed", 0)
                return (
                    f"Memory cleanup: removed {removed} entries "
                    f"older than {max_age_days} days."
                )
            elif r.status_code == 404:
                return "Memory cleanup: endpoint not available (no cleanup API)."
            else:
                raise RuntimeError(f"Memory cleanup: endpoint returned {r.status_code}")
        except Exception as e:
            raise RuntimeError(f"Memory cleanup failed: {e}") from e

    async def _audit_log_rotate(self, task: HeartbeatTask) -> str:
        """Export-then-drop noo_security_audit partitions older than retention.

        Also lazily creates current + next month partitions so inserts keep
        working across the month boundary.
        """
        try:
            from ..db import get_async_engine
            from ..config import get_config
            from .audit_archive import (
                ArchiveConfig,
                ensure_current_and_next,
                rotate,
            )
        except Exception as e:
            raise RuntimeError(f"Audit rotate failed to initialise: {e}") from e

        retention_months = int(
            task.config.get(
                "retention_months",
                get_config().security.audit_retention_months,
            )
        )
        cfg = ArchiveConfig.from_pydantic(get_config().audit_archive)
        engine = get_async_engine()

        # 1. Ensure current + next month partitions exist
        try:
            await ensure_current_and_next(engine)
        except Exception as e:
            raise RuntimeError(f"Audit rotate: ensure_partition failed: {e}") from e

        # 2. Rotate expired partitions
        try:
            result = await rotate(engine, cfg, retention_months)
        except Exception as e:
            raise RuntimeError(f"Audit rotate: rotation failed: {e}") from e

        return (
            f"Audit rotate: exported={result['exported']} "
            f"dropped={result['dropped']} errors={result['errors']} "
            f"(retention={retention_months}mo, backend={cfg.backend})"
        )

    async def _idle_scaledown(self, task: HeartbeatTask) -> str:
        """Stop backends that have been idle longer than the threshold."""
        idle_threshold = task.config.get("idle_threshold_sec", 600)

        try:
            from ..cluster.backend_manager import get_backend_manager
            bm = get_backend_manager()
        except ImportError:
            bm = None

        if not bm:
            return "Idle scaledown: BackendManager not available."

        idle = bm.get_idle_backends(idle_threshold)
        if not idle:
            return "Idle scaledown: no idle backends found."

        stopped = []
        for node, backend_type in idle:
            ok = await bm.stop_backend(node, backend_type)
            if ok:
                stopped.append(f"{backend_type} on {node.hostname}")
                logger.info("heartbeat_idle_scaledown",
                            backend=backend_type, node=node.id)

        if stopped:
            return f"Idle scaledown: stopped {len(stopped)} backend(s): {', '.join(stopped)}"
        return "Idle scaledown: found idle backends but failed to stop them."

    async def _custom_prompt(self, task: HeartbeatTask) -> str:
        """Run a user-defined prompt through the agent and return the result."""
        prompt = task.config.get("prompt", "")
        if not prompt:
            return "Custom prompt: no prompt configured in task config."

        if self.coordinator:
            try:
                result = await self.coordinator.run(
                    message=prompt,
                    conversation_id=None,
                    channel="heartbeat",
                    sender_id="heartbeat_scheduler",
                    sender_name="Heartbeat",
                )
                return result.response
            except Exception as e:
                logger.warning("heartbeat_coordinator_error", error=str(e))

        client = self._get_http_client()
        try:
            r = await client.post(
                f"{self.gateway_url}/api/agent/run",
                json={
                    "prompt": prompt,
                    "stream": False,
                    "tools_enabled": task.config.get("tools_enabled", True),
                },
            )
            if r.status_code == 200:
                return r.json().get("response", r.json().get("text", ""))
            else:
                raise RuntimeError(f"Custom prompt: agent returned {r.status_code}")
        except Exception as e:
            raise RuntimeError(f"Custom prompt failed: {e}") from e

    # ====================================================================
    # Category 1: Knowledge & Memory
    # ====================================================================

    async def _knowledge_refresh(self, task: HeartbeatTask) -> str:
        """Check source URIs of ingested docs via HTTP HEAD, re-ingest changed ones."""
        max_docs = task.config.get("max_docs", 20)

        store = self._get_pageindex_store()
        if not store:
            raise RuntimeError(
                "knowledge_refresh requires the trellion add-on (no PageIndex "
                "store in this container) — check surface routing"
            )

        try:
            docs = await store.list_docs(limit=max_docs)
        except Exception as e:
            raise RuntimeError(f"Knowledge refresh: failed to list docs: {e}") from e

        url_docs = [d for d in docs if d.get("source_uri", "").startswith("http")]
        if not url_docs:
            return "Knowledge refresh: no HTTP-sourced documents found."

        checked = 0
        changed = 0
        reingested = 0

        client = self._get_http_client()
        for doc in url_docs:
            uri = doc["source_uri"]
            old_hash = doc.get("hash", "")
            try:
                head = await client.head(uri, follow_redirects=True)
                etag = head.headers.get("etag", "")
                last_modified = head.headers.get("last-modified", "")
                new_sig = f"{etag}|{last_modified}|{head.headers.get('content-length', '')}"
                checked += 1

                if new_sig != old_hash and (etag or last_modified):
                    changed += 1
                    try:
                        ingest_client = self._get_http_client()
                        r = await ingest_client.post(
                            f"{self.gateway_url}/api/v1/rag/ingest",
                            json={"source": uri, "force": True},
                        )
                        # A slow ingest answers 202 with an operation handle; follow it
                        # so "re-ingested" means finished, not merely accepted.
                        r = await settle(ingest_client, r, self.gateway_url)
                        if r.status_code == 200:
                            reingested += 1
                    except Exception:
                        pass
            except Exception:
                checked += 1

        return (
            f"Knowledge refresh: checked {checked} sources, "
            f"{changed} changed, {reingested} re-ingestion jobs submitted."
        )

    async def _conversation_summarize(self, task: HeartbeatTask) -> str:
        """Find old conversations, summarize via LLM, store summary."""
        min_age_days = task.config.get("min_age_days", 30)
        min_messages = task.config.get("min_messages", 5)
        max_conversations = task.config.get("max_conversations", 10)

        cs = self._get_conversation_store()
        if not cs:
            return "Conversation summarize: ConversationStore not available."
        if not self.coordinator:
            return "Conversation summarize: coordinator not available (needed for LLM)."

        try:
            old_convos = await cs.get_old_conversations(
                older_than_days=min_age_days,
                min_messages=min_messages,
                limit=max_conversations,
            )
        except Exception as e:
            raise RuntimeError(f"Conversation summarize: failed to fetch old conversations: {e}") from e

        if not old_convos:
            return "Conversation summarize: no qualifying conversations found."

        processed = 0
        summaries_generated = 0

        for conv in old_convos:
            conv_id = conv["id"]
            try:
                msgs = await cs.get_recent_messages(
                    conv_id, limit=50, types=["user", "assistant"]
                )
                if len(msgs) < min_messages:
                    continue

                transcript = "\n".join(
                    f"[{m['type']}]: {m['content'][:500]}" for m in msgs
                )
                prompt = (
                    f"Summarize this conversation in 2-3 sentences. "
                    f"Focus on key topics discussed, decisions made, and outcomes.\n\n"
                    f"{transcript[:4000]}"
                )
                result = await self.coordinator.run(
                    message=prompt,
                    conversation_id=None,
                    channel="heartbeat",
                    sender_id="heartbeat_scheduler",
                    sender_name="Heartbeat",
                )
                summary = result.response
                # Store summary as metadata message in the conversation
                await cs.add_message(
                    conv_id, "metadata",
                    f"[Auto-summary] {summary}",
                    metadata={"type": "auto_summary", "generated_by": "heartbeat"},
                )
                summaries_generated += 1
            except Exception as e:
                logger.warning("heartbeat_summarize_error",
                               conversation_id=conv_id, error=str(e))
            processed += 1

        return (
            f"Conversation summarize: processed {processed} conversations, "
            f"generated {summaries_generated} summaries."
        )


    # Edge-tier staging: snapshot a full edge row before snipping it, so an
    # over-aggressive floor/dedup is restorable for the same retention window
    # as entity prunes. Edges are cheaper than entities (they re-extract on
    # re-ingest), but staging costs nothing and keeps the safety net uniform.

    # The runtime `CREATE TABLE IF NOT EXISTS` for graph_prune_staging /
    # graph_edge_prune_staging was removed: migration 014 has owned both tables
    # since they were introduced, so it was redundant belt-and-braces. It also
    # blocked the noo_app cutover — the app role has no CREATE on the schema,
    # and IF NOT EXISTS does NOT rescue that, because Postgres checks the
    # privilege before the existence shortcut.
    async def _stage_edge(self, conn, sa_text, edge_id: str, reason: str, run_id: str) -> None:
        """Snapshot one edge into graph_edge_prune_staging before deletion."""
        await conn.execute(
            sa_text("""
                INSERT INTO graph_edge_prune_staging
                    (edge_id, src_entity_id, rel_type, dst_entity_id,
                     confidence, evidence_json, reason, run_id)
                SELECT edge_id, src_entity_id, rel_type, dst_entity_id,
                       confidence, evidence_json, :reason, :run_id
                FROM edges WHERE edge_id = :edge_id
            """),
            {"edge_id": edge_id, "reason": reason, "run_id": run_id},
        )

    async def _prune_snapshot_entity(self, conn, sa_text, entity_row: dict) -> dict:
        """Build the restore payload for an entity: its row + edges + mentions.

        Embeddings/signals are intentionally excluded — they regenerate via
        rag_reindex / graph_signals after a restore.
        """
        eid = entity_row["entity_id"]
        edges_r = await conn.execute(
            sa_text("""
                SELECT edge_id::text, src_entity_id::text, rel_type,
                       dst_entity_id::text, evidence_json, created_at,
                       confidence, classified_at, classifier_model
                FROM edges
                WHERE src_entity_id = :eid OR dst_entity_id = :eid
            """),
            {"eid": eid},
        )
        edges = [
            {
                "edge_id": r[0], "src_entity_id": r[1], "rel_type": r[2],
                "dst_entity_id": r[3], "evidence_json": r[4],
                "created_at": r[5].isoformat() if r[5] else None,
                "confidence": r[6],
                "classified_at": r[7].isoformat() if r[7] else None,
                "classifier_model": r[8],
            }
            for r in edges_r.fetchall()
        ]
        mentions_r = await conn.execute(
            sa_text("""
                SELECT mention_id::text, entity_id::text, page_id::text,
                       span_json, quote
                FROM mentions WHERE entity_id = :eid
            """),
            {"eid": eid},
        )
        mentions = [
            {
                "mention_id": r[0], "entity_id": r[1], "page_id": r[2],
                "span_json": r[3], "quote": r[4],
            }
            for r in mentions_r.fetchall()
        ]
        return {"entity": entity_row, "edges": edges, "mentions": mentions}

    async def _prune_stage_row(
        self, conn, sa_text, entity_row: dict, reason: str,
        payload: dict, run_id: str,
    ) -> None:
        await conn.execute(
            sa_text("""
                INSERT INTO graph_prune_staging
                    (entity_id, canonical_name, entity_type, reason, payload, run_id)
                VALUES (:eid, :name, :etype, :reason, CAST(:payload AS jsonb), :run_id)
            """),
            {
                "eid": entity_row["entity_id"],
                "name": entity_row["canonical_name"],
                "etype": entity_row["type"],
                "reason": reason,
                "payload": json.dumps(payload, default=str),
                "run_id": run_id,
            },
        )

    async def _graph_prune(self, task: HeartbeatTask) -> str:
        """Graph hygiene with a staged (soft-delete) safety net.

        Entity tier — sweeps three categories: orphans (no edges, no mentions),
        junk names (too short / no letters), and near-duplicate names (merged).

        Edge tier (edge metabolism) — collapses exact-duplicate edges and snips
        age-gated low-confidence edges, leaving the ENTITIES intact and marking
        their embeddings stale so the graph re-forms around the tighter
        neighbourhood (paired with reinforcement in store.insert_edge).

        Every removal is first snapshotted (`graph_prune_staging` for entities,
        `graph_edge_prune_staging` for edges) and held for
        `staging_retention_days` (default 30); rows restore via
        POST /api/v1/graph/prune/restore, and expire on a later run.
        """
        from sqlalchemy import text as sa_text

        dry_run = task.config.get("dry_run", True)
        remove_orphans = task.config.get("remove_orphans", True)
        orphan_min_age_days = float(task.config.get("orphan_min_age_days", 7))
        # OFF unless asked (as the Rust action): trellion's entity-quality gate
        # (entity_cleanup) owns junk names; this rule knows no entity types.
        remove_junk = task.config.get("remove_junk", False)
        min_name_length = int(task.config.get("min_name_length", 2))
        merge_duplicates = task.config.get("merge_duplicates", True)
        similarity_threshold = task.config.get("similarity_threshold", 0.85)
        max_entities = task.config.get("max_entities", 200)
        max_delete = int(task.config.get("max_delete", 500))
        retention_days = float(task.config.get("staging_retention_days", 30))

        store = self._get_pageindex_store()
        if not store:
            raise RuntimeError(
                "graph_prune requires the trellion add-on (no PageIndex store "
                "in this container) — check surface routing"
            )

        run_id = str(uuid.uuid4())[:12]
        prefix = "(dry-run) " if dry_run else ""
        lines: List[str] = []
        budget = max_delete

        async with store._engine.connect() as conn:
            # Serialize prune runs. A manual /run firing during the scheduled
            # run (or two schedulers) would interleave the SELECT→DELETE windows
            # on the live entities/edges tables. Take a session advisory lock on
            # this connection; if another prune already holds it, skip this run
            # rather than race. Released explicitly at the end of the block; on
            # an unexpected error the lock leaks until the pooled connection is
            # recycled (pool_recycle=1h) — harmless for a weekly job, and a
            # skipped run is always safe.
            got_lock = (await conn.execute(
                sa_text("SELECT pg_try_advisory_lock(hashtext('noo:graph_prune')::bigint)")
            )).scalar()
            if not got_lock:
                return "Graph prune: another prune run is in progress — skipped."

            await conn.commit()

            # ── 0. Purge staged rows past the retention window ──────────
            if dry_run:
                r = await conn.execute(
                    sa_text("""
                        SELECT COUNT(*) FROM graph_prune_staging
                        WHERE staged_at < now() - (:d * interval '1 day')
                    """),
                    {"d": retention_days},
                )
                expired = r.scalar() or 0
                if expired:
                    lines.append(f"would purge {expired} staged rows past {retention_days:.0f}d retention")
            else:
                r = await conn.execute(
                    sa_text("""
                        DELETE FROM graph_prune_staging
                        WHERE staged_at < now() - (:d * interval '1 day')
                    """),
                    {"d": retention_days},
                )
                await conn.commit()
                if r.rowcount:
                    lines.append(f"purged {r.rowcount} staged rows past {retention_days:.0f}d retention")
                # Same retention sweep for edge staging (table may not exist
                # yet on first run — ignore if so).
                try:
                    re_ = await conn.execute(
                        sa_text("""
                            DELETE FROM graph_edge_prune_staging
                            WHERE staged_at < now() - (:d * interval '1 day')
                        """),
                        {"d": retention_days},
                    )
                    await conn.commit()
                    if re_.rowcount:
                        lines.append(f"purged {re_.rowcount} staged edges past {retention_days:.0f}d retention")
                except Exception:
                    await conn.rollback()

            # ── 1. Orphans: no edges, no mentions, older than min age ───
            orphans_done = 0
            if remove_orphans and budget > 0:
                r = await conn.execute(
                    sa_text("""
                        SELECT entity_id::text, canonical_name, type,
                               aliases_json, created_at
                        FROM entities e
                        WHERE NOT EXISTS (SELECT 1 FROM edges ed
                                          WHERE ed.src_entity_id = e.entity_id
                                             OR ed.dst_entity_id = e.entity_id)
                          AND NOT EXISTS (SELECT 1 FROM mentions m
                                          WHERE m.entity_id = e.entity_id)
                          AND e.created_at < now() - (:age * interval '1 day')
                        LIMIT :lim
                    """),
                    {"age": orphan_min_age_days, "lim": budget},
                )
                orphan_rows = r.fetchall()
                if dry_run:
                    orphans_done = len(orphan_rows)
                else:
                    for row in orphan_rows:
                        ent = {
                            "entity_id": row[0], "canonical_name": row[1],
                            "type": row[2], "aliases_json": row[3],
                            "created_at": row[4].isoformat() if row[4] else None,
                        }
                        # Orphan by definition — empty edges/mentions snapshot
                        payload = {"entity": ent, "edges": [], "mentions": []}
                        await self._prune_stage_row(conn, sa_text, ent, "orphan", payload, run_id)
                        await conn.execute(
                            sa_text("DELETE FROM entities WHERE entity_id = :eid"),
                            {"eid": ent["entity_id"]},
                        )
                        orphans_done += 1
                    await conn.commit()
                budget -= orphans_done
                if orphans_done:
                    lines.append(
                        f"{'would remove' if dry_run else 'staged+removed'} "
                        f"{orphans_done} orphans (no edges/mentions, >{orphan_min_age_days:.0f}d old)"
                    )

            # ── 2. Junk names: too short or containing no letters ───────
            junk_done = 0
            if remove_junk and budget > 0:
                r = await conn.execute(
                    sa_text("""
                        SELECT entity_id::text, canonical_name, type,
                               aliases_json, created_at
                        FROM entities
                        WHERE length(canonical_name) < :minlen
                           OR canonical_name !~ '[a-zA-Z]'
                        LIMIT :lim
                    """),
                    {"minlen": min_name_length, "lim": budget},
                )
                junk_rows = r.fetchall()
                junk_examples = [row[1] for row in junk_rows[:5]]
                if dry_run:
                    junk_done = len(junk_rows)
                else:
                    for row in junk_rows:
                        ent = {
                            "entity_id": row[0], "canonical_name": row[1],
                            "type": row[2], "aliases_json": row[3],
                            "created_at": row[4].isoformat() if row[4] else None,
                        }
                        payload = await self._prune_snapshot_entity(conn, sa_text, ent)
                        await self._prune_stage_row(conn, sa_text, ent, "junk_name", payload, run_id)
                        # Cascades edges + mentions (snapshotted above)
                        await conn.execute(
                            sa_text("DELETE FROM entities WHERE entity_id = :eid"),
                            {"eid": ent["entity_id"]},
                        )
                        junk_done += 1
                    await conn.commit()
                budget -= junk_done
                if junk_done:
                    lines.append(
                        f"{'would remove' if dry_run else 'staged+removed'} "
                        f"{junk_done} junk names (e.g. {', '.join(repr(x) for x in junk_examples)})"
                    )

            # ── 3. Near-duplicate names: merge, staging the loser ────────
            dup_pairs = 0
            merged = 0
            if merge_duplicates and budget > 0:
                r = await conn.execute(
                    sa_text("""
                        SELECT entity_id::text, canonical_name, type,
                               aliases_json, created_at
                        FROM entities
                        ORDER BY RANDOM()
                        LIMIT :lim
                    """),
                    {"lim": max_entities},
                )
                sample = [
                    {
                        "entity_id": row[0], "canonical_name": row[1],
                        "type": row[2], "aliases_json": row[3],
                        "created_at": row[4].isoformat() if row[4] else None,
                    }
                    for row in r.fetchall()
                ]
                by_type: Dict[str, List[dict]] = {}
                for ent in sample:
                    by_type.setdefault(ent["type"], []).append(ent)

                duplicates: List[tuple] = []
                for _etype, ents in by_type.items():
                    for i in range(len(ents)):
                        for j in range(i + 1, len(ents)):
                            ratio = difflib.SequenceMatcher(
                                None,
                                ents[i]["canonical_name"].lower(),
                                ents[j]["canonical_name"].lower(),
                            ).ratio()
                            if ratio >= similarity_threshold:
                                duplicates.append((ents[i], ents[j], ratio))
                dup_pairs = len(duplicates)

                if not dry_run:
                    merged_ids: set = set()
                    for keep, merge, _ratio in duplicates[:budget]:
                        if keep["entity_id"] in merged_ids or merge["entity_id"] in merged_ids:
                            continue
                        try:
                            payload = await self._prune_snapshot_entity(conn, sa_text, merge)
                            payload["merged_into"] = keep["entity_id"]
                            await self._prune_stage_row(
                                conn, sa_text, merge, "duplicate_merge", payload, run_id
                            )
                            await conn.commit()
                            await store.merge_entities(keep["entity_id"], merge["entity_id"])
                            merged_ids.add(merge["entity_id"])
                            merged += 1
                        except Exception as e:
                            logger.warning(
                                "graph_prune_merge_error",
                                keep=keep["canonical_name"],
                                merge=merge["canonical_name"],
                                error=str(e),
                            )
                if dup_pairs:
                    dup_ex = ", ".join(
                        f"'{d[1]['canonical_name']}' -> '{d[0]['canonical_name']}' ({d[2]:.0%})"
                        for d in duplicates[:3]
                    )
                    lines.append(
                        f"{'would merge' if dry_run else f'merged {merged} of'} "
                        f"{dup_pairs} duplicate pairs in a {len(sample)}-entity sample "
                        f"(e.g. {dup_ex})"
                    )

            # ── 4. EDGE TIER: dedup + age-gated low-confidence prune ─────
            # Surgical, entity-preserving cleanup (edge metabolism). We snip
            # weak/redundant EDGES and leave the entities standing, then mark
            # the affected entities' embeddings stale so they re-embed around
            # the tightened neighbourhood on the next graph-signals pass — the
            # graph restructures itself rather than being culled node-wise.
            prune_edges = task.config.get("prune_edges", True)
            edge_conf_floor = float(task.config.get("edge_confidence_floor", 0.15))
            edge_min_age_days = float(task.config.get("edge_min_age_days", 14))
            dedup_edges = task.config.get("dedup_edges", True)
            affected_entities: set = set()

            if (prune_edges or dedup_edges) and budget > 0:
                await conn.commit()

                # 4a. Exact-duplicate edges: keep the strongest (highest
                # confidence, newest as tiebreak), snip the rest. Endpoints
                # of removed dupes get re-embedded.
                dup_removed = 0
                if dedup_edges and budget > 0:
                    dupes = await conn.execute(
                        sa_text("""
                            SELECT edge_id::text, src_entity_id::text, dst_entity_id::text
                            FROM (
                                SELECT edge_id, src_entity_id, dst_entity_id,
                                       row_number() OVER (
                                         PARTITION BY src_entity_id, rel_type, dst_entity_id
                                         ORDER BY confidence DESC NULLS LAST, created_at DESC
                                       ) AS rn
                                FROM edges
                            ) ranked
                            WHERE rn > 1
                            LIMIT :budget
                        """),
                        {"budget": budget},
                    )
                    dupe_rows = dupes.fetchall()
                    if dupe_rows and not dry_run:
                        for er in dupe_rows:
                            await self._stage_edge(conn, sa_text, er[0], "duplicate", run_id)
                            affected_entities.update((er[1], er[2]))
                        await conn.execute(
                            sa_text("DELETE FROM edges WHERE edge_id = ANY(:ids)"),
                            {"ids": [er[0] for er in dupe_rows]},
                        )
                        await conn.commit()
                    dup_removed = len(dupe_rows)
                    budget -= dup_removed
                    if dup_removed:
                        lines.append(
                            f"{'would collapse' if dry_run else 'collapsed'} "
                            f"{dup_removed} duplicate edges"
                        )

                # 4b. Age-gated low-confidence prune: only CLASSIFIED edges
                # (classified_at IS NOT NULL — unclassified default to 1.0 and
                # haven't earned a real score yet) below the floor AND older
                # than the min age (so a fresh weak edge gets a chance to be
                # reinforced before it's cut).
                edge_removed = 0
                if prune_edges and budget > 0:
                    weak = await conn.execute(
                        sa_text("""
                            SELECT edge_id::text, src_entity_id::text,
                                   dst_entity_id::text, rel_type, confidence
                            FROM edges
                            WHERE classified_at IS NOT NULL
                              AND confidence < :floor
                              AND created_at < now() - (:age * interval '1 day')
                            ORDER BY confidence ASC
                            LIMIT :budget
                        """),
                        {"floor": edge_conf_floor, "age": edge_min_age_days, "budget": budget},
                    )
                    weak_rows = weak.fetchall()
                    if weak_rows and not dry_run:
                        for er in weak_rows:
                            await self._stage_edge(conn, sa_text, er[0], "low_confidence", run_id)
                            affected_entities.update((er[1], er[2]))
                        await conn.execute(
                            sa_text("DELETE FROM edges WHERE edge_id = ANY(:ids)"),
                            {"ids": [er[0] for er in weak_rows]},
                        )
                        await conn.commit()
                    edge_removed = len(weak_rows)
                    budget -= edge_removed
                    if edge_removed:
                        ex = ", ".join(
                            f"{er[3]}({er[4]:.2f})" for er in weak_rows[:3]
                        )
                        lines.append(
                            f"{'would snip' if dry_run else 'snipped'} {edge_removed} "
                            f"weak edges (<{edge_conf_floor}, >{edge_min_age_days:.0f}d; e.g. {ex})"
                        )

                # 4c. Restructure trigger: drop stale embeddings for endpoints
                # of removed edges so the next graph-signals/embed pass
                # recomputes them around the tightened neighbourhood.
                affected_entities.discard(None)
                if affected_entities and not dry_run:
                    await conn.execute(
                        sa_text("DELETE FROM entity_embeddings WHERE entity_id = ANY(:ids)"),
                        {"ids": list(affected_entities)},
                    )
                    await conn.commit()
                    lines.append(
                        f"marked {len(affected_entities)} entities for re-embedding "
                        f"(neighbourhood changed)"
                    )

            # Release the prune advisory lock (happy path).
            await conn.execute(
                sa_text("SELECT pg_advisory_unlock(hashtext('noo:graph_prune')::bigint)")
            )

        if not lines:
            return f"Graph prune: {prefix}nothing to do (run {run_id})."
        return f"Graph prune: {prefix}" + "; ".join(lines) + f". Run {run_id}; staged rows restorable for {retention_days:.0f}d."

    async def _graph_clustering(self, task: HeartbeatTask) -> str:
        """Run community detection on the knowledge graph."""
        min_cluster_size = task.config.get("min_cluster_size", 3)
        resolution = task.config.get("resolution", 1.0)

        try:
            from .deps import services
            rag = getattr(services, "pageindex_rag", None)
            if not rag:
                raise RuntimeError(
                    "graph_clustering requires the trellion add-on (no "
                    "PageIndexRAG in this container) — check surface routing"
                )
            clusterer = getattr(rag, "clusterer", None)
            if not clusterer:
                return "Graph clustering: graph clustering not available (module not installed)."

            result = await clusterer.run_clustering(
                min_cluster_size=min_cluster_size,
                resolution=resolution,
            )

            if "error" in result:
                return f"Graph clustering: {result['error']}"

            return (
                f"Graph clustering: generation {result.get('generation', '?')}, "
                f"{result.get('clusters', 0)} clusters, "
                f"{result.get('meta_clusters', 0)} meta-clusters, "
                f"{result.get('nodes', 0)} nodes, "
                f"{result.get('edges', 0)} edges, "
                f"{result.get('stale_removed', 0)} stale removed."
            )
        except Exception as e:
            logger.exception("graph_clustering_error")
            raise RuntimeError(f"Graph clustering failed: {e}") from e

    async def _graph_signals(self, task: HeartbeatTask) -> str:
        """Recompute PageRank, betweenness, motifs, spectral embeddings, and label propagation."""
        try:
            from .deps import services
            rag = getattr(services, "pageindex_rag", None)
            if not rag:
                raise RuntimeError(
                    "graph_signals requires the trellion add-on (no PageIndexRAG "
                    "in this container) — check surface routing"
                )

            from ..addon_roles import GRAPH_METRICS, provider
            computer = provider(GRAPH_METRICS)(rag.store)
            # Smart entry: perturbs only dirty subsections and noops on a
            # clean graph. Config full=true forces a full recompute.
            # Requires trellion >= incremental-signals (noo-trellion#37) —
            # deploy-sequenced, no fallback.
            result = await computer.compute_signals(
                force_full=bool(task.config.get("full", False))
            )

            mode = result.get("mode", "full")
            return (
                f"Graph signals ({mode}): "
                f"{result.get('signals_computed', 0)} entities, "
                f"{result.get('nodes', 0)} graph nodes."
            )
        except Exception as e:
            logger.exception("graph_signals_error")
            raise RuntimeError(f"Graph signals failed: {e}") from e

    # ====================================================================
    # System 1 rehearsal: thought experiment
    # ====================================================================

    async def _thought_experiment(self, task: HeartbeatTask) -> str:
        """Generate synthetic queries from the knowledge graph and rehearse retrieval.

        The agent poses questions to itself based on entity relationships,
        runs the full graph-guided retrieval pipeline, and captures successful
        traversals as System 1 intuition -- building experience without user input.
        """
        from datetime import datetime as _dt, timezone as _tz

        num_queries = task.config.get("num_queries", 5)
        min_entities = task.config.get("min_entities", 3)
        allowed_intents = task.config.get("intent_types", None)  # None = all
        skip_if_active = task.config.get("skip_if_active", True)
        # Days before an already-rehearsed entity pair may be picked again
        # (0 disables cross-run dedup).
        revisit_days = float(task.config.get("pair_revisit_days", 7))

        # Skip when the system is actively being used — organic traversals
        # are already being captured from real interactions
        if skip_if_active:
            try:
                from .deps import services
                coord = getattr(services, "coordinator", None)
                if coord and coord._sessions:
                    import time as _time
                    active = sum(
                        1 for s in coord._sessions.values()
                        if _time.time() - s.last_active < 300  # active in last 5 min
                    )
                    if active > 0:
                        return f"Skipped: {active} active session(s) — organic traversals being captured"
            except Exception:
                pass

        store = self._get_pageindex_store()
        if not store:
            raise RuntimeError(
                "thought_experiment requires the trellion add-on (no PageIndex "
                "store in this container) — check surface routing"
            )

        # 1. Sample random entities that have edges
        try:
            entities = await self._sample_graph_entities(store, count=num_queries * 3)
        except Exception as e:
            raise RuntimeError(f"Thought experiment: failed to sample entities: {e}") from e

        if len(entities) < min_entities:
            return (
                f"Thought experiment: not enough connected entities in graph "
                f"({len(entities)}, need {min_entities}). Ingest more documents first."
            )

        # 2. Generate synthetic queries from entity relationships
        try:
            queries = await self._generate_synthetic_queries(
                store, entities, num_queries, allowed_intents,
                revisit_ttl_s=int(revisit_days * 86400),
            )
        except Exception as e:
            raise RuntimeError(f"Thought experiment: failed to generate queries: {e}") from e

        if not queries:
            return (
                "Thought experiment: no new queries this run — all sampled "
                "entity pairs were rehearsed within the revisit window."
            )

        # 3. Get the recall memory manager (if available)
        video_mem = None
        try:
            from .deps import services
            video_mem = getattr(services, "recall_memory", None)
        except Exception:
            pass

        # 4. Run each query through the retrieval pipeline
        results: list[dict] = []
        for query_text, intent, seed_ids in queries:
            try:
                from ..addon_roles import GRAPH_RANKER, provider
                retriever = provider(GRAPH_RANKER)()
                if video_mem:
                    # Optional capability of a ranker, not part of the role.
                    set_video = getattr(retriever, "set_video_manager", None)
                    if set_video is not None:
                        set_video(video_mem)

                boosted = await retriever.get_graph_boosted_entities(
                    query=query_text, seed_entity_ids=seed_ids, store=store, top_k=10,
                )

                # If we got meaningful results, capture the traversal
                if boosted and len(boosted) >= 2:
                    # From the package, not traversal_archiver: trellion moved
                    # these dataclasses to video/types.py, and archiver only
                    # re-imports TraversalSnapshot — importing TraversalStep
                    # from it raised ImportError on every rehearsal query, so
                    # thought_experiment captured 0 traversals for days while
                    # recording status=success.
                    from ..memory.video import (
                        TraversalSnapshot,
                        TraversalStep,
                    )

                    steps = []
                    for i, entity in enumerate(boosted[:5]):
                        steps.append(TraversalStep(
                            entity_id=entity.entity_id,
                            entity_name=entity.name,
                            entity_type=entity.type,
                            edge_type=entity.path.split("-")[0].strip() if "-" in entity.path else "",
                            edge_confidence=min(entity.score, 1.0),
                            direction="seed" if i == 0 else "outgoing",
                        ))

                    snap = TraversalSnapshot(
                        snapshot_id=str(uuid.uuid4())[:12],
                        query=query_text,
                        query_intent=intent,
                        steps=steps,
                        outcome_score=0.7,  # Self-practice gets moderate score
                        timestamp=_dt.now(_tz.utc).isoformat(),
                        persona_id="",
                    )

                    captured = False
                    if video_mem:
                        try:
                            video_mem.capture_traversal(snap)
                            captured = True
                        except Exception:
                            logger.debug(
                                "thought_experiment.capture_failed",
                                exc_info=True,
                            )

                    results.append({
                        "query": query_text,
                        "intent": intent,
                        "entities_found": len(boosted),
                        "captured": captured,
                    })
                else:
                    results.append({
                        "query": query_text,
                        "intent": intent,
                        "entities_found": len(boosted) if boosted else 0,
                        "captured": False,
                    })
            except Exception as e:
                logger.debug(
                    "thought_experiment.query_failed",
                    query=query_text,
                    error=str(e),
                )
                results.append({"query": query_text, "error": str(e)})

        captured_count = sum(1 for r in results if r.get("captured"))
        total_entities = sum(r.get("entities_found", 0) for r in results)
        errors = sum(1 for r in results if "error" in r)

        # Every query failing is a broken task, not a quiet rehearsal —
        # recording success here hid the TraversalStep import breakage for
        # days.
        if results and errors == len(results):
            first = next(r["error"] for r in results if "error" in r)
            raise RuntimeError(
                f"thought_experiment: all {len(results)} queries failed "
                f"(first error: {first[:200]})"
            )

        summary = (
            f"Thought experiment complete: {len(queries)} queries run, "
            f"{captured_count} traversals captured, "
            f"{total_entities} entities discovered"
        )
        if errors:
            summary += f", {errors} errors"
        summary += "."

        # Append condensed per-query details
        detail_lines = []
        for r in results:
            q = r.get("query", "?")[:60]
            if "error" in r:
                detail_lines.append(f"  - [ERR] {q}: {r['error'][:80]}")
            else:
                marker = "captured" if r.get("captured") else "not captured"
                detail_lines.append(
                    f"  - [{r.get('intent', '?')}] {q} "
                    f"-> {r.get('entities_found', 0)} entities ({marker})"
                )

        return summary + "\n" + "\n".join(detail_lines)

    async def _sample_graph_entities(
        self,
        store: Any,
        count: int = 15,
    ) -> list[dict]:
        """Sample entities from the knowledge graph that have edge connections.

        Prefers well-connected entities (those with many edges) so that
        synthetic queries have meaningful graph structure to traverse.

        Returns a list of dicts with entity_id, canonical_name, type.
        """
        from sqlalchemy import text as sa_text

        async with store._engine.connect() as conn:
            result = await conn.execute(
                sa_text("""
                    SELECT e.entity_id, e.canonical_name, e.type, COUNT(ed.edge_id) AS edge_count
                    FROM entities e
                    JOIN edges ed
                      ON e.entity_id = ed.src_entity_id
                      OR e.entity_id = ed.dst_entity_id
                    GROUP BY e.entity_id, e.canonical_name, e.type
                    HAVING COUNT(ed.edge_id) > 0
                    ORDER BY RANDOM()
                    LIMIT :limit
                """),
                {"limit": count},
            )
            rows = result.fetchall()

        return [
            {
                "entity_id": str(r[0]),
                "canonical_name": r[1],
                "type": r[2],
                "edge_count": r[3],
            }
            for r in rows
        ]

    async def _generate_synthetic_queries(
        self,
        store: Any,
        entities: list[dict],
        num_queries: int = 5,
        allowed_intents: list[str] | None = None,
        revisit_ttl_s: int = 0,
    ) -> list[tuple[str, str, list[str]]]:
        """Generate synthetic natural-language queries from entity relationships.

        For entity pairs connected by edges, generates queries that exercise
        different retrieval intents based on the edge type.

        Args:
            store: PageIndexStore instance.
            entities: List of entity dicts from _sample_graph_entities.
            num_queries: Maximum number of queries to generate.
            allowed_intents: If provided, only generate queries with these intents.
            revisit_ttl_s: If > 0, skip entity pairs already rehearsed within
                this window (tracked in Redis) so runs explore new territory
                instead of repeating themselves.

        Returns:
            List of (query_text, intent, [seed_entity_ids]) tuples.
        """
        import random
        from sqlalchemy import text as sa_text

        entity_ids = [e["entity_id"] for e in entities]
        entity_map = {e["entity_id"]: e for e in entities}

        # Fetch edges between the sampled entities
        async with store._engine.connect() as conn:
            result = await conn.execute(
                sa_text("""
                    SELECT edge_id, src_entity_id, rel_type, dst_entity_id
                    FROM edges
                    WHERE src_entity_id = ANY(:ids) OR dst_entity_id = ANY(:ids)
                    LIMIT 200
                """),
                {"ids": entity_ids},
            )
            edges = result.fetchall()

        if not edges:
            return []

        # Resolve names for edge endpoints that fell outside the sampled set —
        # without this the fallback template renders UUID prefixes
        # ("How does a0e92dfb relate to w3?").
        unknown_ids = {
            str(eid)
            for edge in edges
            for eid in (edge[1], edge[3])
            if str(eid) not in entity_map
        }
        if unknown_ids:
            try:
                async with store._engine.connect() as conn:
                    result = await conn.execute(
                        sa_text("""
                            SELECT entity_id, canonical_name, type
                            FROM entities
                            WHERE entity_id = ANY(:ids)
                        """),
                        {"ids": list(unknown_ids)},
                    )
                    for r in result.fetchall():
                        entity_map[str(r[0])] = {
                            "entity_id": str(r[0]),
                            "canonical_name": r[1],
                            "type": r[2],
                            "edge_count": 0,
                        }
            except Exception:
                logger.debug("thought_experiment.endpoint_resolve_failed", exc_info=True)

        # Edge-type to query template and intent mapping
        _EDGE_QUERY_TEMPLATES: dict[str, list[tuple[str, str]]] = {
            "CAUSES": [
                ("What causes {entity_name}?", "causal"),
                ("Why does {entity_name} happen?", "causal"),
            ],
            "CAUSED_BY": [
                ("What is {entity_name} caused by?", "causal"),
                ("What are the reasons for {entity_name}?", "causal"),
            ],
            "PART_OF": [
                ("What are the components of {entity_name}?", "definitional"),
                ("What is {entity_name} part of?", "definitional"),
            ],
            "CONTAINS": [
                ("What does {entity_name} contain?", "definitional"),
                ("What are the parts of {entity_name}?", "definitional"),
            ],
            "DEPENDS_ON": [
                ("What does {entity_name} depend on?", "procedural"),
                ("What are the dependencies of {entity_name}?", "procedural"),
            ],
            "USED_IN": [
                ("Where is {entity_name} used?", "procedural"),
                ("What uses {entity_name}?", "procedural"),
            ],
            "IMPLEMENTS": [
                ("How is {entity_name} implemented?", "procedural"),
                ("What implements {entity_name}?", "procedural"),
            ],
            "SIMILAR_TO": [
                ("What is similar to {entity_name}?", "comparative"),
                ("Compare {entity_name} with its alternatives", "comparative"),
            ],
            "CONTRASTS_WITH": [
                ("How does {entity_name} differ from its counterparts?", "comparative"),
            ],
            "INSTANCE_OF": [
                ("What is {entity_name}?", "definitional"),
                ("Define {entity_name}", "definitional"),
            ],
            "EXTENDS": [
                ("What does {entity_name} extend?", "comparative"),
            ],
            "PRODUCES": [
                ("What does {entity_name} produce?", "causal"),
            ],
            "PRECEDES": [
                ("What comes after {entity_name}?", "procedural"),
            ],
            "REFERENCES": [
                ("What references {entity_name}?", "exploratory"),
            ],
        }

        # Default template for unknown edge types
        _DEFAULT_TEMPLATES: list[tuple[str, str]] = [
            ("How does {entity_a} relate to {entity_b}?", "exploratory"),
            ("What is the relationship between {entity_a} and {entity_b}?", "exploratory"),
        ]

        queries: list[tuple[str, str, list[str]]] = []
        seen_pairs: set[tuple[str, str]] = set()
        rds = self._get_redis() if revisit_ttl_s > 0 else None

        # Shuffle edges for variety across runs
        edge_list = list(edges)
        random.shuffle(edge_list)

        for edge in edge_list:
            if len(queries) >= num_queries:
                break

            src_id = str(edge[1])
            rel_type = edge[2]
            dst_id = str(edge[3])

            # Skip if we already generated for this pair
            pair_key = (src_id, dst_id)
            if pair_key in seen_pairs or (dst_id, src_id) in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            # Cross-run dedup: SET NX marks the pair as rehearsed; if the key
            # already exists this pair was covered within the revisit window,
            # so move on to unexplored territory.
            if rds is not None:
                a, b = sorted((src_id, dst_id))
                try:
                    fresh = await rds.set(
                        f"noo:thought_experiment:pair:{a}:{b}",
                        "1",
                        nx=True,
                        ex=revisit_ttl_s,
                    )
                    if not fresh:
                        continue
                except Exception:
                    rds = None  # Redis flaked mid-run — continue without dedup

            src = entity_map.get(src_id)
            dst = entity_map.get(dst_id)

            if rel_type in _EDGE_QUERY_TEMPLATES:
                templates = _EDGE_QUERY_TEMPLATES[rel_type]
                template_text, intent = random.choice(templates)

                # Filter by allowed intents
                if allowed_intents and intent not in allowed_intents:
                    continue

                # Use the source entity for single-entity templates
                target = src or dst
                if target:
                    query_text = template_text.format(
                        entity_name=target["canonical_name"],
                    )
                    seed_ids = [target["entity_id"]]
                    # Add the other entity as a second seed if known
                    other = dst if target == src else src
                    if other:
                        seed_ids.append(other["entity_id"])
                    queries.append((query_text, intent, seed_ids))
            else:
                # Fallback: relation-based query
                template_text, intent = random.choice(_DEFAULT_TEMPLATES)
                if allowed_intents and intent not in allowed_intents:
                    continue

                name_a = src["canonical_name"] if src else src_id[:8]
                name_b = dst["canonical_name"] if dst else dst_id[:8]
                query_text = template_text.format(entity_a=name_a, entity_b=name_b)
                seed_ids = [eid for eid in [src_id, dst_id] if eid in entity_map]
                if seed_ids:
                    queries.append((query_text, intent, seed_ids))

        return queries

    async def _memory_relevance_audit(self, task: HeartbeatTask) -> str:
        """Run test queries against RAG + conversation memory, score retrieval quality."""
        test_queries = task.config.get("test_queries", [
            "What is the current project status?",
            "How does the system handle errors?",
            "What are the recent changes?",
        ])
        min_expected_score = task.config.get("min_expected_score", 0.3)

        rag_scores: List[float] = []
        mem_scores: List[float] = []
        warnings: List[str] = []

        client = self._get_http_client()
        for query in test_queries:
            # Test RAG
            try:
                r = await client.post(
                    f"{self.gateway_url}/api/v1/rag/query",
                    json={"query": query, "top_k": 3},
                )
                if r.status_code == 200:
                    results = r.json().get("results", [])
                    top = results[0].get("score", 0.0) if results else 0.0
                    rag_scores.append(top)
                    if top < min_expected_score:
                        warnings.append(f"RAG '{query[:30]}...' below threshold ({top:.2f})")
            except Exception:
                rag_scores.append(0.0)

            # Test conversation memory
            try:
                r = await client.get(
                    f"{self.gateway_url}/api/memory/search",
                    params={"query": query, "top_k": "3"},
                )
                if r.status_code == 200:
                    ctx = r.json().get("context", "")
                    score = min(1.0, len(ctx) / 500.0) if ctx else 0.0
                    mem_scores.append(score)
            except Exception:
                mem_scores.append(0.0)

        rag_avg = sum(rag_scores) / len(rag_scores) if rag_scores else 0.0
        mem_avg = sum(mem_scores) / len(mem_scores) if mem_scores else 0.0
        warn_str = f" Warnings: {'; '.join(warnings)}" if warnings else ""

        return (
            f"Memory relevance audit: {len(test_queries)} queries — "
            f"RAG avg {rag_avg:.2f}, memory avg {mem_avg:.2f}.{warn_str}"
        )

    # ====================================================================
    # Category 2: Proactive Awareness
    # ====================================================================

    async def _news_scan(self, task: HeartbeatTask) -> str:
        """Fetch RSS/Atom feeds, filter by keywords, optionally ingest into KB."""
        feeds = task.config.get("feeds", [])
        keywords = [k.lower() for k in task.config.get("keywords", [])]
        max_entries = task.config.get("max_entries", 10)
        ingest = task.config.get("ingest", False)
        summarize = task.config.get("summarize", True)

        if not feeds:
            return "News scan: no feeds configured."

        all_entries: List[Dict[str, str]] = []

        client = self._get_http_client()
        for feed_url in feeds:
            try:
                r = await client.get(feed_url, follow_redirects=True)
                if r.status_code != 200:
                    continue

                entries = self._parse_feed(r.text)
                all_entries.extend(entries)
            except Exception as e:
                logger.warning("news_scan_feed_error", url=feed_url, error=str(e))

        # Filter by keywords if configured
        if keywords:
            matched = [
                e for e in all_entries
                if any(k in e.get("title", "").lower() or k in e.get("summary", "").lower()
                       for k in keywords)
            ]
        else:
            matched = all_entries

        matched = matched[:max_entries]

        # Optionally ingest into KB
        ingested = 0
        if ingest and matched:
            client = self._get_http_client()
            for entry in matched:
                link = entry.get("link", "")
                if link:
                    try:
                        r = await client.post(
                            f"{self.gateway_url}/api/v1/rag/ingest",
                            json={"source": link},
                        )
                        r = await settle(client, r, self.gateway_url)
                        if r.status_code == 200:
                            ingested += 1
                    except Exception:
                        pass

        # Optionally summarize
        summary_text = ""
        if summarize and matched and self.coordinator:
            try:
                titles = "\n".join(f"- {e.get('title', 'Untitled')}" for e in matched[:5])
                result = await self.coordinator.run(
                    message=f"Briefly summarize these news headlines:\n{titles}",
                    conversation_id=None,
                    channel="heartbeat",
                    sender_id="heartbeat_scheduler",
                    sender_name="Heartbeat",
                )
                summary_text = f" Summary: {result.response[:300]}"
            except Exception:
                pass

        titles_preview = "; ".join(f"'{e.get('title', '')[:50]}'" for e in matched[:3])
        ingest_note = f", {ingested} ingested" if ingest else ""
        return (
            f"News scan: checked {len(feeds)} feeds, {len(all_entries)} total entries "
            f"({len(matched)} matched){ingest_note}: {titles_preview}{summary_text}"
        )

    @staticmethod
    def _parse_feed(xml_text: str) -> List[Dict[str, str]]:
        """Parse RSS/Atom feed XML. Uses feedparser if available, else stdlib."""
        if FEEDPARSER_AVAILABLE:
            feed = feedparser.parse(xml_text)
            return [
                {
                    "title": e.get("title", ""),
                    "link": e.get("link", ""),
                    "summary": e.get("summary", "")[:300],
                }
                for e in feed.get("entries", [])
            ]

        # Fallback: stdlib XML parsing for basic RSS/Atom
        entries: List[Dict[str, str]] = []
        try:
            root = ElementTree.fromstring(xml_text)
            # RSS 2.0
            for item in root.iter("item"):
                entries.append({
                    "title": (item.findtext("title") or "").strip(),
                    "link": (item.findtext("link") or "").strip(),
                    "summary": (item.findtext("description") or "")[:300].strip(),
                })
            # Atom
            ns = {"atom": "http://www.w3.org/2005/Atom"}
            for entry in root.iter("{http://www.w3.org/2005/Atom}entry"):
                link_el = entry.find("atom:link", ns)
                entries.append({
                    "title": (entry.findtext("{http://www.w3.org/2005/Atom}title") or "").strip(),
                    "link": link_el.get("href", "") if link_el is not None else "",
                    "summary": (entry.findtext("{http://www.w3.org/2005/Atom}summary") or "")[:300].strip(),
                })
        except ElementTree.ParseError:
            pass
        return entries

    async def _goal_review(self, task: HeartbeatTask) -> str:
        """Review persistent goals stored in task config using coordinator LLM."""
        goals = task.config.get("goals", [])
        review_prompt = task.config.get("review_prompt", "")

        if not goals:
            return "Goal review: no goals configured."
        if not self.coordinator:
            return "Goal review: coordinator not available (needed for LLM)."

        goals_text = "\n".join(
            f"- **{g.get('name', 'Unnamed')}**: {g.get('description', '')} "
            f"(target: {g.get('target_date', 'none')}, status: {g.get('status', 'unknown')})"
            for g in goals
        )

        prompt = review_prompt or (
            "Review the following goals. For each, assess progress based on "
            "what you know from the knowledge base and recent conversations. "
            "Use the tools noo_rag_query and noo_memory_search if helpful.\n\n"
        )
        prompt += f"\n{goals_text}"

        try:
            result = await self.coordinator.run(
                message=prompt,
                conversation_id=None,
                channel="heartbeat",
                sender_id="heartbeat_scheduler",
                sender_name="Heartbeat",
            )
            return f"Goal review:\n{result.response}"
        except Exception as e:
            raise RuntimeError(f"Goal review: error running coordinator: {e}") from e

    async def _channel_keepalive(self, task: HeartbeatTask) -> str:
        """Ping each configured channel to verify connections are alive."""
        channels = task.config.get("channels", [])
        send_test = task.config.get("send_test", False)

        if not channels:
            return "Channel keepalive: no channels configured."

        results: List[str] = []

        try:
            from ..channels.manager import ChannelManager  # noqa: F401
            from .deps import services
            cm = getattr(services, "channel_manager", None)
        except Exception:
            cm = None

        if not cm:
            return "Channel keepalive: ChannelManager not available."

        for ch_name in channels:
            adapter = cm.get_adapter(ch_name)
            if adapter is None:
                results.append(f"{ch_name} NOT_REGISTERED")
                continue

            # Check adapter status
            status = "OK"
            try:
                if hasattr(adapter, "is_connected"):
                    if not adapter.is_connected():
                        status = "DISCONNECTED"
                elif hasattr(adapter, "health_check"):
                    ok = await adapter.health_check()
                    if not ok:
                        status = "DEGRADED"
            except Exception:
                status = "ERROR"

            if send_test and status == "OK":
                try:
                    test_recipient = task.config.get(f"{ch_name}_test_recipient")
                    if test_recipient:
                        await cm.dispatch(
                            channel=ch_name,
                            recipient=test_recipient,
                            message="[Heartbeat keepalive test]",
                        )
                        status = "OK (test sent)"
                except Exception:
                    status = "OK (test failed)"

            results.append(f"{ch_name} {status}")

        return f"Channel keepalive: {', '.join(results)}"

    # ====================================================================
    # Category 3: Operational Resilience
    # ====================================================================

    async def _model_cache_warm(self, task: HeartbeatTask) -> str:
        """Pre-pull models onto nodes before peak hours."""
        models = task.config.get("models", [])
        if not models:
            return "Model cache warm: no models configured."

        # Check what's already cached
        cached_set: set = set()
        client = self._get_http_client()
        try:
            r = await client.get(f"{self.gateway_url}/api/models/cached")
            if r.status_code == 200:
                cached_list = r.json().get("models", [])
                cached_set = {
                    (m.get("model"), m.get("node_id")) for m in cached_list
                }
        except Exception:
            pass

        already_cached = 0
        pulling = 0

        client = self._get_http_client()
        for spec in models:
            model_name = spec.get("model", "")
            node_id = spec.get("node_id", "")
            if (model_name, node_id) in cached_set:
                already_cached += 1
                continue

            try:
                r = await client.post(
                    f"{self.gateway_url}/api/models/pull",
                    json={
                        "model": model_name,
                        "backend": spec.get("backend", "ollama"),
                        "node_id": node_id,
                    },
                )
                if r.status_code == 200:
                    pulling += 1
                    logger.info("heartbeat_model_pull",
                                model=model_name, node=node_id)
            except Exception as e:
                logger.warning("heartbeat_model_pull_error",
                               model=model_name, error=str(e))

        return (
            f"Model cache warm: {already_cached}/{len(models)} already cached, "
            f"pulling {pulling} model(s)."
        )

    async def _backup_knowledge(self, task: HeartbeatTask) -> str:
        """Export docs/entities/edges to JSONL snapshot files."""
        output_dir = task.config.get("output_dir", "/data/backups")
        include_graph = task.config.get("include_graph", True)
        include_conversations = task.config.get("include_conversations", False)

        # Security: validate output_dir
        out_path = Path(output_dir).resolve()
        allowed_prefixes = (Path("/data"), Path("/tmp"))
        if not any(str(out_path).startswith(str(p)) for p in allowed_prefixes):
            return f"Backup knowledge: output_dir must be under /data/ or /tmp/ (got {out_path})"

        store = self._get_pageindex_store()
        if not store:
            return "Backup knowledge: PageIndex store not available."

        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        backup_dir = out_path / date_str
        backup_dir.mkdir(parents=True, exist_ok=True)

        doc_count = entity_count = edge_count = conv_count = 0

        # Export documents
        try:
            docs = await store.export_all_docs()
            doc_file = backup_dir / "docs.jsonl"
            with open(doc_file, "w") as f:
                for d in docs:
                    f.write(json.dumps(d) + "\n")
            doc_count = len(docs)
        except Exception as e:
            logger.warning("backup_docs_error", error=str(e))

        # Export graph
        if include_graph:
            try:
                entities = await store.export_all_entities()
                with open(backup_dir / "entities.jsonl", "w") as f:
                    for e in entities:
                        f.write(json.dumps(e) + "\n")
                entity_count = len(entities)
            except Exception as e:
                logger.warning("backup_entities_error", error=str(e))

            try:
                edges = await store.export_all_edges()
                with open(backup_dir / "edges.jsonl", "w") as f:
                    for e in edges:
                        f.write(json.dumps(e) + "\n")
                edge_count = len(edges)
            except Exception as e:
                logger.warning("backup_edges_error", error=str(e))

        # Export conversations
        if include_conversations:
            cs = self._get_conversation_store()
            if cs:
                try:
                    result = await cs.list_conversations(limit=10000)
                    convos = result.get("conversations", [])
                    with open(backup_dir / "conversations.jsonl", "w") as f:
                        for c in convos:
                            f.write(json.dumps(c) + "\n")
                    conv_count = len(convos)
                except Exception as e:
                    logger.warning("backup_conversations_error", error=str(e))

        parts = [f"{doc_count} docs"]
        if include_graph:
            parts.extend([f"{entity_count} entities", f"{edge_count} edges"])
        if include_conversations:
            parts.append(f"{conv_count} conversations")

        return f"Backup knowledge: exported {', '.join(parts)} to {backup_dir}/"

    async def _disk_cleanup(self, task: HeartbeatTask) -> str:
        """Detection-only scan — reports stale items without performing any cleanup.

        The one implemented prune (heartbeat_run_records) is the gateway's
        ``heartbeat_retention`` task, run on demand via
        ``POST /api/heartbeat/tasks/{task_id}/run``.  This heartbeat action
        only counts/measures what *would* be cleaned.
        """
        targets = task.config.get("targets", list(self.CLEANUP_TARGETS))

        invalid = set(targets) - self.CLEANUP_TARGETS
        if invalid:
            return f"Disk cleanup: invalid targets: {invalid}. Allowed: {self.CLEANUP_TARGETS}"

        if not targets:
            return "Disk cleanup: no targets configured."

        report: List[str] = []

        for target in targets:
            if target == "tmp_noo_files":
                report.append(await self._detect_tmp_pai())
            elif target == "heartbeat_run_records":
                report.append(await self._detect_heartbeat_records())
            elif target == "docker_dangling_images":
                report.append(await self._detect_docker_images())
            elif target == "container_logs":
                report.append(await self._detect_container_logs())

        return f"Disk cleanup (report-only): {'; '.join(report)}"

    # -- Detection helpers (read-only, no side effects) ---------------------

    async def _detect_tmp_pai(self) -> str:
        """Count /tmp/noo-* files older than 24 h and estimate total size."""
        import time as _time
        cutoff = _time.time() - 86400
        tmp = Path("/tmp")
        found = 0
        total_bytes = 0
        for p in tmp.glob("noo-*"):
            try:
                st = p.stat()
                if st.st_mtime < cutoff:
                    found += 1
                    if p.is_file():
                        total_bytes += st.st_size
                    elif p.is_dir():
                        for child in p.rglob("*"):
                            try:
                                total_bytes += child.stat().st_size
                            except Exception:
                                pass
            except Exception:
                pass
        size_str = _format_bytes(total_bytes)
        return f"tmp_noo_files: {found} stale (~{size_str})"

    async def _detect_heartbeat_records(self) -> str:
        """Count heartbeat run records older than 90 days."""
        store = self._get_heartbeat_store()
        if not store:
            return "heartbeat_run_records: store not available"

        try:
            if hasattr(store, "_engine"):
                from sqlalchemy import func, select, text
                from ..db.models import PaiHeartbeatRun
                _runs = PaiHeartbeatRun.__table__
                with store._engine.connect() as conn:
                    count = conn.execute(
                        select(func.count())
                        .select_from(_runs)
                        .where(_runs.c.started_at < func.now() - text("INTERVAL '90 days'"))
                    ).scalar() or 0
                    return f"heartbeat_run_records: {count} old records"
        except Exception as e:
            raise RuntimeError(f"heartbeat_run_records cleanup failed: {e}") from e
        return "heartbeat_run_records: store not available"

    # The two node-agent detectors are the GATEWAY's.
    # disk_cleanup is RUST_NATIVE (gateway-rust heartbeat_actions.rs), so
    # neither the cron loop nor "Run now" routes it here; the gateway asks
    # each node agent for a dry-run of /cleanup/{images,logs} with its own
    # controller leaf. This process presents services/worker, a SERVICE leaf
    # that every node agent's ControllerOnly gate refuses (403), and these
    # bodies used to send no bearer at all and swallow every error — a
    # "0 dangling" report that measured nothing. If a path ever lands here
    # again it fails the run, naming where the scan lives.
    _NODE_SCAN_ELSEWHERE = (
        "{target}: not scanned by the worker — node agents admit only the "
        "controller to /cleanup/*, and this process presents its own service "
        "leaf. disk_cleanup runs in the gateway "
        "(heartbeat_actions.rs); trigger it there: "
        "POST /api/heartbeat/tasks/<task_id>/run"
    )

    async def _detect_docker_images(self) -> str:
        """Refuse: the dangling-image scan is the gateway's (see above)."""
        msg = self._NODE_SCAN_ELSEWHERE.format(target="docker_dangling_images")
        logger.error("heartbeat_node_scan_refused", target="docker_dangling_images", reason=msg)
        raise RuntimeError(msg)

    async def _detect_container_logs(self) -> str:
        """Refuse: the container-log scan is the gateway's (see above)."""
        msg = self._NODE_SCAN_ELSEWHERE.format(target="container_logs")
        logger.error("heartbeat_node_scan_refused", target="container_logs", reason=msg)
        raise RuntimeError(msg)

    def _get_heartbeat_store(self) -> Any:
        """Get the heartbeat store from the global scheduler."""
        sched = get_heartbeat_scheduler()
        return sched.store if sched else None

    async def _cost_report(self, task: HeartbeatTask) -> str:
        """Report GPU hours, cloud API usage, cache efficiency."""
        period_days = task.config.get("period_days", 7)
        gpu_cost_per_hour = task.config.get("gpu_cost_per_hour", 0.0)

        sections: List[str] = []

        # Cache stats
        client = self._get_http_client()
        try:
            r = await client.get(f"{self.gateway_url}/api/cache/stats")
            if r.status_code == 200 and r.json().get("enabled", True) is not None:
                cache = r.json()
                hits = cache.get("hits", 0)
                misses = cache.get("misses", 0)
                total = hits + misses
                rate = round((hits / total) * 100, 1) if total > 0 else 0
                sections.append(f"Cache: {rate}% hit rate ({total} requests)")
        except Exception:
            pass

        # Cluster node uptime
        try:
            r = await client.get(f"{self.gateway_url}/api/cluster/nodes")
            if r.status_code == 200:
                nodes = r.json()
                if isinstance(nodes, dict):
                    nodes = nodes.get("nodes", [])
                online = sum(1 for n in nodes if n.get("status") == "online")
                gpu_hours = online * 24 * period_days
                cost = gpu_hours * gpu_cost_per_hour
                cost_str = f"${cost:.2f}" if gpu_cost_per_hour > 0 else "$0 (self-hosted)"
                sections.append(f"Local GPU: ~{gpu_hours}h ({cost_str})")
        except Exception:
            pass

        # Conversation token stats
        cs = self._get_conversation_store()
        if cs:
            try:
                stats = await cs.get_conversation_stats(days=period_days)
                tokens_in = stats.get("total_tokens_in", 0)
                tokens_out = stats.get("total_tokens_out", 0)
                total_tokens = tokens_in + tokens_out
                # Cloud cost estimate (configurable per-million rates)
                input_rate = task.config.get("cloud_input_cost_per_m", 3)
                output_rate = task.config.get("cloud_output_cost_per_m", 15)
                est_cost = (tokens_in * input_rate + tokens_out * output_rate) / 1_000_000
                sections.append(
                    f"Cloud API: ~${est_cost:.2f} ({total_tokens:,} tokens)"
                )
            except Exception:
                pass

        if not sections:
            return "Cost report: unable to collect metrics."

        return f"Cost report ({period_days}d): {', '.join(sections)}"

    # ====================================================================
    # Category 4: Self-Assessment
    # ====================================================================

    async def _self_benchmark(self, task: HeartbeatTask) -> str:
        """Run fixed test prompts through coordinator, measure latency + quality."""
        test_prompts = task.config.get("test_prompts", [
            {"prompt": "What is 2+2?", "expected_keywords": ["4"], "category": "math"},
            {"prompt": "Summarize: The sky is blue because of Rayleigh scattering.",
             "expected_keywords": ["scattering", "blue"], "category": "comprehension"},
        ])
        timeout = task.config.get("timeout", 30)

        if not self.coordinator:
            return "Self benchmark: coordinator not available."

        results: List[Dict[str, Any]] = []
        for spec in test_prompts:
            prompt = spec.get("prompt", "")
            expected = [k.lower() for k in spec.get("expected_keywords", [])]

            start = time.monotonic()
            try:
                result = await asyncio.wait_for(
                    self.coordinator.run(
                        message=prompt,
                        conversation_id=None,
                        channel="heartbeat",
                        sender_id="heartbeat_scheduler",
                        sender_name="Heartbeat",
                    ),
                    timeout=timeout,
                )
                latency = time.monotonic() - start
                response = result.response.lower()
                matched = sum(1 for k in expected if k in response)
                quality = matched / len(expected) if expected else 1.0
                results.append({"latency": latency, "quality": quality})
            except asyncio.TimeoutError:
                results.append({"latency": timeout, "quality": 0.0})
            except Exception:
                results.append({"latency": time.monotonic() - start, "quality": 0.0})

        if not results:
            return "Self benchmark: no results."

        avg_latency = sum(r["latency"] for r in results) / len(results)
        avg_quality = sum(r["quality"] for r in results) / len(results)
        quality_pass = sum(1 for r in results if r["quality"] >= 0.5)

        return (
            f"Self benchmark: {len(results)} prompts — "
            f"avg {avg_latency:.1f}s latency, "
            f"quality {quality_pass}/{len(results)} pass. "
            f"Avg quality score: {avg_quality:.0%}"
        )

    async def _security_audit(self, task: HeartbeatTask) -> str:
        """Check rate-limit violations, auth failures, anomalous tool calls."""
        period_hours = task.config.get("period_hours", 24)
        alert_threshold = task.config.get("alert_threshold", 5)

        findings: Dict[str, int] = {
            "rate_limit_violations": 0,
            "auth_failures": 0,
            "high_risk_tool_calls": 0,
            "path_traversal_attempts": 0,
        }

        # Check rate limiter state (in-memory)
        try:
            from .security import get_security_manager
            sm = get_security_manager()
            if sm and hasattr(sm, "get_violation_stats"):
                stats = sm.get_violation_stats(period_hours=period_hours)
                findings["rate_limit_violations"] = stats.get("violations", 0)
                findings["path_traversal_attempts"] = stats.get("path_traversal", 0)
        except Exception:
            pass

        # Check exec approval stats
        try:
            from .exec_approval import get_approval_manager
            am = get_approval_manager()
            if am and hasattr(am, "get_stats"):
                stats = am.get_stats()
                findings["high_risk_tool_calls"] = stats.get("denied", 0)
        except Exception:
            pass

        # Try Loki if available
        try:
            loki_url = task.config.get("loki_url") or os.environ.get(
                "NOO_LOKI_URL", ""
            )
            if not loki_url:
                # Fall back to gateway host with default Loki port
                from urllib.parse import urlparse
                parsed = urlparse(self.gateway_url)
                loki_url = f"{parsed.scheme}://{parsed.hostname}:3100"
            client = self._get_http_client()
            r = await client.get(
                f"{loki_url}/loki/api/v1/query_range",
                params={
                    "query": '{job="noo-gateway"} |= "401"',
                    "limit": "100",
                    "start": str(int(time.time()) - period_hours * 3600),
                },
            )
            if r.status_code == 200:
                data = r.json().get("data", {}).get("result", [])
                auth_count = sum(len(s.get("values", [])) for s in data)
                findings["auth_failures"] = auth_count
        except Exception:
            pass

        total = sum(findings.values())
        risk_level = "LOW" if total < alert_threshold else ("MEDIUM" if total < alert_threshold * 3 else "HIGH")

        detail = ", ".join(f"{k}: {v}" for k, v in findings.items())
        return f"Security audit ({period_hours}h): {detail}. Overall risk: {risk_level}"

    async def _cert_rotation_check(self, task: HeartbeatTask) -> str:
        """Check PKI directory for certificates expiring soon."""
        warn_days = task.config.get("warn_days", 30)
        pki_dir = task.config.get("pki_dir", "")

        if not pki_dir:
            import os
            pki_dir = os.getenv("NOO_PKI_DIR", "")
        if not pki_dir:
            return "Cert rotation check: NOO_PKI_DIR not configured."

        try:
            from ..pki.ca import ClusterCA
            ca = ClusterCA(pki_dir=pki_dir)
            expiring = ca.get_expiring_certs(warn_days=warn_days)
        except ImportError:
            return "Cert rotation check: PKI module not available."
        except Exception as e:
            raise RuntimeError(f"Cert rotation check: error scanning certs: {e}") from e

        if not expiring:
            return f"Cert rotation check: all certificates valid (>{warn_days} days remaining)."

        lines = [f"Cert rotation check: {len(expiring)} certificate(s) expiring within {warn_days} days:"]
        for cert_info in expiring:
            lines.append(
                f"  - {cert_info['name']}: expires {cert_info['expires']} "
                f"({cert_info['days_left']} days remaining)"
            )
        return "\n".join(lines)

    async def _cert_auto_rotate(self, task: HeartbeatTask) -> str:
        """Queue host-side rotation of expiring leaf certificates (not the CA).

        This action used to rotate IN-PROCESS via ClusterCA — no backup, no
        health-probe, no auto-revert — while two safe paths already existed
        (the CLI's rotate-all closed loop, and the autonomy patrol's spool
        delegation — now a direct Rust spool write). A bad in-process
        rotation bricked mTLS with nothing to roll back to.

        It now delegates through the SAME host-watcher spool the autonomy
        path uses (gateway-rust routes/admin.rs): the watcher runs the CLI rotate-all
        safety envelope — backup → rotate → restart consumers → health-probe
        → AUTO-REVERT on failure. The rotation outlives this task's run;
        the result file and the next cert_expiry_check are the verification.

        Config: ``warn_days`` gates the local pre-scan only (don't queue when
        nothing is expiring). The host-side rotate-all applies its own
        warn/new-cert windows; the old ``new_cert_days``/``reload`` knobs are
        obsolete — the closed loop always reloads consumers.
        """
        import os

        warn_days = task.config.get("warn_days", 30)
        pki_dir = task.config.get("pki_dir", "")

        if not pki_dir:
            pki_dir = os.getenv("NOO_PKI_DIR", "")
        if not pki_dir:
            return "Cert auto-rotate: NOO_PKI_DIR not configured."

        # Read-only pre-scan so we don't queue a host-side run for nothing.
        try:
            from ..pki.ca import ClusterCA
            ca = ClusterCA(pki_dir=pki_dir)
        except ImportError:
            return "Cert auto-rotate: PKI module not available."
        except Exception as e:
            raise RuntimeError(f"Cert auto-rotate: error initialising CA: {e}") from e

        expiring = ca.get_expiring_certs(warn_days=warn_days)
        # Filter out CA — rotate-all only touches leaves.
        leaf_expiring = [c for c in expiring if not c["name"].endswith("ca.crt")]
        if not leaf_expiring:
            return f"Cert auto-rotate: no leaf certificates expiring within {warn_days} days."

        from . import host_spool

        path = host_spool.write_command(
            "rotate", "pki", requested_by="cert_auto_rotate"
        )
        if not path:
            raise RuntimeError(
                "Cert auto-rotate: could not queue rotation (host spool "
                "unavailable — is noo-hostd running? "
                "systemctl --user status noo-hostd)"
            )

        lines = [
            f"Cert auto-rotate: {len(leaf_expiring)} leaf certificate(s) expiring "
            f"within {warn_days} days — rotation queued host-side "
            "(backup→rotate→reload→probe→auto-revert)."
        ]
        for c in leaf_expiring:
            lines.append(
                f"  - {c['name']}: expires {c['expires']} "
                f"({c['days_left']} days remaining)"
            )

        # Wait briefly for fast outcomes (mirrors the Rust rotate handler); a
        # real rotation with restarts takes minutes and reports via the
        # result file after this returns.
        name = os.path.basename(path).removesuffix(".cmd.json")
        result_path = os.path.join(os.path.dirname(path), f"{name}.result.json")
        wait_seconds = int(task.config.get("result_wait_seconds", 40))
        for _ in range(max(0, wait_seconds // 5)):
            await asyncio.sleep(5)
            if os.path.exists(result_path):
                try:
                    with open(result_path, encoding="utf-8") as fh:
                        result = json.loads(fh.read())
                    lines.append(f"  Host-side result: {json.dumps(result)}")
                except (OSError, ValueError):
                    lines.append(f"  Host-side result file unreadable: {result_path}")
                return "\n".join(lines)

        lines.append(
            "  Rotation running host-side; result will land at "
            f"{result_path} (next cert_expiry_check verifies)."
        )
        return "\n".join(lines)

    # ====================================================================
    # Category 5: Logging
    # ====================================================================

    async def _write_log(self, task: HeartbeatTask) -> str:
        """Write a structured markdown log to the writable workspace."""
        sections = task.config.get("sections", ["cluster", "rag", "jobs", "errors"])
        filename_template = task.config.get("filename", "heartbeat-{date}.md")
        # The default workspace; a `workspace_dir` override is honoured only inside it
        # (confined_output_path).
        workspace_dir = _resolve_workspace_dir()

        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        filename = filename_template.replace("{date}", date_str)
        # Workspace convention (operator, 2026-08-09): activity/heartbeat
        # logs live under activity/. Applied here rather than in the default
        # template because existing tasks carry their old bare filename in
        # persisted config; an explicit subdirectory is respected as chosen.
        if "/" not in filename:
            filename = f"activity/{filename}"
        out_path = confined_output_path(workspace_dir, task.config.get("workspace_dir") or None, filename)
        # Opened NOW, without following a symlink, and written through this handle: the section
        # gathering below is slow, and a path checked before it can be swapped during it.
        try:
            out_file = open_confined(out_path)
        except Exception as e:
            raise RuntimeError(f"write_log: failed to open {out_path}: {e}") from e

        # Gather content for each section
        content_parts: List[str] = []
        header = (
            f"# Heartbeat Log\n\n"
            f"**Generated**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  \n"
            f"**Task**: {task.name}  \n"
            f"**Sections**: {', '.join(sections)}\n"
        )
        content_parts.append(header)

        try:
            for section in sections:
                section_content = await self._gather_section(section)
                content_parts.append(f"\n## {section.title()}\n\n{section_content}")
        except BaseException:
            out_file.close()  # opened early; do not leak it when the gather fails
            raise

        content = "\n".join(content_parts)

        # Write file
        try:
            with out_file:
                out_file.truncate(0)
                out_file.write(content)
        except Exception as e:
            raise RuntimeError(f"write_log: failed to write {out_path}: {e}") from e

        # Track artifact for the executor to capture
        self._current_artifacts = [str(out_path)]

        return f"write_log: wrote {len(content)} bytes to {out_path}"

    async def _gather_section(self, section: str) -> str:
        """Collect data for a single log section."""
        client = self._get_http_client()

        if section == "cluster":
            try:
                r = await client.get(f"{self.gateway_url}/api/cluster/nodes")
                if r.status_code == 200:
                    nodes = r.json()
                    if isinstance(nodes, dict):
                        nodes = nodes.get("nodes", [])
                    online = sum(1 for n in nodes if n.get("status") == "online")
                    offline = [n for n in nodes if n.get("status") != "online"]
                    lines = [f"- **Nodes**: {online}/{len(nodes)} online"]
                    for n in offline:
                        lines.append(f"  - OFFLINE: {n.get('hostname', n.get('id', '?'))}")
                    loads = [n.get("load", 0) for n in nodes if n.get("status") == "online"]
                    if loads:
                        avg_load = sum(loads) / len(loads)
                        lines.append(f"- **Avg Load**: {avg_load:.0%}")
                    return "\n".join(lines)
            except Exception as e:
                return f"Error fetching cluster data: {e}"

        elif section == "rag":
            try:
                r = await client.get(f"{self.gateway_url}/api/v1/rag/status")
                if r.status_code == 200:
                    rag = r.json()
                    return (
                        f"- **Documents**: {rag.get('document_count', 0)}\n"
                        f"- **Pages**: {rag.get('page_count', 0)}\n"
                        f"- **Unembedded**: {rag.get('unembedded_pages', 0)}"
                    )
            except Exception as e:
                return f"Error fetching RAG data: {e}"

        elif section == "jobs":
            try:
                r = await client.get(f"{self.gateway_url}/api/scheduler/status")
                if r.status_code == 200:
                    sched = r.json()
                    if sched.get("queue_depth", 0) is None:
                        return "- **Jobs**: not reported (the queue is unreadable: Redis not connected)"
                    return (
                        f"- **Queue Depth**: {sched.get('queue_depth', 0)}\n"
                        f"- **Active Jobs**: {sched.get('active_jobs', 0)}\n"
                        f"- **Completed**: {sched.get('completed', 'N/A')}\n"
                        f"- **Failed**: {sched.get('failed', 'N/A')}"
                    )
            except Exception as e:
                return f"Error fetching job data: {e}"

        elif section == "memory":
            cs = self._get_conversation_store()
            if cs:
                try:
                    stats = await cs.get_conversation_stats(days=1)
                    return (
                        f"- **Conversations (24h)**: {stats.get('conversation_count', 0)}\n"
                        f"- **Messages (24h)**: {stats.get('message_count', 0)}"
                    )
                except Exception:
                    return "Memory stats unavailable."
            return "ConversationStore not available."

        elif section == "errors":
            sched = get_heartbeat_scheduler()
            if sched:
                result = sched.get_history(limit=10, status="error")
                recent = result.get("runs", [])
                if not recent:
                    return "No recent errors."
                lines = []
                for err in recent:
                    ts = err.get("started_at", "")[:16].replace("T", " ")
                    lines.append(f"- **{ts}** `{err.get('task_name', '')}`: {err.get('error', '')[:200]}")
                return "\n".join(lines)
            return "Scheduler not available."

        elif section == "backends":
            try:
                r = await client.get(f"{self.gateway_url}/api/cluster/backends")
                if r.status_code == 200:
                    backends = r.json().get("backends", [])
                    if not backends:
                        return "No backends running."
                    lines = [f"- **Running**: {len(backends)}"]
                    for b in backends[:10]:
                        model = b.get("model", "?")
                        node = b.get("node_id", b.get("hostname", "?"))
                        lines.append(f"  - {model} on {node}")
                    return "\n".join(lines)
            except Exception as e:
                return f"Error fetching backend data: {e}"

        return f"Unknown section: {section}"

    # ====================================================================
    # Category 6: External / Outbound
    # ====================================================================

    async def _structured_research(self, task: HeartbeatTask) -> str:
        """Robust local research via the capability pipeline (no agentic loop).

        Code drives search → per-source extract (map, cheap model) → synthesize
        (reduce, strong model, guided JSON, quality-floored) → save + ingest.
        Reliable on local models because no step depends on the model deciding
        to act. See pipeline/research.py. Config: topic (required), map_model,
        reduce_model, workspace_dir, max_results.
        """
        topic = task.config.get("topic", "")
        if not topic:
            return "Structured research: config.topic is required."
        try:
            from ..pipeline.research import run_research
            summary = await run_research(
                topic,
                map_model=task.config.get("map_model") or None,
                reduce_model=task.config.get("reduce_model") or None,
                # never the task's own: config is data an agent can author (confined_output_path)
                workspace_dir=None,
                max_results=int(task.config.get("max_results", 4)),
            )
            return summary
        except Exception as e:  # noqa: BLE001
            logger.exception("structured_research_error")
            raise RuntimeError(f"Structured research failed: {e}") from e

    async def _research_report(self, task: HeartbeatTask) -> str:
        """Research a topic using the coordinator (web search + RAG) and produce a report."""
        topic = task.config.get("topic", "")
        depth = task.config.get("depth", "standard")  # brief, standard, deep
        save_to_file = task.config.get("save_to_file", True)
        filename_template = task.config.get("filename", "research-{topic}-{date}.md")
        workspace_dir = task.config.get("workspace_dir", "")
        extra_instructions = task.config.get("instructions", "")

        if not topic:
            return "Research report: no topic configured. Set config.topic."

        if not self.coordinator:
            return "Research report: coordinator not available (required for LLM research)."

        # Build the research prompt based on depth
        depth_guidance = {
            "brief": "Write a concise 2-3 paragraph summary.",
            "standard": (
                "Write a structured report with sections: Overview, Key Findings, "
                "Details, and Conclusion. Aim for 500-1000 words."
            ),
            "deep": (
                "Write a comprehensive, detailed report. Include: Executive Summary, "
                "Background, Detailed Analysis, Key Data Points, Implications, "
                "and Recommendations. Use web search extensively to gather "
                "multiple sources. Aim for 1500+ words."
            ),
        }

        prompt = (
            f"Research the following topic and produce a report in markdown format.\n\n"
            f"**Topic**: {topic}\n\n"
            f"**Depth**: {depth_guidance.get(depth, depth_guidance['standard'])}\n\n"
            f"Use the web_search tool to find current information. "
            f"Use noo_rag_query to check the knowledge base for relevant internal docs. "
            f"Include sources and references where applicable.\n"
        )
        if extra_instructions:
            prompt += f"\n**Additional instructions**: {extra_instructions}\n"

        try:
            result = await self.coordinator.run(
                message=prompt,
                conversation_id=None,
                channel="heartbeat",
                sender_id="heartbeat_scheduler",
                sender_name="Heartbeat",
                # Optional per-task model override (config.model). Set to a
                # cloud model (e.g. claude-sonnet-5) so research reliably
                # web-searches; empty → local default backend.
                model=task.config.get("model") or None,
            )
            report = result.response
        except Exception as e:
            raise RuntimeError(f"Research report failed: {e}") from e

        # Optionally save to file
        if save_to_file:
            if not workspace_dir:
                workspace_dir = _resolve_workspace_dir()

            date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            safe_topic = "".join(c if c.isalnum() or c in "-_ " else "" for c in topic)[:50].strip().replace(" ", "-").lower()
            filename = (
                filename_template
                .replace("{topic}", safe_topic)
                .replace("{date}", date_str)
            )
            # Same convention as _write_log: research reports live under
            # research/ unless the template already picks a subdirectory.
            if "/" not in filename:
                filename = f"research/{filename}"
            try:
                out_path = confined_output_path(
                    _resolve_workspace_dir(), task.config.get("workspace_dir") or None, filename
                )
                with open_confined(out_path) as f:
                    f.truncate(0)
                    f.write(report)
                self._current_artifacts = [str(out_path)]
            except Exception as e:
                logger.warning("research_report_save_error", error=str(e))

        preview = report[:300].replace("\n", " ")
        return f"Research report on '{topic}' ({depth}): {len(report)} chars. {preview}..."

    # ====================================================================
    # Category 7: Pipelines
    async def _continue_pending_tasks(self, task: HeartbeatTask) -> str:
        """Resume coordinator sessions that have pending background tasks.

        Checks PostgreSQL for saved coordinator sessions with incomplete
        background work, restores them, and continues the async loop.
        Reports results to the session's originating channel.
        """
        if not self.coordinator or not hasattr(self.coordinator, '_task_manager'):
            return "Async task coordinator not available."

        task_manager = self.coordinator._task_manager
        if not task_manager or not getattr(task_manager, 'store', None):
            return "No task persistence store configured."

        try:
            import asyncio
            loop = asyncio.get_running_loop()
            pending_sessions = await loop.run_in_executor(
                None, task_manager.store.list_pending_sessions,
            )
        except Exception as e:
            raise RuntimeError(f"Failed to load pending sessions: {e}") from e

        if not pending_sessions:
            return "No pending coordinator sessions to resume."

        results = []
        time_budget = task.config.get("time_budget_sec", 120)

        for session_data in pending_sessions:
            session_id = session_data.get("session_id", "?")
            try:
                # Restore session state
                state = session_data.get("session_state", {})
                if not state:
                    continue

                # Resume using the coordinator in async mode
                result = await self.coordinator.run(
                    message="[System: Resuming pending background tasks from previous session]",
                    conversation_id=state.get("conversation_id"),
                    channel=state.get("channel", "heartbeat"),
                    sender_id="heartbeat_scheduler",
                    sender_name="Task Coordinator",
                    mode="async",
                    time_budget_sec=min(time_budget, state.get("time_budget_remaining_sec", 120)),
                )

                summary = (result.response or "")[:300]
                results.append(f"Session {session_id}: {summary}")

                # Notify original channel if available
                channel = state.get("channel", "")
                if channel and channel != "heartbeat" and self.channel_dispatcher:
                    try:
                        # Extract recipient from state if available
                        recipients = state.get("recipients", [])
                        for recipient in recipients:
                            await self.channel_dispatcher.dispatch(
                                channel=channel,
                                recipient=recipient,
                                message=f"Background task completed:\n\n{result.response}",
                            )
                    except Exception:
                        pass

            except Exception as e:
                results.append(f"Session {session_id}: ERROR — {e}")
                logger.error(
                    "heartbeat_continue_tasks_error",
                    session_id=session_id, error=str(e),
                )

        return f"Resumed {len(results)} session(s):\n" + "\n".join(results)

    # ====================================================================

    async def _pipeline(self, task: HeartbeatTask) -> str:
        """Run a sequence of actions in order, passing output between steps."""
        steps = task.config.get("steps")
        if not steps or not isinstance(steps, list):
            return "Pipeline: config.steps must be a non-empty list."

        if self._pipeline_depth >= self._MAX_PIPELINE_DEPTH:
            return f"Pipeline: max nesting depth ({self._MAX_PIPELINE_DEPTH}) exceeded."

        self._pipeline_depth += 1
        try:
            return await self._run_pipeline_steps(task, steps)
        finally:
            self._pipeline_depth -= 1

    async def _run_pipeline_steps(self, task: HeartbeatTask, steps: List) -> str:
        context: Dict[str, str] = {}
        all_artifacts: List[str] = []
        results: List[str] = []
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        for i, step in enumerate(steps):
            step_name = step.get("name", f"step_{i}")
            action = step.get("action")
            if not action:
                results.append(f"{step_name}: skipped (no action)")
                continue

            # Evaluate condition if present
            condition = step.get("condition")
            _safe_eval = _get_safe_eval() if condition else None
            if condition and _safe_eval is not None:
                try:
                    if not _safe_eval(condition, context):
                        results.append(f"{step_name}: skipped (condition false)")
                        context[step_name] = ""
                        continue
                except (ValueError, Exception) as e:
                    results.append(f"{step_name}: skipped (condition error: {e})")
                    context[step_name] = ""
                    continue

            # Resolve config with context from previous steps
            step_config = step.get("config", {})
            resolved_config = _resolve_config(step_config, context, date_str)

            if action in _LLM_ACTIONS:
                # Refused, not run: see _LLM_ACTIONS.
                results.append(
                    f"{step_name}: refused: a pipeline step cannot run the agent action {action!r}; "
                    "schedule it as its own task"
                )
                context[step_name] = ""
                if step.get("on_error", "stop") == "stop":
                    raise RuntimeError(f"Pipeline step {step_name!r} refused: LLM actions cannot run inside a pipeline")
                continue

            # Build temporary task for this step
            temp_task = HeartbeatTask(
                id=f"{task.id}__{step_name}",
                name=f"{task.name} > {step_name}",
                schedule=task.schedule,
                action=action,
                config=resolved_config,
            )

            on_error = step.get("on_error", "stop")
            self._current_artifacts = []
            try:
                result_text = await self.execute(temp_task)
                context[step_name] = result_text
                all_artifacts.extend(self._current_artifacts)
                results.append(f"{step_name} ({action}): success")
            except Exception as e:
                context[step_name] = f"Error: {e}"
                results.append(f"{step_name} ({action}): error — {e}")
                if on_error == "stop":
                    results.append("Pipeline stopped due to error.")
                    break
                elif on_error == "skip":
                    continue
                # "continue" — keep going

        self._current_artifacts = all_artifacts
        return f"Pipeline ({len(results)}/{len(steps)} steps): " + "; ".join(results)

    async def _research_and_send(self, task: HeartbeatTask) -> str:
        """Research a topic and send the report to a channel."""
        topic = task.config.get("topic", "")
        channel = task.config.get("channel", "")
        recipient = task.config.get("recipient", "")

        if not topic:
            return "Research and send: config.topic is required."
        if not channel or not recipient:
            return "Research and send: config.channel and config.recipient are required."

        # Step 1: Run the research report
        report_result = await self._research_report(task)

        # Extract the actual report from the coordinator (re-run won't work,
        # so we look at the saved artifact or re-generate a shorter version)
        # The report_result contains a preview; for sending, we want the full text.
        # We can get it from the artifact file if it was saved.
        full_report = ""
        if self._current_artifacts:
            try:
                full_report = Path(self._current_artifacts[0]).read_text(encoding="utf-8")
            except Exception:
                pass

        if not full_report:
            # Fall back to generating a sendable summary
            if self.coordinator:
                try:
                    result = await self.coordinator.run(
                        message=(
                            f"Research '{topic}' and write a concise report suitable "
                            f"for sending as a message. Use web_search for current info. "
                            f"Keep it under 2000 characters."
                        ),
                        conversation_id=None,
                        channel="heartbeat",
                        sender_id="heartbeat_scheduler",
                        sender_name="Heartbeat",
                    )
                    full_report = result.response
                except Exception as e:
                    raise RuntimeError(f"Research and send: research phase failed: {e}") from e
            else:
                return "Research and send: coordinator not available."

        # Step 2: Send via channel
        send_task = HeartbeatTask(
            id=f"{task.id}_send",
            name=f"{task.name} (send)",
            schedule=task.schedule,
            action="channel_message",
            config={
                "channel": channel,
                "recipient": recipient,
                "message": full_report,
            },
        )
        # `_channel_message` was deleted 2026-08-01: it delivered over an
        # HTTP loopback to POST /api/channels/send carrying only an mTLS
        # cert and NO cluster HMAC bearer, so the gateway 401'd its own
        # call and every send failed. Both `channel_message` and
        # `research_and_send` are RUST_LLM_ACTIONS, so this branch is
        # unreachable in Rust-primary — raise rather than return a string,
        # because a returned "FAILED" string records status=success.
        del send_task, report_result
        raise RuntimeError(
            "research_and_send delivery is owned by the Rust heartbeat loop "
            "(heartbeat_actions::notify_channels); the Python send path was "
            "removed."
        )

    async def _chat_digest(self, task: HeartbeatTask) -> str:
        """Read messages from a channel space and produce a digest summary."""
        channel = task.config.get("channel", "google_chat")
        recipient = task.config.get("recipient", "")
        limit = int(task.config.get("limit", 100))
        since = task.config.get("since", "")
        prompt = task.config.get("prompt", "")

        if not recipient:
            raise ValueError(
                "config.recipient is required. "
                "For Google Chat, use the space name (e.g. 'spaces/AAAAxxxx')."
            )

        # Read messages from the channel
        try:
            import httpx
            from .deps import ssl_verify, client_cert
            params: Dict[str, Any] = {"recipient": recipient, "limit": limit}
            if since:
                params["since"] = since
            async with httpx.AsyncClient(verify=ssl_verify(), cert=client_cert(), timeout=30) as c:
                r = await c.get(
                    f"{self.gateway_url}/api/channels/{channel}/messages",
                    params=params,
                )
                r.raise_for_status()
                data = r.json()
        except Exception as e:
            raise ValueError(f"Failed to read messages from {channel}: {e}")

        messages = data.get("messages", [])
        if not messages:
            return f"Chat digest: no messages found in {recipient}"

        # Format messages for the coordinator
        msg_text = "\n".join(
            f"[{m.get('create_time', '?')}] {m.get('sender', '?')}: {m.get('text', '')}"
            for m in messages
        )

        default_prompt = (
            "Review the following conversation from Google Chat. "
            "Identify key topics, interesting ideas, action items, decisions made, "
            "and open questions. Produce a concise digest summary organized by theme."
        )

        if not self.coordinator:
            return f"Chat digest: {len(messages)} messages read but coordinator not available for summarization.\n\nRaw messages:\n{msg_text[:3000]}"

        try:
            result = await self.coordinator.run(
                message=f"{prompt or default_prompt}\n\n--- Chat History ({len(messages)} messages) ---\n{msg_text}",
                conversation_id=None,
                channel="heartbeat",
                sender_id="heartbeat_scheduler",
                sender_name="Heartbeat",
            )
            return f"**Chat Digest** ({len(messages)} messages from {channel})\n\n{result.response}"
        except Exception as e:
            return f"Chat digest: read {len(messages)} messages but summarization failed: {e}\n\nFirst 5 messages:\n" + "\n".join(
                f"- {m.get('sender', '?')}: {m.get('text', '')[:200]}"
                for m in messages[:5]
            )


# ========================================================================
# Default starter tasks
# ========================================================================

# Names that older releases seeded for a default task whose cadence has since
# changed. Installs keep the row they were seeded with (insert-only seeding), so
# a default that moved from 6-hourly to daily kept the old NAME while the
# schedule was moved separately (`noo heartbeat set-schedule`): the task read
# "6-hourly" and ran daily. Only an EXACT match on the old default name is
# renamed; an operator's own rename is never touched.
LEGACY_DEFAULT_NAMES = {
    ("database_backup", "Database Backup (6-hourly)"): "Database Backup (daily, 03:30)",
}

DEFAULT_TASKS = [
    {
        # Enabled by default — the agent-message record has no other pruner
        # Weekly, applies (not a dry run), 90 days.
        "id": "agent_messages_retention",
        "name": "Agent messages retention (weekly, 90d)",
        "schedule": "0 5 * * 0",
        "action": "agent_messages_retention",
        "config": {"dry_run": False, "days": 90},
        "enabled": True,
        "created_by": "system",
    },
    {
        "id": "daily_briefing",
        "name": "Daily System Briefing",
        "schedule": "0 8 * * *",
        "action": "daily_briefing",
        "enabled": False,
        "created_by": "system",
    },
    {
        # Enabled by default — Postgres IS the system (memory, KB, node
        # registry, config). Verify restorability with scripts/restore-drill.sh.
        "id": "database_backup",
        "name": "Database Backup (daily, 03:30)",
        # Daily at 03:30 in the controller's heartbeat timezone
        # (NOO_HEARTBEAT_TZ), a quiet hour. The dump takes minutes and grows;
        # the action queues it and a gateway hook finishes the run, so the
        # schedule no longer has to fit a polling window.
        "schedule": "30 3 * * *",
        "action": "database_backup",
        "enabled": True,
        "created_by": "system",
    },
    {
        "id": "daily_log",
        "name": "Daily Activity Log",
        "schedule": "0 18 * * *",
        "action": "write_log",
        "config": {
            "sections": ["cluster", "rag", "jobs", "errors"],
            "filename": "activity-{date}.md",
        },
        "enabled": False,
        "created_by": "system",
    },
    {
        "id": "cluster_health",
        "name": "Cluster Health Check",
        "schedule": "*/30 * * * *",
        "action": "cluster_health",
        "enabled": False,
        "created_by": "system",
    },
    {
        "id": "rag_reindex",
        "name": "RAG Reindex Check",
        "schedule": "0 */4 * * *",
        "action": "rag_reindex",
        "enabled": False,
        "created_by": "system",
    },
    {
        "id": "security_audit",
        "name": "Security Audit",
        "schedule": "0 6 * * *",
        "action": "security_audit",
        "enabled": False,
        "created_by": "system",
    },
    {
        "id": "weekly_research",
        "name": "Weekly Research Report",
        "schedule": "0 9 * * 1",
        "action": "research_report",
        "config": {
            "topic": "AI and LLM developments",
            "depth": "standard",
            "save_to_file": True,
            "instructions": "Focus on open-source models, local inference, and self-hosted AI.",
        },
        "enabled": False,
        "created_by": "system",
    },
    {
        "id": "daily_digest_gchat",
        "name": "Daily Digest to Google Chat",
        "schedule": "0 17 * * 1-5",
        "action": "channel_message",
        "config": {
            "channel": "google_chat",
            "recipient": "",
            "prompt": "Summarize today's system activity: cluster health, jobs completed, knowledge base changes, and any errors. Keep it concise and actionable.",
        },
        "enabled": False,
        "created_by": "system",
    },
    {
        "id": "thought_experiment",
        "name": "Graph Traversal Rehearsal",
        "schedule": "*/20 * * * *",
        "action": "thought_experiment",
        "config": {
            "num_queries": 5,
            "min_entities": 3,
            "skip_if_active": True,
        },
        "enabled": True,
        "created_by": "system",
    },
    {
        "id": "graph_signals",
        "name": "Graph Signal Recomputation",
        "schedule": "0 */6 * * *",
        "action": "graph_signals",
        "enabled": True,
        "created_by": "system",
    },
]

ACTION_DESCRIPTIONS: Dict[str, str] = {
    "daily_briefing": "Summarize system status, KB, cache, and jobs",
    "cluster_health": "Check node status and report degraded nodes",
    "rag_reindex": "Trigger re-embedding of stale documents",
    "memory_cleanup": "Prune conversations older than N days",
    "idle_scaledown": "Stop backends with no recent inference",
    "custom_prompt": "Run an arbitrary prompt through the coordinator",
    "knowledge_refresh": "Check source URIs and re-ingest changed docs",
    "conversation_summarize": "Summarize old conversations via LLM",
    "graph_prune": "Detect and merge near-duplicate entities",
    "memory_relevance_audit": "Run test queries and score retrieval quality",
    "news_scan": "Fetch RSS feeds, filter by keywords, optionally ingest",
    "goal_review": "Review persistent goals using coordinator LLM",
    "channel_keepalive": "Ping channels to verify connections",
    "model_cache_warm": "Pre-pull models onto nodes before peak hours",
    "backup_knowledge": "Export docs/entities/edges to JSONL snapshots",
    "disk_cleanup": "Report stale items that could be cleaned up",
    "cost_report": "Report GPU hours, API usage, cache efficiency",
    "self_benchmark": "Run test prompts, measure latency and quality",
    "security_audit": "Check rate-limit violations and auth failures",
    "cert_rotation_check": "Check for certificates expiring soon",
    "cert_auto_rotate": "Auto-rotate expiring leaf certificates",
    "database_backup": "Dump Postgres to the host backup dir (via host watcher, 7-day retention)",
    "audit_log_rotate": "Export-then-DROP audit log partitions older than retention",
    "write_log": "Write structured markdown log to workspace",
    "research_report": "Research a topic via web search and produce a report",
    "channel_message": "Send a message (or prompt-generated text) to a channel",
    "research_and_send": "Research a topic and send the report to a channel",
    "chat_digest": "Read messages from a channel space and produce a summary digest",
    "graph_clustering": "Run community detection on the knowledge graph",
    "thought_experiment": "Generate synthetic queries from the knowledge graph, rehearse retrieval, and capture traversals as System 1 intuition",
    "pipeline": "Run a sequence of actions in order, passing output between steps",
}

ACTION_CONFIG_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "daily_briefing": {"fields": []},
    "cluster_health": {"fields": [
        {"name": "alert_on_offline", "type": "boolean", "label": "Alert on offline nodes", "default": True},
    ]},
    "rag_reindex": {"fields": []},
    "memory_cleanup": {"fields": [
        {"name": "max_age_days", "type": "number", "label": "Max age (days)", "default": 90, "required": True},
    ]},
    "idle_scaledown": {"fields": [
        {"name": "idle_threshold_sec", "type": "number", "label": "Idle threshold (seconds)", "default": 600},
    ]},
    "custom_prompt": {"fields": [
        {"name": "prompt", "type": "text", "label": "Prompt", "required": True, "placeholder": "Enter a prompt for the coordinator..."},
        {"name": "tools_enabled", "type": "boolean", "label": "Enable tools", "default": True},
    ]},
    "knowledge_refresh": {"fields": [
        {"name": "max_docs", "type": "number", "label": "Max docs to check", "default": 20},
        {"name": "timeout_per_doc", "type": "number", "label": "Timeout per doc (sec)", "default": 10},
    ]},
    "conversation_summarize": {"fields": [
        {"name": "min_age_days", "type": "number", "label": "Min age (days)", "default": 30},
        {"name": "min_messages", "type": "number", "label": "Min messages", "default": 5},
        {"name": "max_conversations", "type": "number", "label": "Max conversations", "default": 10},
    ]},
    "graph_prune": {"fields": [
        {"name": "similarity_threshold", "type": "number", "label": "Similarity threshold", "default": 0.85},
        {"name": "dry_run", "type": "boolean", "label": "Dry run only", "default": True},
        {"name": "max_entities", "type": "number", "label": "Max entities to scan", "default": 200},
    ]},
    "memory_relevance_audit": {"fields": [
        {"name": "test_queries", "type": "string_list", "label": "Test queries (one per line)"},
        {"name": "min_expected_score", "type": "number", "label": "Min expected score", "default": 0.3},
    ]},
    "news_scan": {"fields": [
        {"name": "feeds", "type": "string_list", "label": "Feed URLs (one per line)", "required": True, "placeholder": "https://example.com/feed.xml"},
        {"name": "keywords", "type": "string_list", "label": "Keywords (one per line)"},
        {"name": "max_entries", "type": "number", "label": "Max entries", "default": 10},
        {"name": "ingest", "type": "boolean", "label": "Ingest into KB", "default": False},
    ]},
    "goal_review": {"fields": [
        {"name": "goals", "type": "json", "label": "Goals (JSON array)", "placeholder": '[{"name": "...", "description": "...", "target_date": "...", "status": "..."}]'},
        {"name": "review_prompt", "type": "text", "label": "Review prompt"},
    ]},
    "channel_keepalive": {"fields": [
        {"name": "channels", "type": "string_list", "label": "Channels to check"},
        {"name": "send_test", "type": "boolean", "label": "Send test message", "default": False},
    ]},
    "model_cache_warm": {"fields": [
        {"name": "models", "type": "json", "label": "Models (JSON array)", "placeholder": '[{"model": "...", "node_id": "...", "backend": "ollama"}]'},
    ]},
    "backup_knowledge": {"fields": [
        {"name": "output_dir", "type": "string", "label": "Output directory", "default": "/data/backups"},
        {"name": "include_graph", "type": "boolean", "label": "Include graph", "default": True},
        {"name": "include_conversations", "type": "boolean", "label": "Include conversations", "default": False},
    ]},
    "disk_cleanup": {"fields": [
        {"name": "targets", "type": "multiselect", "label": "Cleanup targets", "options": [
            {"value": "tmp_noo_files", "label": "Temp PAI files"},
            {"value": "heartbeat_run_records", "label": "Old run records"},
            {"value": "docker_dangling_images", "label": "Docker dangling images"},
            {"value": "container_logs", "label": "Container logs"},
        ]},
    ]},
    "cost_report": {"fields": [
        {"name": "period_days", "type": "number", "label": "Period (days)", "default": 7},
        {"name": "gpu_cost_per_hour", "type": "number", "label": "GPU cost/hour ($)", "default": 0.0},
    ]},
    "self_benchmark": {"fields": [
        {"name": "test_prompts", "type": "json", "label": "Test prompts (JSON array)"},
        {"name": "timeout", "type": "number", "label": "Timeout (seconds)", "default": 30},
    ]},
    "security_audit": {"fields": [
        {"name": "period_hours", "type": "number", "label": "Period (hours)", "default": 24},
        {"name": "alert_threshold", "type": "number", "label": "Alert threshold", "default": 5},
    ]},
    "cert_rotation_check": {"fields": [
        {"name": "warn_days", "type": "number", "label": "Warn if expiring within (days)", "default": 30},
        {"name": "pki_dir", "type": "string", "label": "PKI directory", "placeholder": "Leave empty to use NOO_PKI_DIR env var"},
    ]},
    "cert_auto_rotate": {"fields": [
        {"name": "warn_days", "type": "number", "label": "Warn if expiring within (days)", "default": 30},
        {"name": "new_cert_days", "type": "number", "label": "New cert validity (days)", "default": 90},
        {"name": "pki_dir", "type": "string", "label": "PKI directory"},
        {"name": "reload", "type": "boolean", "label": "Restart consumers after rotation (host watcher)", "default": True},
    ]},
    "database_backup": {"fields": [
        {"name": "wait_secs", "type": "number", "label": "Wait for result (seconds)", "default": 120},
    ]},
    "audit_log_rotate": {"fields": [
        {"name": "retention_months", "type": "number", "label": "Retention months",
         "default": 3,
         "placeholder": "Overrides security.audit_retention_months for this task"},
    ]},
    "write_log": {"fields": [
        {"name": "sections", "type": "multiselect", "label": "Sections", "options": [
            {"value": "cluster", "label": "Cluster"},
            {"value": "rag", "label": "RAG"},
            {"value": "jobs", "label": "Jobs"},
            {"value": "memory", "label": "Memory"},
            {"value": "errors", "label": "Errors"},
            {"value": "backends", "label": "Backends"},
        ]},
        {"name": "filename", "type": "string", "label": "Filename template", "default": "heartbeat-{date}.md"},
    ]},
    "research_report": {"fields": [
        {"name": "topic", "type": "string", "label": "Topic", "required": True, "placeholder": "AI developments this week"},
        {"name": "depth", "type": "select", "label": "Depth", "default": "standard", "options": [
            {"value": "brief", "label": "Brief"},
            {"value": "standard", "label": "Standard"},
            {"value": "deep", "label": "Deep"},
        ]},
        {"name": "save_to_file", "type": "boolean", "label": "Save to file", "default": True},
        {"name": "instructions", "type": "text", "label": "Additional instructions"},
    ]},
    "channel_message": {"fields": [
        {"name": "channel", "type": "select", "label": "Channel", "required": True, "options": [
            {"value": "google_chat", "label": "Google Chat"},
            {"value": "telegram", "label": "Telegram"},
            {"value": "whatsapp", "label": "WhatsApp"},
        ]},
        {"name": "recipient", "type": "channel_recipient", "label": "Recipient", "required": True, "linked_channel_field": "channel"},
        {"name": "prompt", "type": "text", "label": "Prompt (generates message via AI)"},
        {"name": "message", "type": "text", "label": "Static message (overrides prompt)"},
    ]},
    "research_and_send": {"fields": [
        {"name": "topic", "type": "string", "label": "Topic", "required": True},
        {"name": "depth", "type": "select", "label": "Depth", "default": "standard", "options": [
            {"value": "brief", "label": "Brief"},
            {"value": "standard", "label": "Standard"},
            {"value": "deep", "label": "Deep"},
        ]},
        {"name": "channel", "type": "select", "label": "Channel", "required": True, "options": [
            {"value": "google_chat", "label": "Google Chat"},
            {"value": "telegram", "label": "Telegram"},
            {"value": "whatsapp", "label": "WhatsApp"},
        ]},
        {"name": "recipient", "type": "channel_recipient", "label": "Recipient", "required": True, "linked_channel_field": "channel"},
        {"name": "save_to_file", "type": "boolean", "label": "Save report to file", "default": True},
    ]},
    "chat_digest": {"fields": [
        {"name": "channel", "type": "select", "label": "Channel", "default": "google_chat", "options": [
            {"value": "google_chat", "label": "Google Chat"},
        ]},
        {"name": "recipient", "type": "string", "label": "Space ID", "required": True,
         "placeholder": "spaces/AAAA..."},
        {"name": "limit", "type": "number", "label": "Max messages", "default": 100},
        {"name": "since", "type": "string", "label": "Since (ISO timestamp)",
         "placeholder": "2026-03-01T00:00:00Z (optional)"},
        {"name": "prompt", "type": "text", "label": "Custom digest prompt",
         "placeholder": "Leave empty for default: identify key topics, ideas, action items..."},
    ]},
    "graph_clustering": {"fields": [
        {"name": "min_cluster_size", "type": "number", "label": "Min cluster size", "default": 3},
        {"name": "resolution", "type": "number", "label": "Resolution", "default": 1.0},
    ]},
    "thought_experiment": {"fields": [
        {"name": "num_queries", "type": "number", "label": "Synthetic queries per run", "default": 5},
        {"name": "min_entities", "type": "number", "label": "Min entities needed to run", "default": 3},
        {"name": "intent_types", "type": "string_list", "label": "Intent types to practice (blank = all)",
         "placeholder": "causal, definitional, procedural, comparative, exploratory"},
    ]},
    "pipeline": {"fields": [
        {"name": "steps", "type": "json", "label": "Pipeline steps (JSON)", "required": True,
         "placeholder": '[{"action": "...", "name": "step1", "config": {}, "condition": "...", "on_error": "stop"}]'},
    ]},
}


# ========================================================================
# HeartbeatScheduler -- task registry + delegated-run executor
# ========================================================================

class HeartbeatScheduler:
    """Task registry and executor for the heartbeat actions Rust delegates.

    Holds the task table, executes a delegated run (``run_task_now``) and
    stores its history. It does not fire tasks on a schedule — the Rust
    heartbeat_loop does — and it does not deliver results to channels.
    """

    def __init__(
        self,
        config: HeartbeatConfig,
        gateway_url: str,
        channel_dispatcher: Any = None,
        coordinator: Any = None,
        store: Any = None,
    ):
        self.config = config
        self.gateway_url = gateway_url.rstrip("/")
        self.channel_dispatcher = channel_dispatcher
        # Same fallback as HeartbeatActionExecutor: install an HTTP proxy
        # if no real coordinator was injected, so cron tasks still work in
        # Rust-primary mode where the Python CoordinatorAgent isn't built.
        if coordinator is None:
            coordinator = _HttpCoordinatorProxy(
                self.gateway_url, lambda: self._executor._get_http_client()
            )
        self.coordinator = coordinator
        self.store = store

        self._tasks: Dict[str, HeartbeatTask] = {}
        self._run_history: List[TaskRunRecord] = []
        self._max_history = 200
        self._executor = HeartbeatActionExecutor(
            gateway_url, coordinator=coordinator,
        )
        self._load_config_tasks()
        self._load_store_tasks()

    def _load_config_tasks(self) -> None:
        """Load task definitions from the HeartbeatConfig."""
        for task_data in self.config.tasks:
            task = HeartbeatTask.from_dict(task_data)
            if task.next_run is None:
                task.next_run = compute_next_run(task.schedule)
            self._tasks[task.id] = task
            logger.info("heartbeat_task_loaded",
                        task_id=task.id, name=task.name,
                        schedule=task.schedule, action=task.action)

        # Merge default tasks — new defaults are added if their ID is not
        # yet present (from config or store).  This ensures newly-added
        # default tasks appear on upgrade without overwriting user edits.
        #
        # IMPORTANT: We only INSERT (not upsert) into the store so that
        # existing DB rows (with user-modified enabled state, config, etc.)
        # are never overwritten by hardcoded defaults.  The subsequent
        # _load_store_tasks() call will override in-memory state with the
        # DB version, preserving the user's changes.
        for task_data in DEFAULT_TASKS:
            if task_data["id"] not in self._tasks:
                task = HeartbeatTask.from_dict(task_data)
                if task.next_run is None:
                    task.next_run = compute_next_run(task.schedule)
                self._tasks[task.id] = task
                # Insert ONLY if not already in DB (don't overwrite user edits)
                if self.store:
                    try:
                        self.store.insert_task_if_new(task.to_dict())
                    except Exception:
                        pass  # store may not be ready yet; task still works in-memory
                logger.info("heartbeat_default_task_loaded",
                            task_id=task.id, name=task.name)

    def _load_store_tasks(self) -> None:
        """Load persisted tasks from the store (if available).

        Store tasks **override** defaults/config tasks — the DB holds
        the user's edits (enabled state, config changes, etc.) and
        should always take priority over hardcoded defaults.
        """
        if not self.store:
            return
        try:
            stored = self.store.list_tasks()
            for task_data in stored:
                task = HeartbeatTask.from_dict(task_data)
                if task.next_run is None:
                    task.next_run = compute_next_run(task.schedule)
                renamed = LEGACY_DEFAULT_NAMES.get((task.id, task.name))
                if renamed:
                    task.name = renamed
                    try:
                        self.store.save_task(task.to_dict())
                    except Exception as e:
                        logger.warning("heartbeat_legacy_rename_failed",
                                       task_id=task.id, error=str(e))
                was_override = task.id in self._tasks
                self._tasks[task.id] = task
                logger.info("heartbeat_task_loaded_from_store",
                            task_id=task.id, name=task.name,
                            override=was_override)
        except Exception as e:
            logger.warning("heartbeat_store_load_failed", error=str(e))

    async def _execute_task(
        self, task: HeartbeatTask, now: datetime, run_id: Optional[str] = None
    ) -> None:
        """Execute a single due task.

        ``run_id``: when the Rust gateway dispatched this run it already
        inserted the noo_heartbeat_runs row (status "running") under an id
        it returned to the caller — recording under the same id completes
        that row (store.save_run upserts). Absent → generate, as before.
        """
        run_id = run_id or str(uuid.uuid4())[:12]
        record = TaskRunRecord(
            run_id=run_id,
            task_id=task.id,
            task_name=task.name,
            action=task.action,
            started_at=now,
        )

        logger.info("heartbeat_task_executing",
                     task_id=task.id, name=task.name,
                     action=task.action, run_id=run_id)

        start_ms = time.monotonic()
        try:
            # Counted as in-flight work so the worker pool's RSS watchdog
            # defers its self-restart instead of orphaning this run (the
            # "dispatched and never reported an outcome" failure mode).
            from .inflight import tracked as _inflight_tracked
            self._executor._current_artifacts = []
            with _inflight_tracked():
                result_text = await self._executor.execute(task)
            record.status = "success"
            record.result_text = result_text
            record.artifacts = list(self._executor._current_artifacts)
        except Exception as e:
            record.status = "error"
            record.error = str(e)
            result_text = f"Error: {e}"
            logger.error("heartbeat_task_error",
                         task_id=task.id, error=str(e))

        elapsed_ms = int((time.monotonic() - start_ms) * 1000)
        record.duration_ms = elapsed_ms
        record.completed_at = datetime.now(timezone.utc)

        task.last_run = now
        task.next_run = compute_next_run(task.schedule, now)

        if result_text and task.channels and task.recipients:
            notified = await self._notify(task, result_text)
            record.notified_channels = notified

        # Output routing
        if record.status == "success":
            try:
                routed = await self._route_output(task, result_text, record)
                if routed:
                    logger.info("heartbeat_output_routed", task_id=task.id, destinations=routed)
            except Exception as e:
                logger.warning("heartbeat_output_route_error", task_id=task.id, error=str(e))

        self._run_history.append(record)
        if len(self._run_history) > self._max_history:
            self._run_history = self._run_history[-self._max_history:]

        if self.store:
            try:
                import asyncio
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, self.store.save_run, record.to_dict())
                await loop.run_in_executor(None, self.store.update_task, task.to_dict())
            except Exception as e:
                logger.warning("heartbeat_store_save_failed", error=str(e))

        logger.info("heartbeat_task_completed",
                     task_id=task.id, status=record.status,
                     duration_ms=elapsed_ms)

    async def _route_output(self, task: HeartbeatTask, result_text: str, record: TaskRunRecord) -> List[str]:
        """Route task output to configured destinations."""
        output_cfg = task.config.get("output", {})
        destinations = output_cfg.get("destinations", [])
        if not destinations:
            return []

        routed: List[str] = []
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        topic = task.config.get("topic", task.name)

        for dest in destinations:
            dtype = dest.get("type", "")
            try:
                if dtype == "channel":
                    # Retired. Channel delivery belongs to the
                    # task's channels/recipients, which the Rust heartbeat
                    # loop delivers through the egress boundary. This route
                    # POSTed raw result text to /api/channels/send (floor
                    # only, and without the cluster bearer the gateway
                    # requires, so it 401'd besides).
                    logger.warning("output_route_channel_retired", task_id=task.id,
                                   channel=dest.get("channel", ""))
                    continue

                if dtype == "rag_ingest":
                    title_template = dest.get("title", "{topic} — {date}")
                    title = title_template.replace("{topic}", topic).replace("{date}", date_str)
                    client = self._executor._get_http_client()
                    r = await client.post(
                        f"{self.gateway_url}/api/v1/docs/ingest",
                        json={"text": result_text, "title": title},
                    )
                    r = await settle(client, r, self.gateway_url)
                    if r.status_code == 200:
                        routed.append("rag_ingest")

                elif dtype == "file":
                    path_template = dest.get("path", "")
                    if not path_template:
                        continue
                    rendered = (
                        path_template
                        .replace("{topic}", topic)
                        .replace("{date}", date_str)
                    )
                    # Confined to the workspace like every heartbeat output: relative plain names, no
                    # `..`, no symlink out. (This was a string-prefix test against /data and /tmp, which
                    # `/database/x` and `/tmpx/x` pass and which followed symlinks.) An absolute path is
                    # accepted only as a path inside the workspace.
                    ws = _resolve_workspace_dir()
                    rp = Path(rendered)
                    if rp.is_absolute():
                        try:
                            rendered = str(rp.relative_to(Path(ws).resolve()))
                        except ValueError:
                            logger.warning("output_route_file_rejected", path=rendered)
                            continue
                    try:
                        file_path = confined_output_path(ws, None, rendered)
                        with open_confined(file_path) as f:
                            f.truncate(0)
                            f.write(result_text)
                    except ValueError as e:
                        logger.warning("output_route_file_rejected", path=rendered, error=str(e))
                        continue
                    record.artifacts.append(str(file_path))
                    routed.append(f"file:{file_path}")

            except Exception as e:
                logger.warning("output_route_error", type=dtype, error=str(e))

        return routed

    async def _notify(self, task: HeartbeatTask, message: str) -> List[str]:
        """Send task results to configured channels."""
        if not self.channel_dispatcher:
            return []

        notified: List[str] = []
        for channel, recipient in zip(task.channels, task.recipients):
            try:
                # Resolve "broadcast" to default saved recipient
                actual_recipient = recipient
                if hasattr(self.channel_dispatcher, "resolve_recipient"):
                    resolved = await self.channel_dispatcher.resolve_recipient(
                        channel, recipient,
                    )
                    if resolved is None:
                        logger.debug("heartbeat_notify_skipped",
                                     channel=channel, task=task.id,
                                     reason="no default recipient configured")
                        continue
                    actual_recipient = resolved

                ok = await self.channel_dispatcher.dispatch(
                    channel=channel,
                    recipient=actual_recipient,
                    message=message,
                )
                if ok:
                    notified.append(channel)
            except Exception as e:
                logger.warning("heartbeat_notify_failed",
                               channel=channel, error=str(e))
        return notified

    # -- Task management --------------------------------------------------

    def add_task(self, task: HeartbeatTask) -> HeartbeatTask:
        """Add a new task to the scheduler."""
        if task.next_run is None:
            task.next_run = compute_next_run(task.schedule)
        self._tasks[task.id] = task
        if self.store:
            try:
                self.store.save_task(task.to_dict())
            except Exception as e:
                logger.warning("heartbeat_task_persist_failed", error=str(e))
        logger.info("heartbeat_task_added", task_id=task.id, name=task.name)
        return task

    def remove_task(self, task_id: str) -> bool:
        """Remove a task by ID."""
        task = self._tasks.pop(task_id, None)
        if task is None:
            return False
        if self.store:
            try:
                self.store.delete_task(task_id)
            except Exception as e:
                logger.warning("heartbeat_task_delete_failed", error=str(e))
        logger.info("heartbeat_task_removed", task_id=task_id)
        return True

    def get_task(self, task_id: str) -> Optional[HeartbeatTask]:
        return self._tasks.get(task_id)

    def list_tasks(self) -> List[HeartbeatTask]:
        return list(self._tasks.values())

    async def run_task_now(
        self, task_id: str, run_id: Optional[str] = None
    ) -> Optional[TaskRunRecord]:
        """Execute a task immediately, regardless of its schedule."""
        task = self._tasks.get(task_id)
        # Refresh from the store first — config may have been edited via the
        # Rust API since this worker loaded its task cache; running with a
        # stale config makes dashboard edit-then-run silently wrong.
        if self.store:
            try:
                import asyncio
                loop = asyncio.get_running_loop()
                rows = await loop.run_in_executor(None, self.store.list_tasks)
                for row in rows:
                    if row.get("id") == task_id:
                        fresh = HeartbeatTask.from_dict(row)
                        self._tasks[task_id] = fresh
                        task = fresh
                        break
            except Exception as e:
                logger.warning("heartbeat_task_refresh_failed",
                               task_id=task_id, error=str(e))
        if task is None:
            return None
        now = datetime.now(timezone.utc)
        await self._execute_task(task, now, run_id=run_id)
        for record in reversed(self._run_history):
            if record.task_id == task_id:
                return record
        return None

    def get_history(
        self,
        limit: int = 50,
        offset: int = 0,
        task_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return paginated run history from DB, with in-memory fallback.

        Returns ``{"runs": [...], "total": int}``.
        """
        # Primary path: query the store (PostgreSQL) with real pagination
        if self.store:
            try:
                runs = self.store.get_history(
                    limit=limit, offset=offset,
                    task_id=task_id, status=status,
                )
                total = self.store.count_history(
                    task_id=task_id, status=status,
                )
                return {"runs": runs, "total": total}
            except Exception as e:
                logger.warning("heartbeat_history_query_failed", error=str(e))

        # Fallback: in-memory only (no store / store error)
        records = self._run_history
        if task_id:
            records = [r for r in records if r.task_id == task_id]
        if status:
            records = [r for r in records if r.status == status]
        total = len(records)
        page = [r.to_dict() for r in records[-offset - limit:len(records) - offset if offset else None]]
        # In-memory is oldest-first, reverse for newest-first
        page.reverse()
        return {"runs": page[:limit], "total": total}

    def get_status(self) -> Dict[str, Any]:
        return {
            # Always False: this process runs no firing loop (Rust owns cron).
            "running": False,
            "enabled": self.config.enabled,
            "check_interval_seconds": self.config.check_interval_seconds,
            "task_count": len(self._tasks),
            "tasks": [t.to_dict() for t in self._tasks.values()],
            "recent_runs": len(self._run_history),
            "croniter_available": CRONITER_AVAILABLE,
        }


# ========================================================================
# Factory & global accessor
# ========================================================================

_scheduler: Optional[HeartbeatScheduler] = None


def get_heartbeat_scheduler() -> Optional[HeartbeatScheduler]:
    """Return the global heartbeat scheduler instance (or None)."""
    return _scheduler


def init_heartbeat_scheduler(
    config: HeartbeatConfig,
    gateway_url: str,
    channel_dispatcher: Any = None,
    coordinator: Any = None,
    store_dsn: Optional[str] = None,
) -> HeartbeatScheduler:
    """Create and wire the Heartbeat Scheduler."""
    global _scheduler

    store = None
    if store_dsn:
        try:
            from .heartbeat_store import HeartbeatStore
            store = HeartbeatStore(dsn=store_dsn)
        except Exception as e:
            logger.warning("heartbeat_store_init_failed", error=str(e))

    _scheduler = HeartbeatScheduler(
        config=config,
        gateway_url=gateway_url,
        channel_dispatcher=channel_dispatcher,
        coordinator=coordinator,
        store=store,
    )
    return _scheduler
