# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Job scheduler — submission, queries and controls (CRUD only).

**Dispatch does not live here.** The Python dispatch loop was
removed: `gateway-rust/src/scheduler_engine.rs`
owns dispatch, the timeout reaper, the janitor and restart recovery, and
`scheduler_completions.rs` owns the `job.ack` / `job.complete` /
`job.failed` lifecycle. There is no longer a `NOO_SCHEDULER_ENGINE` switch
— one engine dispatches, and it is the Rust one.

What remains in Python, and why:

* the CRUD surface (`submit_job`, `get_job`, `list_jobs`, `cancel_job`,
  `reprioritize_job`, pause/resume, drain/undrain, `get_status`,
  `get_job_history`) — it writes the same Redis keys the Rust engine
  reads. (Its NATS worker callers were unregistered reference bodies and
  were archived in `legacy/python-workers-reference/` by the 2026-08-08
  sweep; the CLI/HTTP surface is Rust, `routes/jobs.rs`.)

That is ALL. The background-producer loop (`run()` +
`register_background_provider` + `cluster/background_providers.py`) was
deleted in the 2026-08-09 dead-code sweep: `setup_background_providers`
had zero production callers, so the loop polled an empty registry
forever — the real producer of background_graph jobs is the Rust
autonomy evaluator (`autonomy_evaluators.rs`). background_embed was
retired (gateway-rust/src/job_types.rs RETIRED_JOB_TYPES).

Everything in this module therefore writes the queue or reads state; it
never places a job on a node, and it runs no loop.
"""

import asyncio
from .. import json_fast as json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger()

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class JobStatus(str, Enum):
    QUEUED = "queued"
    DISPATCHED = "dispatched"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    DEAD = "dead"


class JobType(str, Enum):
    INFERENCE = "inference"
    TOOL_EXEC = "tool_exec"
    MODEL_DOWNLOAD = "model_download"
    BACKGROUND_GRAPH = "background_graph"
    BACKGROUND_CACHE = "background_cache"
    FETCH_BUNDLE = "fetch_bundle"
    MODEL_FILE = "model_file"


# Terminal states — jobs in these states are done
TERMINAL_STATES = {JobStatus.COMPLETED, JobStatus.CANCELLED, JobStatus.DEAD}

# The per-tier slot policy (`DEFAULT_SLOTS` / `normalize_tier`) lived here
# until phase 7. It was duplicated in `gateway-rust/src/scheduler_slots.rs`
# for the duration of the port precisely so it could be deleted on this
# side once dispatch moved; two copies of a placement policy that must
# agree is a drift hazard, and only the dispatcher needs it.

# Redis key prefixes
QUEUE_KEY = "noo:jobs:queue"
JOB_KEY_PREFIX = "noo:jobs:"
NODE_JOBS_PREFIX = "noo:jobs:node:"
ACTIVE_SET = "noo:jobs:active"
DRAINED_KEY = "noo:jobs:drained_nodes"
HISTORY_KEY = "noo:jobs:history"
PAUSED_KEY = "noo:scheduler:paused"  # Redis flag — shared with Rust gateway

# `noo:jobs:history` is written by `scheduler_engine::terminalize()` in
# Rust, which owns the terminal transition; HISTORY_MAX_LEN lives there
# with the LTRIM that uses it. Python only reads the list.

# Dispatch ownership is no longer selectable. `scheduler_engine()` /
# `rust_owns_dispatch()` were the phase-6 cutover flag; with the Python
# loop gone there is nothing left for `NOO_SCHEDULER_ENGINE=python` to
# select, and a flag that can only strand the queue is worse than none.


class JobScheduler:
    """Job submission, queries and controls.

    Not a dispatcher and not a loop: see the module docstring.
    """

    def __init__(self, redis_url: str = "rediss://redis:6379"):
        if not REDIS_AVAILABLE:
            raise ImportError("redis package not installed")

        from ..cache import _apply_redis_tls, _redis_ssl_kwargs
        self.redis = redis.from_url(
            _apply_redis_tls(redis_url), decode_responses=True,
            **_redis_ssl_kwargs(),
        )
        self._paused = False

        # Messaging set externally after NATS connects
        self._messaging = None

    def set_messaging(self, messaging):
        """Inject the ClusterMessaging instance (called after NATS connects)."""
        self._messaging = messaging

    # ── Job Submission ──────────────────────────────────────────────

    def submit_job(
        self,
        job_type: str,
        payload: Dict[str, Any],
        priority: int = 5,
        backend: Optional[str] = None,
        force_node: Optional[str] = None,
        min_vram_gb: float = 0.0,
        timeout_sec: int = 300,
        max_retries: int = 2,
    ) -> str:
        """Submit a job to the queue.

        Raises:
            ValueError: `job_type` is not something a node-agent can execute.

        Returns:
            job_id
        """
        # Fail closed. This queue is drained by node-agents, so a type with
        # no case in their executor can only be dispatched and abandoned —
        # which is exactly how `test_run` (a gateway-local type) used to rot
        # for minutes before the reaper noticed. JobType mirrors the
        # authoritative table in gateway-rust/src/job_types.rs; the two are
        # pinned together by tests/test_job_type_declarations.py.
        if job_type not in {t.value for t in JobType}:
            valid = ", ".join(sorted(t.value for t in JobType))
            raise ValueError(
                f"unknown job type '{job_type}' — no node can execute it. "
                f"Valid types: {valid}"
            )

        job_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        job = {
            "id": job_id,
            "type": job_type,
            "payload": json.dumps(payload),
            "priority": str(priority),
            "status": JobStatus.QUEUED.value,
            "created_at": now,
            "updated_at": now,
            "dispatched_at": "",
            "completed_at": "",
            "node_id": "",
            "result": "",
            "error": "",
            "retries": "0",
            "max_retries": str(max_retries),
            "timeout_sec": str(timeout_sec),
            "force_node": force_node or "",
            "min_vram_gb": str(min_vram_gb),
            "backend": backend or "",
        }

        pipe = self.redis.pipeline()
        # Store the full job record as a hash
        pipe.hset(f"{JOB_KEY_PREFIX}{job_id}", mapping=job)
        # Add to priority queue (score = -priority so higher priority pops first)
        pipe.zadd(QUEUE_KEY, {job_id: -priority})
        # Track in active set
        pipe.sadd(ACTIVE_SET, job_id)
        pipe.execute()

        logger.info("job_submitted", job_id=job_id, type=job_type, priority=priority)
        return job_id

    # ── Job Queries ─────────────────────────────────────────────────

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get full job record from Redis hash."""
        data = self.redis.hgetall(f"{JOB_KEY_PREFIX}{job_id}")
        if not data:
            return None
        # Deserialize payload back to dict
        if data.get("payload"):
            try:
                data["payload"] = json.loads(data["payload"])
            except (json.JSONDecodeError, TypeError):
                pass
        return data

    def list_jobs(
        self,
        status: Optional[str] = None,
        node_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List jobs with optional filters."""
        # Get active job IDs
        active_ids = self.redis.smembers(ACTIVE_SET)
        # Also get queued IDs
        queued_ids = self.redis.zrange(QUEUE_KEY, 0, -1)
        all_ids = active_ids | set(queued_ids)

        jobs = []
        for jid in all_ids:
            job = self.redis.hgetall(f"{JOB_KEY_PREFIX}{jid}")
            if not job:
                continue
            if status and job.get("status") != status:
                continue
            if node_id and job.get("node_id") != node_id:
                continue
            jobs.append(job)

        # Sort by created_at descending
        jobs.sort(key=lambda j: j.get("created_at", ""), reverse=True)
        return jobs[:limit]

    def get_queue_depth(self) -> int:
        """Number of jobs waiting in queue."""
        return self.redis.zcard(QUEUE_KEY)

    # ── Job Control ─────────────────────────────────────────────────

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a job. Returns True if cancelled, False if not found or already terminal."""
        job = self.get_job(job_id)
        if not job:
            return False

        current_status = job.get("status")
        if current_status in {s.value for s in TERMINAL_STATES}:
            return False

        now = datetime.now(timezone.utc).isoformat()
        pipe = self.redis.pipeline()
        pipe.hset(f"{JOB_KEY_PREFIX}{job_id}", mapping={
            "status": JobStatus.CANCELLED.value,
            "updated_at": now,
            "completed_at": now,
        })
        # Remove from queue if still queued
        pipe.zrem(QUEUE_KEY, job_id)
        # Remove from active set
        pipe.srem(ACTIVE_SET, job_id)
        # Remove from node's job set if dispatched
        node_id = job.get("node_id")
        if node_id:
            pipe.srem(f"{NODE_JOBS_PREFIX}{node_id}", job_id)
        pipe.execute()

        # Notify node via NATS if dispatched
        if node_id and self._messaging and self._messaging.is_connected:
            asyncio.ensure_future(self._notify_cancel(job_id, node_id))

        logger.info("job_cancelled", job_id=job_id)
        return True

    async def _notify_cancel(self, job_id: str, node_id: str):
        """Send cancellation event via NATS."""
        try:
            await self._messaging.publish_event("job.cancel", {
                "job_id": job_id,
                "node_id": node_id,
            })
        except Exception as e:
            logger.warning("cancel_notify_failed", job_id=job_id, error=str(e))

    def reprioritize_job(self, job_id: str, new_priority: int) -> bool:
        """Change priority of a queued job."""
        job = self.get_job(job_id)
        if not job or job.get("status") != JobStatus.QUEUED.value:
            return False

        pipe = self.redis.pipeline()
        pipe.hset(f"{JOB_KEY_PREFIX}{job_id}", mapping={
            "priority": str(new_priority),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        # Update queue score
        pipe.zadd(QUEUE_KEY, {job_id: -new_priority})
        pipe.execute()

        logger.info("job_reprioritized", job_id=job_id, priority=new_priority)
        return True

    # ── Scheduler Controls ──────────────────────────────────────────

    def pause(self):
        """Pause dispatching. Existing jobs continue running.

        Sets a Redis flag so the Rust gateway can also read/write pause state.
        """
        self._paused = True
        try:
            self.redis.set(PAUSED_KEY, "1")
        except Exception:
            pass  # best-effort — in-memory flag still works
        logger.info("scheduler_paused")

    def resume(self):
        """Resume dispatching.

        Clears the Redis pause flag so the Rust gateway sees the change.
        """
        self._paused = False
        try:
            self.redis.delete(PAUSED_KEY)
        except Exception:
            pass  # best-effort — in-memory flag still works
        logger.info("scheduler_resumed")

    @property
    def is_paused(self) -> bool:
        # Check Redis flag first (may have been set by Rust gateway)
        try:
            val = self.redis.get(PAUSED_KEY)
            redis_paused = val == "1" if val else False
            # Sync in-memory flag with Redis state
            if redis_paused != self._paused:
                self._paused = redis_paused
        except Exception:
            pass  # fall back to in-memory flag
        return self._paused

    def drain_node(self, node_id: str):
        """Drain a node — no new jobs dispatched to it. Existing jobs finish."""
        self.redis.sadd(DRAINED_KEY, node_id)
        logger.info("node_drained", node_id=node_id)

    def undrain_node(self, node_id: str):
        """Undrain a node — allow new jobs again."""
        self.redis.srem(DRAINED_KEY, node_id)
        logger.info("node_undrained", node_id=node_id)

    def is_node_drained(self, node_id: str) -> bool:
        return self.redis.sismember(DRAINED_KEY, node_id)

    def get_status(self) -> Dict[str, Any]:
        """Scheduler state summary."""
        active_count = self.redis.scard(ACTIVE_SET)
        queue_depth = self.get_queue_depth()
        drained = list(self.redis.smembers(DRAINED_KEY))

        # Count background jobs in queue (score = 0, meaning priority = 0)
        bg_queued = self.redis.zrangebyscore(QUEUE_KEY, 0, 0)
        bg_queue_depth = len(bg_queued) if bg_queued else 0

        return {
            # `running` means "THIS process dispatches", and after phase 7
            # it never does — dispatch is a Rust loop in another process,
            # whose liveness this one cannot observe. The Rust
            # /api/scheduler/status reports the real answer from
            # loop_health; claiming anything here would be a guess.
            "running": False,
            # No loop of any kind runs here since the 2026-08-09 sweep
            # (the producer poll was the last one, and it polled an empty
            # registry). Kept as a literal so status consumers keep their
            # key; the real loop health is Rust /api/scheduler/status.
            "loop_alive": False,
            "engine": "rust",
            "running_detail": (
                "dispatch is owned by gateway-rust scheduler_engine; this "
                "process serves the job CRUD surface only"
            ),
            "paused": self.is_paused,
            "queue_depth": queue_depth,
            "active_jobs": active_count,
            "drained_nodes": drained,
            "background_queue_depth": bg_queue_depth,
            # The lifecycle consumer is scheduler_completions.rs. The health
            # of a listener this process deliberately never starts is not
            # ours to report — `None` says "not mine", not "broken".
            "completions_owner": "rust",
            "completions_healthy": None,
            "history_size": self.redis.llen(HISTORY_KEY),
        }

    # ── Job History (read-only) ────────────────────────────────────

    def get_job_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent job history (survives TTL expiry).

        Read-only: `scheduler_engine::terminalize()` in Rust is the sole
        writer of `noo:jobs:history`, in the same atomic step that flips a
        job terminal. Two writers would give every job two rows.
        """
        raw = self.redis.lrange(HISTORY_KEY, 0, limit - 1)
        return [json.loads(r) for r in raw]


# Global instance
_scheduler: Optional[JobScheduler] = None


def get_scheduler() -> Optional[JobScheduler]:
    """Get global scheduler instance (may be None if not initialized)."""
    return _scheduler


def init_scheduler(redis_url: str = "rediss://redis:6379") -> JobScheduler:
    """Initialize and return the global scheduler."""
    global _scheduler
    _scheduler = JobScheduler(redis_url)
    return _scheduler
