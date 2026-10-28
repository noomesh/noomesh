# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Python worker pool — NATS-based service handlers.

When the Rust gateway is active, these workers handle the "smart" work
(RAG, graph, recall memory, embeddings, channels, settings, autonomy, etc.)
via NATS request/reply. The Rust gateway delegates to these workers
instead of calling Python directly.

When the Python gateway is active, these workers are NOT needed — the
gateway calls the services directly in-process.

Usage (standalone worker mode)::

    python -m noomesh.gateway.worker_pool

Two supervisors exist (WP-T23 phase 1):

- ``NOO_WORKER_SUPERVISOR=inprocess`` (default): the Rust gateway spawns and
  supervises this module as a child process (main.rs) — respawn on exit,
  RSS-ceiling restarts.
- ``NOO_WORKER_SUPERVISOR=external``: a separate container (compose service
  ``trellion`` → ``noo-trellion``) runs this module. Docker's restart policy
  replaces respawn; the compose ``mem_limit`` + the in-process RSS
  self-watchdog below replace the supervisor's RSS ceiling; the ``/health``
  listener (:8090, container-internal) feeds the compose healthcheck.

This module is supervisor-agnostic: it self-connects NATS (retry=True),
self-initializes services, serves /health, and enforces its own RSS ceiling.

Protocol: see GATEWAY_CONTRACT.md and gateway-rust/PORTING_GUIDE.md.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import structlog

from .. import json_fast as json
from ..cluster import reply_ledger
from . import bus_principal, inflight

log = structlog.get_logger(__name__)

# ── Handler registry ────────────────────────────────────────────────
# Handler implementations live in noomesh.workers.* (one module per
# domain), registered via the @worker_handler decorator. Importing the
# package populates the registry (see noomesh/workers/__init__.py —
# that import IS the discovery mechanism). This module is only the
# orchestration shell: NATS connection, subscriptions, concurrency
# tiers, service init, and the reply envelope.
from .. import workers as _workers  # noqa: F401 — registers all @worker_handler subjects
from ..workers.registry import all_handlers, get_handler

# Backward-compat re-exports — these names lived here before the
# 2026-07-14 split and are imported by gateway/exec_approval.py and
# tests/test_kb_teams.py. (The users-proposal trio left with the 2026-08-08
# reference sweep: _users_propose/_validate_user_proposal/_users_admin_error
# were removed (history in git log before 2026-08-08) — the flow is
# native Rust, routes/users.rs.)
from ..workers.common import (  # noqa: F401
    _get_conversation_store,
    _get_coordinator,
    _get_rag,
    _trellion_engine,
    _unwrap_body,
)
from ..workers.kb import _TEAM_NAME_RE  # noqa: F401
from ..workers.users import _notify_exec_approval  # noqa: F401


# ─── Concurrency model (proposal: 2026-04-30) ──────────────────────────
#
# Three dispatch tiers, used by start_worker_pool() based on subject:
#
#   1. Priority      → _handle_priority_request — fire-and-forget task,
#                      no backpressure cap. For real-time hot paths only
#                      (chat, inference, cluster ops).
#   2. Concurrent    → _handle_concurrent — fire-and-forget task BOUNDED
#                      by a global semaphore + optional per-subject
#                      semaphore. Default for everything not-priority.
#                      Replaces the old "sequential per subscription"
#                      mode that caused head-of-line blocking when the
#                      graph_extractor's worker.temporal.extract floods
#                      stalled lighter subjects (autonomy, recall, etc.).
#   3. Inline (legacy) → _handle_request — used only as the actual worker
#                        body called by the wrappers above.
#
# Tune via env vars:
#   NOO_WORKER_GLOBAL_CONCURRENCY  (default 32) — total in-flight cap
#   per-subject limits in _PER_SUBJECT_LIMITS below

from ..config import env_or_yaml as _env_or_yaml

# One queue group for every worker replica. The name is
# shared by the core worker and the ML worker on purpose: a subject is
# served by whichever replicas registered a handler for it, and the group
# guarantees one delivery per message across them.
WORKER_QUEUE_GROUP = "workers"

_GLOBAL_SEM_CAPACITY = int(_env_or_yaml(
    "NOO_WORKER_GLOBAL_CONCURRENCY", lambda c: c.worker.global_concurrency, 32))
_global_sem: Any = None  # lazy-init in the event loop (asyncio.Semaphore)

# Tighter per-subject caps for handlers that are slow + can flood.
# Keys are subject prefixes (matched with str.startswith). Anything
# not matched is bounded only by the global semaphore.
_PER_SUBJECT_LIMITS: dict[str, int] = {
    "worker.temporal.extract": 2,   # LLM-heavy graph extraction (~30-60s each)
    "worker.embedding.":       4,   # embedding requests
    "worker.rag.ingest":       2,   # PDF parse + chunk + embed pipeline
    "worker.recall.":          4,   # episodic-recall ops (pgvector search, lifecycle)
}
_per_subject_sems: dict[str, Any] = {}

# Priority subjects — run in their own asyncio.Task so they never
# block behind long-running background jobs (entity extraction, etc.).
# Module-level (not local to start_worker_pool) so tests can assert a
# user-facing subject actually gets the priority tier.
_PRIORITY_PREFIXES = (
    "worker.cluster.",     # backend start/stop, provisioning
    # "worker.chat" and "worker.inference." left this list 2026-08-08:
    # worker.chat's handler was never registered here and its Rust route is
    # deleted; worker.inference.task (the last worker.inference.* subject)
    # is native Rust (routes/inference.rs submit_inference_task).
    "worker.compat.",      # OpenAI-compatible API
    "worker.auth.",        # authentication
    "worker.settings.",    # settings (gateway restart, etc.)
    # Trellion snapshots — consolidations can take
    # 30s-5min; running them sequentially through _handle_request blocks
    # subsequent fast snapshot requests (list/get/curriculum) behind the
    # slow consolidate. Priority dispatch puts each request in its own
    # asyncio task so they don't queue.
    "worker.api.snapshots",
    # Autonomy NATS dispatchers (Rust autonomy_loop calls these every
    # 5-10 min). Most autonomy checks now run as native Rust SQL
    # against the shared Postgres (no NATS hop needed) — but if any
    # autonomy condition genuinely requires a Python ML check in the
    # future, this priority prefix keeps it from queueing behind the
    # graph_extractor / temporal_extract floods. Cheap insurance.
    "worker.autonomy.",
    # Heartbeat delegation (Rust heartbeat_loop owns cron firing and calls
    # this for every action NOT in RUST_NATIVE_ACTIONS / RUST_LLM_ACTIONS —
    # i.e. Python is the DEFAULT path, not an exception: graph_signals,
    # thought_experiment, rag_reindex and anything not yet ported).
    #
    # Same starvation as the neighbours above, but with teeth: a scheduled
    # task that misses its slot does not retry — it is simply skipped until
    # the next cron tick, and the user gets "could not be dispatched … the
    # task did not run". Observed 2026-07-30 for graph_signals, where the
    # request sat behind temporal.extract work (~30-60s each) until Rust's
    # 120s NATS deadline (NOO_WORKER_TIMEOUT_SECS) elapsed.
    #
    # A slow ML action still occupies its own task once started; this only
    # stops the DISPATCH from queueing behind unrelated background floods.
    "worker.api.heartbeat",
    # Cluster discovery + proposals — kept on the SEQUENTIAL handler
    # for now. Priority dispatch via tokio::spawn was created here
    # but the spawned task never executed in practice (msg received,
    # handler body never ran, no logs). Sequential path works fine
    # for the proposals/list endpoints; discover is bounded by the
    # 30s timeout in _cluster_discover so a hang can't pin the queue.
    # TODO: investigate why priority dispatch failed for cluster.*
    # "worker.api.cluster.",
)


def _is_priority_subject(subject: str) -> bool:
    """True when *subject* dispatches on the unbounded priority tier."""
    return any(subject.startswith(p) for p in _PRIORITY_PREFIXES)


def _get_subject_sem(subject: str) -> Any:
    """Return the matching per-subject Semaphore, or None if no limit."""
    import asyncio
    for prefix, limit in _PER_SUBJECT_LIMITS.items():
        if subject.startswith(prefix):
            sem = _per_subject_sems.get(prefix)
            if sem is None:
                sem = asyncio.Semaphore(limit)
                _per_subject_sems[prefix] = sem
            return sem
    return None


# ── Refusal audit (rate-limited) ──────────────────────────────────────
#
# A refused message is a security event, and a bus under a replay attempt
# produces them faster than any sink wants. One audit row + one log line per
# (subject, reason) per minute, with the suppressed count carried on the next
# one — so a flood is visible as a flood rather than as 40k rows.
_REFUSAL_WINDOW_SECS = 60.0
_refusal_last: "dict[tuple[str, str], float]" = {}
_refusal_suppressed: "dict[tuple[str, str], int]" = {}


def _audit_principal_refusal(subject: str, exc: Exception) -> None:
    import time as _time

    reason = getattr(exc, "reason", "refused")
    detail = getattr(exc, "detail", str(exc))
    key = (subject, reason)
    now = _time.monotonic()
    last = _refusal_last.get(key, 0.0)
    if last and now - last < _REFUSAL_WINDOW_SECS:
        _refusal_suppressed[key] = _refusal_suppressed.get(key, 0) + 1
        return
    suppressed = _refusal_suppressed.pop(key, 0)
    _refusal_last[key] = now

    log.warning(
        "bus_principal.refused",
        subject=subject,
        reason=reason,
        detail=detail[:200],
        suppressed=suppressed,
    )
    try:
        from .audit_log import audit

        audit(
            "bus_principal_refused",
            severity="warning",
            actor="bus",
            resource=subject,
            outcome=reason,
            detail=detail[:500],
            suppressed=suppressed,
        )
    except Exception:  # noqa: BLE001 — the refusal already happened
        pass


def error_text(e: BaseException) -> str:
    """What a handler's failure says: its message, or else its type.

    ``str(e)`` is empty for a bare ``assert`` and many library errors, and a
    blank error reached the operator as ``Worker error on worker.rag.query: ``
    (0.6.13-rc.2/rc.3 rehearsal). A non-empty message is kept exactly: the
    gateway and clients match on some of them.
    """
    return str(e) if str(e).strip() else type(e).__name__


def error_reply(e: Exception) -> dict:
    """The bus reply for a handler that raised.

    A handler that REFUSED on purpose names the kind (structured, never
    message text) so the gateway can answer a 4xx rather than a 503. An old
    gateway ignores the extra key; an old worker never sends it.
    """
    response = {"success": False, "error": error_text(e)}
    kind = getattr(e, "error_kind", None)
    if isinstance(kind, str):
        response["error_kind"] = kind
    return response


async def _handle_request(msg) -> None:
    """Inner request handler — parses, dispatches to the registered
    handler, publishes the reply. Always awaited from one of the
    wrappers below (never used as a NATS callback directly anymore)."""
    # Owed from the moment it arrived, so a refused reply can be named (i69).
    reply_ledger.received(msg.reply, msg.subject)
    try:
        request = json.loads(msg.data.decode())
    except Exception:
        if msg.reply:
            await msg.respond(json.dumps({"error": "invalid JSON"}).encode())
        return

    subject = msg.subject

    # ── Who is this from? ───────────────────
    #
    # Before the dispatch, not inside it. The bus GRANT says only the
    # gateway may publish `worker.>`; it says nothing about whose behalf a
    # given message is on, and every handler below used to take that from
    # the body it was handed. A message with no principal, a bad signature,
    # a stale one, or one signed for a different subject is REFUSED with a
    # reply error and audited — it is never served with the payload's own
    # account of itself.
    try:
        principal = bus_principal.verify_message(msg.headers, subject)
        request = bus_principal.apply_to_request(request, principal)
    except bus_principal.PrincipalError as exc:
        _audit_principal_refusal(subject, exc)
        if msg.reply:
            await msg.respond(
                json.dumps(
                    {"success": False, "error": f"bus principal refused: {exc.detail}"}
                ).encode()
            )
        return

    handler = get_handler(subject)

    if not handler:
        if msg.reply:
            await msg.respond(json.dumps({"error": f"no handler for {subject}"}).encode())
        return

    try:
        with inflight.tracked():
            result = await handler(request)
        response = {"success": True, "data": result}
    except Exception as e:
        # With the traceback: the reply carries only the text, so this line
        # is the one place that says where it failed.
        log.warning("worker.handler_error", subject=subject, error=error_text(e), exc_info=True)
        response = error_reply(e)

    if msg.reply:
        await msg.respond(json.dumps(response).encode())


async def _bounded_handle(msg) -> None:
    """Run _handle_request inside global + (optional) per-subject
    semaphores. Provides backpressure: total in-flight handlers ≤
    NOO_WORKER_GLOBAL_CONCURRENCY, and slow subjects can't dominate."""
    import asyncio
    global _global_sem
    if _global_sem is None:
        _global_sem = asyncio.Semaphore(_GLOBAL_SEM_CAPACITY)

    subject_sem = _get_subject_sem(msg.subject)
    async with _global_sem:
        if subject_sem is not None:
            async with subject_sem:
                await _handle_request(msg)
        else:
            await _handle_request(msg)


async def _handle_concurrent(msg) -> None:
    """Default dispatch: spawn handler as a bounded task. Replaces the
    old sequential `_handle_request` callback, which serialized all
    non-priority subjects within a single subscription. Bounded by the
    global + per-subject semaphores in `_bounded_handle`."""
    import asyncio
    asyncio.create_task(_bounded_handle(msg))


async def _handle_priority_request(msg) -> None:
    """Priority handler — fire-and-forget task with NO backpressure.
    Use sparingly for true real-time paths (chat, inference, cluster
    ops) where queueing behind the global semaphore would be visible
    to a user. Most subjects should use _handle_concurrent instead."""
    import asyncio
    asyncio.create_task(_handle_request(msg))


# ═══════════════════════════════════════════════════════════════════════
# RAG handlers
# ═══════════════════════════════════════════════════════════════════════


def _configured_audit_log_file() -> "str | None":
    """``security.audit_log_file`` from the config, or ``None`` when the
    config does not load — the audit logger still comes up on its other sinks."""
    try:
        from ..config import get_config

        return getattr(getattr(get_config(), "security", None), "audit_log_file", None)
    except Exception as exc:
        log.warning("worker_pool.audit_log_file_config_unreadable", error=str(exc)[:200])
        return None


#: Inits that need the trellion package, skipped on a surfaces=core worker.
_ML_PACK_INITS = (
    "trellion_engine", "conversation_store", "rag", "memory_system",
    "retrieval_tracker", "recall_memory",
)


#: Set once the pool has subscribed; makes `start_worker_pool` idempotent.
_pool_started = False


def _worker_surfaces() -> str:
    return (os.getenv("NOO_WORKER_SURFACES") or "all").strip().lower()


def _serves_ml_pack() -> bool:
    """False only on the slim ``core`` worker, which has no trellion package.

    Mirrors the gate in ``workers/__init__.py``: ``all``/``ml``/``ml-intel``
    (and unknown values, which fall back to ``all``) are ML-capable.
    """
    return _worker_surfaces() != "core"


def _log_code_source() -> None:
    """One boot line that says WHICH Python is actually running.

    The 2026-08-09 saga shipped three dist releases whose Python fixes
    never ran: the host checkout's ./src bind mount silently won over the
    released image's code while the checkout was stale. Dist mode now
    neutralizes the overlay (launcher repoints its dest), and this line
    makes any drift observable at a glance:

        worker.code_source path=… overlay_mounted=… fingerprint=…

    overlay_mounted=True in a dist install IS the bug. The fingerprint is
    a cheap stat-based digest (names+sizes+mtimes of the package's .py
    files) — enough to tell two code states apart, not a content hash.
    """
    import hashlib

    import noomesh

    pkg_dir = os.path.dirname(os.path.abspath(noomesh.__file__))
    overlay_mounted = False
    try:
        with open("/proc/mounts", encoding="utf-8", errors="replace") as fh:
            overlay_mounted = any(" /app/src " in line for line in fh)
    except OSError:
        pass

    digest = hashlib.sha256()
    try:
        for root, dirs, files in os.walk(pkg_dir):
            dirs.sort()
            for name in sorted(files):
                if not name.endswith(".py"):
                    continue
                path = os.path.join(root, name)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                digest.update(f"{path}:{st.st_size}:{int(st.st_mtime)}".encode())
    except OSError:
        pass

    log.info(
        "worker.code_source",
        path=pkg_dir,
        overlay_mounted=overlay_mounted,
        fingerprint=digest.hexdigest()[:8],
    )


# ═══════════════════════════════════════════════════════════════════════
# Worker pool startup
# ═══════════════════════════════════════════════════════════════════════

async def start_worker_pool(messaging: Any) -> None:
    """Subscribe to all worker subjects and start handling requests.

    Called at gateway startup (both Python and Rust modes).
    In Python mode, this is optional (direct calls are faster).
    In Rust mode, this is required (only way to reach Python services).
    """
    global _pool_started
    if messaging is None:
        # Not a pool start at all. trellion's ``PageIndexRAG.startup()`` calls
        # this with its own (unset) messaging handle, from inside
        # ``_init_python_services`` and so before ``main()`` below starts the
        # real pool on its connected handle. Live 2026-10-10 00:48 on host8:
        # that call logged `worker_pool.no_nats` at WARNING on every start of
        # noo-trellion and noo-trellion-intel, a fraction of a second before
        # the same process subscribed every subject. A warning that fires on
        # every healthy start teaches the operator to skip the one that
        # matters.
        log.debug("worker_pool.start_skipped", reason="no messaging handle (embedded caller)")
        return
    if _pool_started:
        # Idempotent: a second call with a live handle would subscribe every
        # subject twice, and the queue group would then hand this process
        # twice its share of requests.
        log.debug("worker_pool.start_skipped", reason="already started")
        return
    if not messaging.is_connected:
        # A real handle with no bus under it: the pool would register zero
        # subscribers and every gateway call routed here gets "no responders".
        log.warning(
            "worker_pool.no_nats",
            message="NATS not connected; the pool registers no subscribers",
        )
        return

    _log_code_source()

    # A surfaces=core noo-worker runs WITHOUT the trellion package by design
    # (Dockerfile.worker: no torch, no noo-trellion). The ML-pack inits below
    # (trellion engine, conversation store, RAG, memory, retrieval tracker,
    # recall memory) can only fail there, and logging each as a warning buries
    # a real failure under expected noise. Skip them and say so once.
    ml_pack = _serves_ml_pack()
    if not ml_pack:
        log.info(
            "worker_pool.ml_pack_init_skipped",
            surfaces=_worker_surfaces(),
            skipped=list(_ML_PACK_INITS),
            reason="served by the noo-trellion container, not this one",
        )

    # Eagerly initialise trellion's engine so the snapshots handlers don't pay
    # a cold-start postgres-connection cost on their first NATS reply (which
    # easily exceeds the 120s NATS request deadline on a slow box).
    if ml_pack:
        try:
            _trellion_engine()
            log.info("worker_pool.trellion_engine_warm")
        except Exception as exc:
            log.warning("worker_pool.trellion_engine_warm_failed", error=str(exc)[:200])

    # Initialise the security audit logger in THIS (live) process. Previously
    # `init_audit_logger` ran only in app.py's FastAPI lifespan, which does not
    # execute under the Rust gateway — so every Python-emitted security event
    # (exec approvals/denials, cluster_auth_failure, path_traversal, ...) was
    # silently dropped (CRIT-5). Wire the
    # structlog + file sinks (always) plus the DB sink on the app role's own
    # engine (`audit_sink_engine`): trellion's engine is the scoped
    # noo_trellion role and cannot see mesh.noo_security_audit. The file
    # path may come from the config, but a config that fails validation
    # must not take the audit trail down with it.
    try:
        from .audit_log import audit_sink_engine, init_audit_logger, audit

        _audit_file = os.getenv("NOO_AUDIT_LOG_FILE") or _configured_audit_log_file()
        _sink_engine, _sink_reason = audit_sink_engine()
        init_audit_logger(log_file=_audit_file, async_engine=_sink_engine)
        log.info(
            "worker_pool.audit_logger_initialized",
            file=_audit_file or "none",
            db_sink=bool(_sink_engine),
            db_sink_reason=_sink_reason,
        )
        # Startup marker — proves the sink is live and gives a "first row" so an
        # empty noo_security_audit is distinguishable from an unwired logger.
        audit(
            "audit_logger_started",
            severity="info",
            actor="worker_pool",
            resource="gateway",
            outcome="ok",
        )
    except Exception as exc:
        log.warning("worker_pool.audit_logger_init_failed", error=str(exc)[:200])

    nc = messaging.nc
    if not nc:
        return

    # Store on services singleton for NATS KV access by handlers
    from .deps import services
    services.messaging = messaging

    # Handler registry — every subject the Rust gateway delegates to has an
    # explicit handler function, registered via @worker_handler in the
    # noomesh.workers.* domain modules (imported eagerly at module load;
    # see noomesh/workers/__init__.py). Subjects ported to native Rust are
    # documented next to their (unregistered) reference handlers in those
    # modules. No ASGI routing through FastAPI.
    handlers = all_handlers()

    # Subscribe to all explicit worker subjects.
    # Dispatch tier:
    #   - Priority (real-time hot paths) → unbounded concurrent task
    #   - Default (everything else)      → concurrent task bounded by
    #                                      global + per-subject semaphores
    # The old "non-priority = sequential" mode caused head-of-line blocking
    # when slow handlers (graph_extractor) starved fast ones (autonomy,
    # recall). Bounded concurrency replaces it; backpressure is preserved
    # via NOO_WORKER_GLOBAL_CONCURRENCY + _PER_SUBJECT_LIMITS.
    for subject in handlers:
        is_priority = _is_priority_subject(subject)
        cb = _handle_priority_request if is_priority else _handle_concurrent
        # QUEUE GROUP, always. Without it NATS fans a
        # request out to EVERY subscriber, so a second worker replica would
        # execute every tool call a second time — two side effects, two
        # audit rows, one reply that raced. In a queue group the server
        # delivers each message to exactly one member, which is what makes
        # `NOO_WORKER_EXTRA=<n>` a scale-out rather than an incident.
        await nc.subscribe(subject, queue=WORKER_QUEUE_GROUP, cb=cb)
        if is_priority:
            log.info("worker_pool.subscribed", subject=subject, priority=True)

    # No `worker.>` wildcard subscription.
    #
    # It existed as a migration safety net, and it actively hid problems: NATS
    # delivers to wildcard subscribers too, so EVERY worker.* subject had a
    # responder whether or not a handler existed. An unimplemented subject was
    # absorbed here instead of failing, which made "is this wired up?"
    # unanswerable from the outside — the tool/ledger preflight checks have to
    # exclude wildcards for exactly this reason.
    #
    # It could not serve anything either: its last resort was
    # `from .app import app`, and gateway/app.py was deleted in the Rust port.
    # In the 24h before removal it fired twice, both for
    # worker.api.v1.video-memory.stats (a retired subject) — a caller hitting a dead endpoint and
    # getting an error, which is what it will now get honestly and promptly.
    _pool_started = True
    log.info("worker_pool.started", handlers=len(handlers))


# `_publish_tool_schemas` was removed. It wrote Pydantic ToolDef schemas to
# the NATS KV bucket `tool_schemas`, documented as "replaces static
# tools.json" — but the Rust gateway never read that bucket. It loads
# config/tools.json from disk (state.rs::load_tool_schemas_cached), and both
# its tool_schemas and tools_json_raw caches come from that one file. The
# publish was dead, and its docstring described an architecture that does not
# exist.

def _init_retrieval_tracker() -> None:
    """Start the Intelligent tier's retrieval tracker where that tier is installed.

    The tracker is the add-on's ``retrieval_tracker_init`` role, reached through
    trellion's provider seam. On the open tier the add-on is absent BY
    DESIGN, so that is one info line, not a failure.

    A tier that is installed and still cannot start the tracker stays a
    warning: that is the loss of function.
    """
    try:
        from trellion.live._intel import intel_available
        from ..addon_roles import RETRIEVAL_TRACKER_INIT, provider
    except ImportError as e:
        log.warning("worker.retrieval_tracker_init_failed",
                    error=f"trellion add-on seam unavailable: {e}")
        return
    if not intel_available():
        log.info(
            "worker.retrieval_tracker_skipped",
            reason="Intelligent tier (noo-trellion-intel) not installed in this container",
        )
        return
    try:
        provider(RETRIEVAL_TRACKER_INIT)(persist_path=os.getenv("RETRIEVAL_TRACKER_PATH"))
        log.info("worker.retrieval_tracker_initialized")
    except Exception as e:
        log.warning("worker.retrieval_tracker_init_failed", error=str(e))


async def _init_python_services(messaging) -> None:
    """Initialize Python services that the FastAPI lifespan normally handles.

    When Rust is the primary gateway, the Python app is loaded as an ASGI
    module but its lifespan never runs. We need to initialize the services
    that NATS-delegated routes depend on (channels, settings store, etc.).
    """
    from .deps import services

    # See start_worker_pool: the slim core worker has no trellion package.
    ml_pack = _serves_ml_pack()

    # Exec-approval manager — the FastAPI lifespan normally initializes
    # this from config; without it, the coordinator-in-worker gate falls
    # back to a default manager (mode=auto, DEFAULT_RISK_MAP) and the
    # configured mode/timeout/risk lists are silently ignored. The
    # callback notifies the approval channels when a HIGH-risk call opens
    # a window.
    try:
        from ..config import get_config
        from .exec_approval import ExecApprovalManager, init_approval_manager
        sec = get_config().security
        # POSTURE-ONLY: NOO_EXEC_APPROVAL_MODE, which posture.py
        # writes into this process's env from the DB, with .env as the
        # bootstrap fallback. No YAML tier — `security.exec_approval_mode` is
        # retired and SecurityConfig now refuses a config that still sets it.
        # Unset means `strict`, the same fail-closed default as the Rust gate
        # (middleware::DEFAULT_EXEC_APPROVAL_MODE); it used to mean `auto`.
        _mode = (
            os.getenv("NOO_EXEC_APPROVAL_MODE", "").strip()
            or ExecApprovalManager.DEFAULT_MODE
        )
        init_approval_manager(
            mode=_mode,
            timeout=sec.exec_approval_timeout,
            high_risk_tools=sec.high_risk_tools,
            medium_risk_tools=sec.medium_risk_tools,
            approval_callback=_notify_exec_approval,
        )
        log.info("worker_exec_approval_initialized", mode=_mode)
    except Exception as e:
        log.warning("worker_exec_approval_init_failed", error=str(e))

    # Channels — outbound goes through the RUST GATEWAY since port-lane
    # item 8: GatewayChannelClient POSTs /api/channels/send
    # with a cluster-HMAC bearer instead of dispatching through in-process
    # Python adapters. Those adapters stopped receiving inbound traffic at
    # a prior change, so this retires the last live use of them (and the
    # stats-persistence loop, which by then was counting only Python-side
    # sends — the Rust pipeline never incremented it). Consumers keep the
    # same access points: services.channel_manager and the channels.manager_ref
    # global, both of which now hold the client.
    try:
        from ..channels.gateway_client import GatewayChannelClient
        from ..channels.manager_ref import set_channel_manager

        channel_client = GatewayChannelClient()
        set_channel_manager(channel_client)
        services.channel_manager = channel_client
        log.info("worker.channels_initialized", channels=channel_client.list_channels(), via="gateway")
    except Exception as e:
        log.warning("worker.channels_init_failed", error=str(e))

    # Coding-task manager — the deleted FastAPI lifespan used to own this
    # singleton, and under the Rust gateway NOTHING constructed it, so
    # get_coding_manager() returned None and every noo_coding_task submit
    # died with "Coding manager not initialized" before the env gate or
    # the earlier sandbox path was even consulted. Found while rewiring
    # channels (port-lane item 8, 2026-08-11).
    try:
        from .coding_tool import CodingTaskManager
        coding_manager = CodingTaskManager()
        coding_manager.set_channel_manager(getattr(services, "channel_manager", None))
        services.coding_manager = coding_manager
        log.info("worker.coding_manager_initialized")
    except Exception as e:
        log.warning("worker.coding_manager_init_failed", error=str(e))

    # Settings store — needed for /api/settings
    try:
        from .settings_store import SettingsStore
        settings_store = SettingsStore()
        services.settings_store = settings_store
        log.info("worker.settings_store_initialized")
    except Exception as e:
        log.warning("worker.settings_store_init_failed", error=str(e))

    # Conversation store — needed for memory endpoints + coordinator context
    dsn = os.getenv("PAGEINDEX_DSN") or os.getenv("DATABASE_URL", "")
    if ml_pack and (not hasattr(services, 'conversation_store') or not services.conversation_store):
        try:
            from ..memory.conversation_store import ConversationStore
            if dsn:
                cs = ConversationStore(dsn=dsn)
                services.conversation_store = cs
                log.info("worker.conversation_store_initialized")
        except Exception as e:
            log.warning("worker.conversation_store_init_failed", error=str(e))

    # Apply DB-authoritative security posture to this process's env (peer of the
    # Rust boot-load) BEFORE NATS subscriptions go live, so the Python gates
    # reflect the DB posture, not just .env. Best-effort.
    try:
        from ..posture import apply_security_posture as _apply_posture
        _store = getattr(services, "conversation_store", None)
        await _apply_posture(getattr(_store, "_engine", None))
    except Exception as e:
        log.debug("worker.security_posture_apply_failed", error=str(e))

    # PageIndex RAG — needed for /api/v1/rag/*, /api/v1/docs, /api/v1/graph/*
    # NOTE: rag_router uses GatewayState.pageindex_rag via DI (no set_rag_instance).
    # The worker sets services.pageindex_rag which the ASGI app picks up.
    if ml_pack:
        try:
            from ..memory.rag_integration import PageIndexRAG

            embedding_url = _env_or_yaml(
                "PAGEINDEX_EMBEDDING_URL", lambda c: c.services.embedding_url, "https://gateway:8080")
            embedding_backend = _env_or_yaml(
                "PAGEINDEX_EMBEDDING_BACKEND", lambda c: c.services.embedding_backend, "gateway")
            embedding_model = _env_or_yaml(
                "PAGEINDEX_EMBEDDING_MODEL", lambda c: c.services.embedding_model, "")
            # Through the gateway, as the `knowledge` purpose (i145): which
            # model answers is a preference in the DB, not an env value.
            from .. import llm_purposes
            llm_url = llm_purposes.gateway_url()
            llm_model = llm_purposes.KNOWLEDGE

            if dsn:
                rag = PageIndexRAG(
                    dsn=dsn,
                    embedding_url=embedding_url,
                    embedding_backend=embedding_backend,
                    embedding_model=embedding_model or None,
                    llm_url=llm_url,
                    llm_model=llm_model,
                )
                await rag.startup()
                services.pageindex_rag = rag
                log.info("worker.rag_initialized",
                         docs=getattr(rag, 'doc_count', '?'),
                         embedding=embedding_backend)
        except Exception as e:
            log.warning("worker.rag_init_failed", error=str(e))

        # Memory system — needed for /api/memory/status, search, etc.
        try:
            from ..memory.manager import MemorySystem, MemoryConfig
            if dsn and hasattr(services, 'conversation_store') and services.conversation_store:
                mem_config = MemoryConfig()
                mem = MemorySystem(config=mem_config, store=services.conversation_store)
                services.memory_system = mem
                log.info("worker.memory_system_initialized")
        except Exception as e:
            log.warning("worker.memory_system_init_failed", error=str(e))

    # Embedding worker — needed for /api/memory/embed/start|status|stop, batch-index
    try:
        embedding_url = _env_or_yaml(
            "PAGEINDEX_EMBEDDING_URL", lambda c: c.services.embedding_url, "https://gateway:8080")
        embedding_backend = _env_or_yaml(
            "PAGEINDEX_EMBEDDING_BACKEND", lambda c: c.services.embedding_backend, "gateway")
        if dsn and hasattr(services, 'conversation_store') and services.conversation_store:
            from ..memory.embedding_worker import EmbeddingWorker, EmbeddingConfig
            ew_config = EmbeddingConfig(
                embedding_base_url=embedding_url,
                embedding_backend=embedding_backend,
            )
            ew = EmbeddingWorker(
                config=ew_config,
                store=services.conversation_store,
            )
            services.embedding_worker = ew
            log.info("worker.embedding_worker_initialized")
    except Exception as e:
        log.warning("worker.embedding_worker_init_failed", error=str(e))

    # Backend manager — RETIRED here 2026-08-12 (port-lane item 10). The
    # /api/cluster/backends/start|stop routes are Rust-native, so nothing
    # live called this instance. It was also never published to the module
    # singleton (constructed directly, not via init_backend_manager), so
    # get_backend_manager() returned None the whole time the Rust gateway
    # has been primary — the Python heartbeat _idle_scaledown handler
    # (unreachable anyway; idle_scaledown is RUST_NATIVE) could never have
    # worked. cluster/backend_manager.py stays as reference only.

    # Heartbeat scheduler — needed for /api/heartbeat/run|webhook (NATS delegation)
    try:
        from .heartbeat import HeartbeatScheduler, HeartbeatConfig
        from .heartbeat_store import HeartbeatStore
        hs_store = HeartbeatStore(dsn=dsn) if dsn else None
        # Protocol-aware gateway base URL (TLS listener refuses http://).
        # _local_gateway_url honors NOO_GATEWAY_URL first, which is how the
        # standalone noo-trellion container reaches the gateway by service
        # name instead of 127.0.0.1 (WP-T23 phase 2).
        from .helpers import _local_gateway_url
        gateway_url = _local_gateway_url()
        hs = HeartbeatScheduler(
            config=HeartbeatConfig(),
            gateway_url=gateway_url,
            # Pass None so `_channel_message` falls through to its HTTP
            # fallback (`POST /api/channels/send`), which routes to the
            # Rust SA OAuth2 path. Avoids a second Python OAuth2 surface
            # in the cron delivery path.
            channel_dispatcher=None,
            # Wire the coordinator so research_report / chat_digest etc.
            # can call coordinator.run() instead of short-circuiting with
            # "coordinator not available."
            coordinator=_get_coordinator(),
            store=hs_store,
        )
        # The instance serves the worker.api.heartbeat.run/webhook NATS
        # handlers (CRUD + on-demand runs). It runs NO firing loop: the Rust
        # heartbeat_loop owns cron. The Python loop (and its
        # `GATEWAY_ENGINE=python` gate) was deleted — it was the second source
        # of the 2026-06-12 dual-fire bug and recomputed next_run in pure UTC.
        services.heartbeat_scheduler = hs
        # NB: deliberately do NOT publish `hs` to the module-level
        # `_scheduler` singleton in heartbeat.py. That would make
        # `_channel_message` use `dispatcher.dispatch` (the in-process
        # Python ChannelManager → GoogleChatAdapter Python OAuth2 path).
        # We want cron deliveries to go through the HTTP fallback —
        # `client.post(f"{self.gateway_url}/api/channels/send", ...)` —
        # which routes to Rust `send_google_chat` with native SA OAuth2.
        # Same OAuth2 implementation as inbound chat replies. Removes
        # the second OAuth2 implementation from the cron path.
        log.info("worker.heartbeat_scheduler_initialized")
    except Exception as e:
        log.warning("worker.heartbeat_scheduler_init_failed", error=str(e))

    # Job scheduler — the CRUD object behind /api/scheduler/* and
    # /api/jobs/submit. It does NOT drain the queue (dispatch is
    # `gateway-rust/src/scheduler_engine.rs`) and it runs NO loop.
    try:
        from ..cluster.scheduler import JobScheduler
        from ..cache import _inject_redis_password
        redis_url = _inject_redis_password(
            _env_or_yaml("REDIS_URL", lambda c: c.services.redis_url, "rediss://redis:6379"))
        sched = JobScheduler(redis_url=redis_url)
        if messaging and messaging.is_connected:
            sched.set_messaging(messaging)
        services.scheduler = sched
        # No loop is spawned: the background-producer poll was deleted in
        # the 2026-08-09 dead-code sweep (it polled an always-empty
        # registry; the Rust autonomy evaluators are the real producers
        # of background_embed / background_graph jobs).
        log.info("worker.scheduler_initialized",
                 dispatch_owner="rust scheduler_engine", role="crud only")
    except Exception as e:
        log.warning("worker.scheduler_init_failed", error=str(e))

    # Node-registry sync loop — feed the Python NodeRegistry from the Rust
    # gossip's NATS KV (`mesh_nodes`) on an interval. After the Rust port,
    # Node-registry sync loop — RETIRED here 2026-08-12 (port-lane item
    # 10). Its 2026-06-23 justification named three consumers of the
    # Python registry, and all three are gone: backend start/stop is
    # Rust-native (routes/cluster.rs), TaskRouter has no callers, and the
    # device tools POST the gateway's /api/v1/device/{action} (Rust,
    # routes/other.rs) instead of reading the registry. The loop was
    # copying mesh_nodes into a registry nothing read, every 30 seconds.
    # workers/backends.py (the KV→registry sync helpers) went with it.

    # Autonomy engine — DISABLED 2026-04-29.
    # Rust gateway-rust/src/autonomy_loop.rs is now the production autonomy
    # engine. Running both Python and Rust loops in parallel causes duplicate
    # alerts (verified during cutover testing — failed_auth_spike fired from
    # both engines, ~1 min apart).
    #
    # The Python AutonomyEngine class itself stays as the reference
    # implementation (see cluster/autonomy.py marker). worker_pool can still
    # import it for one-shot location evaluation if a NATS handler ever
    # needs it — we just don't start the long-running .start() loop.
    #
    # Reference (preserved as comments):
    #     from ..cluster.autonomy import AutonomyEngine, LocationChecker, ActionDispatcher
    #     from ..cluster.default_locations import DEFAULT_LOCATIONS
    #     proto = "https" if os.getenv("NOO_TLS_CERT") else "http"
    #     gateway_url = f"{proto}://127.0.0.1:{os.getenv('GATEWAY_PORT', '8080')}"
    #     checker = LocationChecker(gateway_url=gateway_url)
    #     dispatcher = ActionDispatcher(
    #         gateway_url=gateway_url,
    #         scheduler=getattr(services, 'scheduler', None),
    #         backend_manager=getattr(services, 'backend_manager', None),
    #     )
    #     ae = AutonomyEngine(locations=DEFAULT_LOCATIONS, checker=checker, dispatcher=dispatcher)
    #     await ae.start()
    #     services.autonomy_engine = ae
    log.info("worker.autonomy_engine_disabled_python_rust_now_authoritative")

    # Retrieval tracker — an add-on's learned source priors. Its
    # stats are add-on metrics, not a gateway route.
    if ml_pack:
        _init_retrieval_tracker()

        # Recall memory — needed for /api/v1/recall/status, search
        try:
            # Trellion's classes keep their names (sibling repo); only ours moved.
            from ..memory.video.config import VideoMemoryConfig as _TrellionRecallConfig
            from ..memory.video.manager import VideoMemoryManager as _TrellionRecallManager
            from ..config import recall_memory_enabled, recall_memory_path_env
            # One directory, decided by NOO_RECALL_MEMORY_PATH (compose sets it,
            # and the deprecated NOO_VIDEO_MEMORY_PATH that trellion's config
            # default still reads); this states the dependency explicitly.
            vm_config = _TrellionRecallConfig()
            # Trellion's default is enabled=False; carry the operator's setting
            # so worker.recall.status reports what is configured.
            vm_config.enabled = recall_memory_enabled()
            _vm_dir = recall_memory_path_env()
            if _vm_dir:
                vm_config.storage_dir = _vm_dir
            embedding_url = _env_or_yaml(
                "PAGEINDEX_EMBEDDING_URL", lambda c: c.services.embedding_url, "https://gateway:8080")
            # Protocol-aware + container-aware (NOO_GATEWAY_URL override): the
            # old hardcoded http://127.0.0.1 was refused outright by the TLS
            # listener and never resolves from the noo-trellion container.
            from .helpers import _local_gateway_url as _gw_url
            vm = _TrellionRecallManager(
                config=vm_config,
                embedding_url=embedding_url,
                gateway_url=_gw_url(),
                conversation_store=getattr(services, 'conversation_store', None),
            )
            await vm.startup()
            services.recall_memory = vm
            log.info("worker.recall_memory_initialized")
        except Exception as e:
            log.warning("worker.recall_memory_init_failed", error=str(e))

    # NOTE: We deliberately do NOT construct the Python CoordinatorAgent
    # here. Channel inbound (Google Chat, Telegram) now calls the native
    # Rust coordinator::run() in-process directly from
    # gateway-rust/src/routes/communication.rs::publish_channel_message —
    # no NATS hop, no Python coordinator dependency. The Python path
    # remains available for callers that explicitly use the FastAPI
    # lifespan in app.py (Python-primary mode). Heartbeat tasks that
    # need coordinator (research_report, chat_digest, daily_briefing)
    # should also be ported to call the Rust coordinator over an
    # in-process or HTTP path; tracked.

    # Cloud provider manager — needed for /api/cloud-providers/status
    try:
        from .cloud_providers import init_cloud_providers
        from ..secret_env import secret as get_secret
        from ..settings import flag as _flag
        cloud_mgr = init_cloud_providers(
            # DB-override (noo_settings) → env → default. Startup read: a toggle
            # takes effect on the next gateway restart (provider init is one-shot).
            enabled=_flag("CLOUD_PROVIDERS_ENABLED"),
            anthropic_api_key=get_secret("ANTHROPIC_API_KEY"),
            openai_api_key=get_secret("OPENAI_API_KEY"),
            openai_base_url=os.getenv("OPENAI_BASE_URL"),
            google_api_key=get_secret("GOOGLE_API_KEY"),
            default_provider=os.getenv("CLOUD_DEFAULT_PROVIDER"),
        )
        log.info("worker.cloud_providers_initialized",
                 available=cloud_mgr.get_available_providers())
    except Exception as e:
        log.warning("worker.cloud_providers_init_failed", error=str(e))

    # Proactive agent — needed for /api/proactive/status, rules, history
    try:
        from ..events import get_event_bus
        from .proactive_agent import init_proactive_agent
        event_bus = get_event_bus()
        channel_mgr = getattr(services, 'channel_manager', None)
        if channel_mgr:
            from .helpers import _local_gateway_url as _gw_url
            pa = init_proactive_agent(
                event_bus=event_bus,
                dispatcher=channel_mgr,
                gateway_url=_gw_url(),
            )
            services.proactive_agent = pa
            # Opt-in autostart: the loop dispatches outbound channel messages
            # (alerts, daily summaries), so it must not surprise a fresh
            # install. Without start() the agent only serves rules/history
            # reads, and GET /api/proactive/status honestly reports stopped
            # (the noo:proactive:status heartbeat key is written only by the
            # running schedule loop).
            if os.getenv("NOO_PROACTIVE_ENABLED", "").strip().lower() in ("1", "true", "yes"):
                await pa.start()
                log.info("worker.proactive_agent_initialized", started=True)
            else:
                log.info("worker.proactive_agent_initialized", started=False,
                         hint="set NOO_PROACTIVE_ENABLED=true to start the loop")
        else:
            log.info("worker.proactive_agent_skipped", reason="no channel_manager")
    except Exception as e:
        log.warning("worker.proactive_agent_init_failed", error=str(e))

    # MCP hub — RETIRED here: the Rust
    # gateway serves the operator door at /mcp/operator on its own port
    # (gateway-rust/src/mcp_local.rs, full-registry manifest) and has owned
    # /mcp/user since mcp_external.rs. (The loopback :3100 listener was removed in stack-v0.2.40.) Compose had moved the 127.0.0.1:3100
    # host publish from this container to the gateway in the same PR, so a
    # Python hub started here would bind a port nothing maps any more.
    # External MCP tool bridging (MCPClientManager) had no production
    # registrations and is deliberately not reproduced — see the plan doc.


# ═══════════════════════════════════════════════════════════════════════
# Standalone-mode support (supervisor-agnostic entry — WP-T23 phase 1)
# ═══════════════════════════════════════════════════════════════════════

_HEALTH_DEFAULT_PORT = 8090
#: The /health listener's bind address. Loopback: see `_start_health_server`.
_HEALTH_HOST = "127.0.0.1"

# Known-critical env vars the worker plane reads. A variable missing from
# the container's compose allowlist fails SILENTLY into a default — the
# single most likely source of a partial outage after the container split
# (the trellion service split). This list does not gate startup; it only
# makes the silence loud. Entries: (accepted names, why it matters).
_CRITICAL_ENV: list[tuple[tuple[str, ...], str]] = [
    (("PAGEINDEX_DSN", "DATABASE_URL"), "Postgres DSN — memory/RAG/settings/heartbeat stores"),
    (("NATS_URL",), "NATS broker URL — the worker.* transport itself"),
    (("REDIS_URL",), "job-scheduler queue + response cache"),
    (("REDIS_PASSWORD",), "redis auth (stack default is TLS + password)"),
    # no shared secret here. The worker plane verifies bus
    # principals with its OWN key and presents its OWN gateway key; the fleet
    # secret it used to hold is a node's credential and no longer delivered.
    (("NOO_BUS_KEY",), "this container's bus-principal key — absent, every worker.* message is refused"),
    (("NOO_GATEWAY_KEY",), "this container's own gateway key — absent, every self-call is refused"),
    (("NOO_AUDIT_HMAC_KEY",), "signs security audit rows — absent, every row is refused"),
    (("PAGEINDEX_EMBEDDING_URL",), "embedding transport (RAG ingest/query, memory search)"),
    (("NOO_SANDBOX_URL",), "coding-task sandbox (noo_coding_task manager side)"),
]


# Entries that only matter when this container serves the ML pack —
# a surfaces=core noo-worker legitimately runs without them, and warning
# anyway would train operators to ignore the check.
_ML_ONLY_CRITICAL = {"PAGEINDEX_EMBEDDING_URL"}


def _missing_critical_env() -> list[str]:
    """Names (first alias) of critical env vars with no non-empty value set."""
    surfaces = (os.getenv("NOO_WORKER_SURFACES") or "all").strip().lower()
    missing = []
    for names, _why in _CRITICAL_ENV:
        if surfaces == "core" and names[0] in _ML_ONLY_CRITICAL:
            continue
        # A tier-1 secret arrives as ``NAME_FILE`` (compose `secrets:`), so
        # "set" means either form — otherwise every file-delivered secret
        # reads as critical_env_unset and the warning trains operators to
        # ignore it.
        if not any(os.getenv(n, "").strip() or os.getenv(n + "_FILE", "").strip() for n in names):
            missing.append(names[0])
    return missing


def _warn_missing_critical_env() -> None:
    missing = _missing_critical_env()
    if missing:
        reasons = {names[0]: why for names, why in _CRITICAL_ENV}
        log.warning(
            "worker_pool.critical_env_unset",
            missing=missing,
            hint="check the compose env allowlist for this container — "
                 "an omitted ${VAR} passthrough silently falls back to defaults",
            detail={n: reasons[n] for n in missing},
        )
    else:
        log.info("worker_pool.critical_env_ok")


def _read_rss_mb() -> int | None:
    """Resident-set size of this process in MB from /proc/self/statm.

    Linux-only; returns None elsewhere. Mirrors main.rs::worker_rss_mb
    (field 2 = resident pages), but uses the real page size.
    """
    try:
        with open("/proc/self/statm") as fh:
            resident_pages = int(fh.read().split()[1])
        page = os.sysconf("SC_PAGE_SIZE")
        return resident_pages * page // (1024 * 1024)
    except Exception:
        return None


def _watchdog_decision(rss_mb: float | None, limit_mb: int, busy: int,
                       deferred_secs: float, hard_factor: float = 1.25,
                       max_defer_secs: float = 900.0) -> str:
    """Pure decision core of the RSS watchdog: 'ok' | 'defer' | 'exit'.

    Over the soft ceiling with work in flight → 'defer', because exiting
    mid-task is how the 2026-08-08 loop turned a sizing problem into 82
    killed heartbeat tasks. Deferral is bounded two ways — RSS reaching
    ``limit * hard_factor`` or ``max_defer_secs`` of continuous deferral —
    so a genuine runaway still cannot ride an ever-busy queue past the
    host's memory.
    """
    if rss_mb is None or rss_mb <= limit_mb:
        return "ok"
    if rss_mb > limit_mb * hard_factor or deferred_secs >= max_defer_secs:
        return "exit"
    return "defer" if busy > 0 else "exit"


async def _rss_watchdog(limit_mb: int, grace_secs: float = 60.0,
                        interval_secs: float = 5.0) -> None:
    """Graceful RSS self-ceiling.

    In external-supervisor mode the compose ``mem_limit`` cgroup is the hard
    backstop (OOM-kill contained to this container); this watchdog preserves
    the *graceful, logged, driver-chosen* restart the in-process Rust
    supervisor provided: over the ceiling → log → exit(0) → Docker restart
    policy (or the Rust supervisor, in inprocess mode) respawns us. The 60s
    grace mirrors main.rs so boot-time allocation spikes don't trip it.

    Task-aware since 2026-08-08: an exit is DEFERRED while handlers or
    heartbeat tasks are in flight (see ``inflight``), bounded by a hard RSS
    factor and a max deferral window — see ``_watchdog_decision``. The
    old unconditional exit produced a permanent restart loop the moment the
    steady-state working set crossed the ceiling, and every exit orphaned
    whatever the worker was doing ("dispatched to the Python worker and
    never reported an outcome").
    """
    if limit_mb <= 0:
        return
    log.info("worker_pool.rss_watchdog_armed", limit_mb=limit_mb,
             grace_secs=grace_secs)
    await asyncio.sleep(grace_secs)
    deferred_since: float | None = None
    loop = asyncio.get_running_loop()
    while True:
        rss = _read_rss_mb()
        busy = inflight.count()
        deferred_secs = (loop.time() - deferred_since) if deferred_since else 0.0
        verdict = _watchdog_decision(rss, limit_mb, busy, deferred_secs)
        if verdict == "ok":
            deferred_since = None
        elif verdict == "defer":
            if deferred_since is None:
                deferred_since = loop.time()
            log.warning("worker_pool.rss_ceiling_exceeded_deferred",
                        rss_mb=rss, limit_mb=limit_mb, in_flight=busy,
                        deferred_secs=int(deferred_secs),
                        action="waiting for in-flight work before exiting")
        else:
            log.error("worker_pool.rss_ceiling_exceeded", rss_mb=rss,
                      limit_mb=limit_mb, in_flight=busy,
                      deferred_secs=int(deferred_secs),
                      action="exiting 0 — restart policy respawns")
            await asyncio.sleep(0.5)  # let the log line flush
            os._exit(0)
        await asyncio.sleep(interval_secs)


async def _start_health_server(messaging: Any, port: int) -> Any:
    """Tiny dependency-free HTTP /health listener.

    LOOPBACK ONLY (:data:`_HEALTH_HOST`). Its one consumer is the container's
    own healthcheck, which dials ``127.0.0.1:8090`` from inside the
    container. It used to bind ``0.0.0.0`` in plain HTTP, reachable from every
    container on the compose networks for no reader at all; there is no host
    parameter, so a caller cannot widen it again.
    Reports ``{nats_connected, handlers_registered, db_ok}``; 200 when NATS
    is connected and handlers are registered, else 503. ``db_ok`` is
    informational (degraded mode is per-capability, DB down must not flap
    the container).
    """

    async def _db_ok() -> bool:
        try:
            from sqlalchemy import text

            from .deps import services
            store = getattr(services, "conversation_store", None)
            eng = getattr(store, "_engine", None)
            if eng is None:
                return False

            async def _probe():
                async with eng.connect() as conn:
                    await conn.execute(text("SELECT 1"))

            await asyncio.wait_for(_probe(), timeout=3.0)
            return True
        except Exception:
            return False

    async def _handle(reader, writer):
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            while True:  # drain headers
                line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if line in (b"\r\n", b"\n", b""):
                    break
            parts = request_line.decode("latin-1", "replace").split()
            path = parts[1].split("?")[0] if len(parts) >= 2 else ""
            if path in ("/health", "/healthz"):
                nats_ok = bool(messaging and messaging.is_connected)
                handlers = len(all_handlers())
                healthy = nats_ok and handlers > 0
                body = json.dumps({
                    "status": "ok" if healthy else "degraded",
                    "nats_connected": nats_ok,
                    "handlers_registered": handlers,
                    "db_ok": await _db_ok(),
                }).encode()
                status = b"200 OK" if healthy else b"503 Service Unavailable"
            else:
                body = b'{"error": "not found"}'
                status = b"404 Not Found"
            writer.write(
                b"HTTP/1.1 " + status
                + b"\r\nContent-Type: application/json"
                + b"\r\nContent-Length: " + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n" + body
            )
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    server = await asyncio.start_server(_handle, host=_HEALTH_HOST, port=port)
    log.info("worker_pool.health_listener_started", host=_HEALTH_HOST, port=port)
    return server


# Standalone entry point
if __name__ == "__main__":
    async def main():
        from ..cluster.messaging import ClusterMessaging

        # Loud (non-fatal) inventory check BEFORE anything else, so a
        # mis-scoped compose env allowlist is the first line in the logs.
        _warn_missing_critical_env()
        # FATAL: a secret delivered both as NAME and NAME_FILE, or a named
        # file that cannot be read. One line, then exit — the same refusal
        # the gateway's preflight `secret_files` check makes.
        from ..secret_env import refuse_on_conflicts

        refuse_on_conflicts()

        nats_url = _env_or_yaml("NATS_URL", lambda c: c.services.nats_url, "tls://nats:4222")
        messaging = ClusterMessaging(nats_url)
        # retry=True → allow_reconnect=True. Worker_pool is a long-lived
        # service; NATS bounces (during cluster rebuilds, container restarts,
        # network blips) would otherwise leave the python NATS client
        # silently disconnected. The process stays up, the registry still
        # logs "running subjects=[...]", but the broker has zero live
        # subscribers — so the Rust gateway gets `no responders` on every
        # tool call (verified 2026-05-16 when noo_rag_query and web_search
        # both failed instantly with "no responders"). nats.py auto-resubs
        # buffered subscriptions on reconnect when allow_reconnect=True.
        #
        # allow_reconnect only governs an ESTABLISHED connection. If NATS is
        # merely slow to come up — a cold `noo stack start`, where the pool
        # and the broker race — connect() returns False and, before this
        # loop, the pool carried on: start_worker_pool() saw `messaging.nc`
        # was None, registered ZERO subscribers, and the process sat there
        # looking alive forever while every gateway tool call got "no
        # responders". Keep retrying instead; /health reports 503 meanwhile.
        _connect_attempt = 0
        while not await messaging.connect(retry=True):
            _connect_attempt += 1
            delay = min(30, 2 * _connect_attempt)
            log.warning(
                "worker_pool.nats_connect_retry",
                attempt=_connect_attempt,
                retry_in_sec=delay,
                url=nats_url,
                message="NATS unreachable — the pool has no subscribers until it connects",
            )
            await asyncio.sleep(delay)

        # /health listener (:8090 default) — compose healthcheck target in
        # external-supervisor mode; harmless extra listener in inprocess
        # mode (phase 1 gate: "/health responds inside the gateway
        # container"). Started BEFORE service init so a slow ML import
        # phase reports 503 instead of connection-refused.
        try:
            health_port = int(os.getenv(
                "NOO_WORKER_HEALTH_PORT", str(_HEALTH_DEFAULT_PORT)))
            await _start_health_server(messaging, health_port)
        except Exception as exc:
            log.warning("worker_pool.health_listener_failed", error=str(exc))

        # RSS self-watchdog — same env knob the Rust supervisor uses, so
        # the ceiling follows the process wherever it runs. In inprocess
        # mode this graceful exit simply fires before the supervisor's
        # SIGKILL path would (same 5s cadence, same threshold).
        rss_limit = int(_env_or_yaml(
            "NOO_WORKER_RSS_LIMIT_MB", lambda c: c.worker.rss_limit_mb, 0) or 0)
        asyncio.create_task(_rss_watchdog(rss_limit))

        # Initialize Python services before subscribing to NATS
        await _init_python_services(messaging)

        await start_worker_pool(messaging)

        log.info("worker_pool.running", subjects=sorted(all_handlers()))

        # Clean shutdown on SIGTERM/SIGINT. As a container entrypoint this
        # process is PID 1, and PID 1 gets NO default signal dispositions —
        # without an explicit handler `docker stop` waits out the full
        # grace period and SIGKILLs (observed: exit 137 after 15s). With
        # it: unsubscribe via NATS close, log, exit 0 within a second.
        import signal
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for _sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(_sig, stop.set)
            except (NotImplementedError, RuntimeError):
                pass  # non-Unix / nested loop — fall back to default behavior

        await stop.wait()
        log.info("worker_pool.shutdown_signal_received")
        try:
            await asyncio.wait_for(messaging.close(), timeout=5.0)
        except Exception:
            pass
        log.info("worker_pool.shutdown_complete")

    asyncio.run(main())
