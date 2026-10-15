# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""NATS-based cluster messaging with JetStream persistence.

This module provides event broadcasting, task queues, and agent-to-agent
messaging across the PAI cluster.
"""

from .. import json_fast as json
from ..redact import scrub_url_userinfo
import asyncio
import os
import ssl
from typing import Callable, Optional, Dict, Any, List
from datetime import datetime, timezone

import structlog

logger = structlog.get_logger()

# Try to import nats, handle if not available
try:
    import nats
    from nats.aio.client import Client as NATS
    from nats.js.api import StreamConfig  # noqa: F401
    NATS_AVAILABLE = True
except ImportError:
    NATS_AVAILABLE = False
    logger.warning("nats_not_available",
                  message="Install nats-py for messaging features")


# --- credentials ---------------------------------------

#: This principal's own pair. One shared NATS user for the gateway, the
#: workers and every node makes subject permissions impossible: nothing on
#: the wire tells the principals apart, so the single user can only be
#: granted ``>``/``>``. noo-worker, noo-trellion and noo-trellion-intel all
#: present ``worker``, which is denied ``tasks.>``, ``$KV.>`` and stream
#: administration.
WORKER_USER_VAR = "NATS_WORKER_USER"
WORKER_PASSWORD_VAR = "NATS_WORKER_PASSWORD"
#: The retired shared fleet pair. Nothing presents it any
#: more and the server no longer defines it: it is named here ONLY so the
#: refusal below can say, specifically, why a set ``NATS_USER`` is ignored.
#: There is no bridge back to it — ``NOO_NATS_LEGACY_SHARED_CREDS`` is gone.
RETIRED_SHARED_USER_VAR = "NATS_USER"
ALLOW_ANONYMOUS_VAR = "NOO_NATS_ALLOW_ANONYMOUS"

#: Per-client inbox prefix, so a permission rule can grant this principal
#: only its own inbox. The default ``_INBOX.`` is shared by everyone and
#: therefore cannot be scoped.
INBOX_PREFIX = "_INBOX_worker"

_TRUTHY = ("1", "true", "yes", "on")


class NatsCredentialsMissing(RuntimeError):
    """No NATS credential and no deliberate anonymous opt-in.

    Raised instead of connecting anonymously. An empty user is not "no auth
    configured" to a server whose user list resolves to nothing — it
    ACCEPTS the anonymous connection, so a blank in the secret store used to
    remove bus authentication fleet-wide in total silence.
    """


def resolve_nats_credentials(env: Optional[Dict[str, str]] = None) -> Optional[Dict[str, str]]:
    """Return ``{"user", "password", "source"}``, or None for anonymous.

    The worker's own pair is the ONLY credential this process presents.
    The shared fleet pair was retired: the server no longer
    defines that user, so there is nothing to fall back to — an unset pair
    is a loud stop naming the command that mints it (tracker N8).

    Raises :class:`NatsCredentialsMissing` when nothing this process may use
    is configured and ``NOO_NATS_ALLOW_ANONYMOUS`` is not set.
    """
    env = os.environ if env is None else env

    def read(key: str) -> str:
        # The one hook: `secret_from` adds the `_FILE` / `NOO_SECRET_` tiers,
        # so a file-delivered NATS password needs no change here.
        from ..secret_env import secret_from

        return (secret_from(key, env.get) or "").strip()

    user = read(WORKER_USER_VAR)
    if user:
        return {"user": user, "password": read(WORKER_PASSWORD_VAR), "source": "worker"}

    if read(ALLOW_ANONYMOUS_VAR).lower() in _TRUTHY:
        return None

    if read(RETIRED_SHARED_USER_VAR):
        raise NatsCredentialsMissing(
            f"{WORKER_USER_VAR}/{WORKER_PASSWORD_VAR} are not set. {RETIRED_SHARED_USER_VAR} "
            f"is set, but the shared bus user was RETIRED: the server no "
            f"longer defines it and nothing presents it. On the controller run "
            f"`noo cluster nats-creds rotate worker --restart` (or `noo cluster nats-users "
            f"render`, which mints a missing pair), then recreate this container — an env "
            f"change does not survive a plain restart."
        )

    raise NatsCredentialsMissing(
        f"no NATS credential: set {WORKER_USER_VAR}/{WORKER_PASSWORD_VAR}. An empty "
        f"user connects ANONYMOUSLY and the server accepts it, which silently "
        f"removes bus authentication — so this is refused. `noo cluster nats-creds "
        f"rotate worker --restart` (or `noo cluster nats-users render`) mints this "
        f"principal's pair and renders the server side. Set "
        f"{ALLOW_ANONYMOUS_VAR}=1 to connect anonymously on purpose."
    )


class ClusterMessaging:
    """NATS messaging for PAI cluster.

    Features:
    - Event broadcasting (pub/sub)
    - Task queues (load balanced)
    - Agent-to-agent messaging (request/reply)
    - Persistence via JetStream
    """

    def __init__(self, nats_url: Optional[str] = None):
        """Initialize messaging client.

        Args:
            nats_url: NATS server URL (default: from env or nats://localhost:4222)
        """
        if not NATS_AVAILABLE:
            raise ImportError("nats-py not installed. Install with: pip install nats-py")

        if not nats_url:
            from ..config import env_or_yaml
            # The bus is mTLS-only (tests/test_nats_tls_only.py): a `nats://`
            # default named a listener that does not exist.
            nats_url = env_or_yaml(
                "NATS_URL", lambda c: c.services.nats_url, "tls://localhost:4222")
        self.nats_url = nats_url
        self.nc: Optional[NATS] = None
        self.js = None  # JetStream context
        self._subscriptions: List = []
        self._connected = False
        # Callbacks fired after the connection is re-established. Subscribers
        # register idempotent re-bind functions here; see on_reconnect().
        self._reconnect_hooks: List = []

    async def connect(self, timeout: float = 5.0, retry: bool = False) -> bool:
        """Connect to NATS and initialize JetStream.

        Args:
            timeout: Connection timeout in seconds
            retry: Whether to retry on failure (default: False for graceful degradation)

        Returns:
            True if connected successfully
        """
        # Resolved OUTSIDE the try: a missing credential is a refusal, not a
        # degradation. Everything below treats an exception as "carry on
        # without messaging", which is exactly the wrong answer to "this
        # process was about to authenticate as nobody".
        _cred = resolve_nats_credentials()
        _cred_kwargs: dict = {}
        if _cred is None:
            logger.warning("nats_anonymous_connect",
                           reason=f"{ALLOW_ANONYMOUS_VAR} is set")
        else:
            _cred_kwargs["user"] = _cred["user"]
            _cred_kwargs["password"] = _cred["password"]
            logger.info("nats_credential_resolved",
                        role=_cred["source"], user=_cred["user"])

        try:

            # TLS configuration — use cluster CA when available
            _tls_kwargs: dict = {}
            _nats_tls = os.getenv("NOO_NATS_TLS", "").lower() in ("1", "true", "yes")
            _tls_ca = os.getenv("NOO_TLS_CA", "")
            if _nats_tls or self.nats_url.startswith("tls://"):
                ctx = ssl.create_default_context()
                if _tls_ca and os.path.exists(_tls_ca):
                    ctx.load_verify_locations(_tls_ca)
                # Load client cert if available (mTLS)
                _tls_cert = os.getenv("NOO_TLS_CERT", "")
                _tls_key = os.getenv("NOO_TLS_KEY", "")
                if _tls_cert and _tls_key and os.path.exists(_tls_cert):
                    ctx.load_cert_chain(_tls_cert, _tls_key)
                    logger.info("nats_tls_client_cert_loaded",
                                cert=_tls_cert)
                elif _tls_cert or _tls_key:
                    logger.warning("nats_tls_client_cert_missing",
                                   cert=_tls_cert,
                                   cert_exists=os.path.exists(_tls_cert) if _tls_cert else False,
                                   key=_tls_key,
                                   key_exists=os.path.exists(_tls_key) if _tls_key else False)
                _tls_kwargs["tls"] = ctx
                # Upgrade nats:// to tls:// for the connection
                if self.nats_url.startswith("nats://"):
                    self.nats_url = self.nats_url.replace("nats://", "tls://", 1)

            # Connect to NATS with timeout and no auto-reconnect on failure
            self.nc = await asyncio.wait_for(
                nats.connect(
                    self.nats_url,
                    connect_timeout=timeout,
                    max_reconnect_attempts=0 if not retry else -1,  # Disable reconnect spam
                    reconnect_time_wait=2 if retry else 0,
                    verbose=False,  # Reduce log spam
                    allow_reconnect=retry,
                    # Per-client inbox prefix so a permission rule can grant
                    # this principal only its own inbox.
                    inbox_prefix=INBOX_PREFIX.encode(),
                    # Lifecycle callbacks. Without these a total bus outage
                    # was completely silent on the Python side — no log line
                    # marked the disconnect, and nothing re-asserted the
                    # JetStream streams afterwards.
                    error_cb=self._on_error,
                    disconnected_cb=self._on_disconnected,
                    reconnected_cb=self._on_reconnected,
                    closed_cb=self._on_closed,
                    **_cred_kwargs,
                    **_tls_kwargs,
                ),
                timeout=timeout + 1
            )
            self.js = self.nc.jetstream()
            self._connected = True

            # Verify the gateway-owned JetStream streams exist
            await self._verify_streams()

            logger.info("nats_connected", url=scrub_url_userinfo(self.nats_url))
            return True

        except asyncio.TimeoutError:
            logger.warning("nats_connection_timeout",
                          url=scrub_url_userinfo(self.nats_url),
                          message="NATS not available (timeout) - continuing without messaging")
            self._connected = False
            return False
        except Exception as e:
            logger.warning("nats_connection_failed",
                          url=scrub_url_userinfo(self.nats_url),
                          error=str(e),
                          message="Continuing without NATS messaging")
            self._connected = False
            return False

    # The job-plane streams. The Rust gateway OWNS their creation
    # (`scheduler_engine::ensure_job_plane_streams`, at boot, create-only) and
    # holds the credential for it. The worker's NATS user is denied
    # `$JS.API.STREAM.CREATE.>` on purpose (least privilege; see
    # `perms_for` in noo-cli nats_users.rs) and is granted exactly
    # `$JS.API.STREAM.INFO.*` — so the worker VERIFIES, never creates.
    # Trying to create made every start log two permission violations and
    # burn a request timeout per stream, and the message ("creation failed")
    # said nothing about the real question: is the stream there?
    REQUIRED_STREAMS = ("EVENTS", "TASKS")

    async def _verify_streams(self):
        """Check that the gateway-owned streams exist; fail loudly if not."""
        if not self.js:
            return

        for name in self.REQUIRED_STREAMS:
            try:
                await self.js.stream_info(name)
                logger.debug("stream_present", name=name)
            except Exception as e:
                if type(e).__name__ == "NotFoundError":
                    logger.error(
                        "stream_missing", name=name,
                        message="JetStream stream is absent; the gateway creates it at "
                                "boot — event/task publishes will fail until it does")
                else:
                    logger.error("stream_verify_failed", name=name, error=str(e))

    # --- connection lifecycle ---------------------------------------------

    def on_reconnect(self, callback) -> None:
        """Register an idempotent re-bind, fired after every reconnect.

        Mirrors the Go node-agent's ``Client.OnReconnect``. Callbacks may be
        sync or async; exceptions are logged, never propagated into nats-py's
        callback task.
        """
        self._reconnect_hooks.append(callback)

    async def _on_error(self, e):
        # A refused REPLY is the caller losing its answer, not bus noise: say
        # which request it was and how long it was held (i69). nats-py gives
        # only the lowercased subject; the ledger maps it back.
        from . import reply_ledger

        lost = reply_ledger.refused_reply(str(e))
        if lost is not None:
            logger.error(
                "worker.reply_undeliverable",
                **lost,
                message="NATS refused this reply, so the requester will never receive the "
                        "answer (it times out). The principal's grant must allow a publish "
                        "on the requester's reply inbox that survives a NATS config reload "
                        "— allow_responses entries are wiped by every reload "
                        "(noo-cli nats_users.rs WORKER_REPLY_INBOX)",
            )
            return
        logger.error("nats_async_error", url=scrub_url_userinfo(self.nats_url), error=str(e))

    async def _on_disconnected(self):
        # LOUD on purpose. The defining property of the 2026-08-02 incident
        # was that losing the bus produced no log line anywhere.
        logger.warning("nats_disconnected", url=scrub_url_userinfo(self.nats_url),
                       message="NATS connection lost — reconnecting")

    async def _on_closed(self):
        logger.error("nats_closed", url=scrub_url_userinfo(self.nats_url),
                     message="NATS connection closed permanently — this process is bus-deaf")

    async def _on_reconnected(self):
        logger.info("nats_reconnected", url=scrub_url_userinfo(self.nats_url))

        # Re-verify the streams. A NATS server that came back with a fresh
        # JetStream store (what a container recreate does) has no EVENTS /
        # TASKS (the gateway re-creates them; this just reports), and every js.publish then fails forever
        # while the client reports a perfectly healthy connection.
        try:
            await self._verify_streams()
        except Exception as e:  # pragma: no cover - defensive
            logger.error("nats_stream_verify_failed", error=str(e))

        for hook in list(self._reconnect_hooks):
            try:
                result = hook()
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.error("nats_reconnect_hook_failed",
                             hook=getattr(hook, "__name__", repr(hook)), error=str(e))

    @property
    def is_connected(self) -> bool:
        """Check if connected to NATS.

        Consults the LIVE socket, not a sticky flag. ``self._connected`` was
        set True on connect and cleared only by ``close()``, so this property
        reported healthy straight through an outage — which silently disarmed
        every consumer that repairs itself on a disconnected → connected
        edge, because that edge could never be observed. (The original case
        was ``scheduler.py::_check_completion_listener``, since removed; the property is still load-bearing for
        the channel and worker subscriptions.)
        """
        if not self._connected or self.nc is None:
            return False
        is_conn = getattr(self.nc, "is_connected", None)
        return True if is_conn is None else bool(is_conn)

    async def publish_event(self, event_type: str, data: Dict[str, Any]):
        """Publish a cluster event with persistence.

        Events are broadcast to all subscribers and persisted in JetStream.

        Args:
            event_type: Event type (e.g., "model.downloaded", "backend.started")
            data: Event payload (will be JSON serialized)

        Example:
            await messaging.publish_event("backend.started", {
                "backend": "vllm",
                "model": "llama-7b"
            })
        """
        if not self.is_connected:
            logger.warning("publish_event_failed", reason="not_connected")
            return

        subject = f"events.{event_type}"
        payload = json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            **data
        }).encode()

        try:
            # Publish to JetStream (persistent)
            ack = await self.js.publish(subject, payload)
            logger.info("event_published",
                       subject=subject,
                       seq=ack.seq,
                       stream=ack.stream)

        except Exception as e:
            logger.error("event_publish_failed",
                        subject=subject,
                        error=str(e))

    async def subscribe_events(self,
                               event_pattern: str,
                               callback: Callable[[Dict], Any],
                               durable_name: Optional[str] = None):
        """Subscribe to cluster events.

        Args:
            event_pattern: Event pattern (e.g., "model.*", "backend.>")
            callback: Async function called with event data
            durable_name: Optional durable consumer name

        Example:
            async def on_backend_started(event):
                print(f"Backend {event['backend']} started")

            await messaging.subscribe_events(
                "backend.started",
                on_backend_started
            )
        """
        if not self.is_connected:
            logger.warning("subscribe_events_failed", reason="not_connected")
            return

        subject = f"events.{event_pattern}"

        # Generate durable name if not provided
        if not durable_name:
            durable_name = f"consumer_{event_pattern.replace('.', '_').replace('>', 'all')}"

        async def handler(msg):
            try:
                data = json.loads(msg.data.decode())
                await callback(data)
                await msg.ack()

            except Exception as e:
                logger.error("event_handler_failed",
                           subject=msg.subject,
                           error=str(e))

        try:
            # Create durable consumer with JetStream
            sub = await self.js.subscribe(
                subject,
                durable=durable_name,
                cb=handler
            )

            self._subscriptions.append(sub)
            logger.info("subscribed_to_events",
                       pattern=event_pattern,
                       durable=durable_name)

        except Exception as e:
            logger.error("subscribe_failed",
                        pattern=event_pattern,
                        error=str(e))

    async def submit_task(self,
                         task_type: str,
                         task_data: Dict[str, Any]) -> str:
        """Submit task to distributed queue.

        Tasks are load-balanced across available workers.

        Args:
            task_type: Type of task (e.g., "inference", "training")
            task_data: Task payload

        Returns:
            task_id: Unique task identifier

        Example:
            task_id = await messaging.submit_task("inference", {
                "prompt": "Hello world",
                "model": "llama-7b"
            })
        """
        if not self.is_connected:
            logger.warning("submit_task_failed", reason="not_connected")
            return ""

        import uuid
        task_id = str(uuid.uuid4())

        subject = f"tasks.{task_type}"
        payload = json.dumps({
            "task_id": task_id,
            "submitted_at": datetime.now(timezone.utc).isoformat(),
            **task_data
        }).encode()

        try:
            await self.js.publish(subject, payload)
            logger.info("task_submitted",
                       task_id=task_id,
                       type=task_type)
            return task_id

        except Exception as e:
            logger.error("task_submit_failed",
                        type=task_type,
                        error=str(e))
            return ""

    async def consume_tasks(self,
                           task_type: str,
                           handler: Callable[[Dict], Any],
                           queue_group: str = "workers"):
        """Consume tasks from queue (load balanced).

        Multiple workers in the same queue_group will each get different tasks.

        Args:
            task_type: Type of tasks to process
            handler: Async function to process task
            queue_group: Queue group name (for load balancing)

        Example:
            async def process_inference(task):
                result = run_inference(task["prompt"])
                print(f"Task {task['task_id']} complete")

            await messaging.consume_tasks("inference", process_inference)
        """
        if not self.is_connected:
            logger.warning("consume_tasks_failed", reason="not_connected")
            return

        subject = f"tasks.{task_type}"

        async def wrapper(msg):
            try:
                task = json.loads(msg.data.decode())
                await handler(task)
                await msg.ack()

            except Exception as e:
                logger.error("task_processing_failed",
                           task_id=task.get("task_id"),
                           error=str(e))
                # Negative ack - task will be redelivered
                await msg.nak()

        try:
            # Durable push consumer — no queue group needed for single-gateway
            # deployments. If horizontal scaling is needed later, switch to
            # pull_subscribe with explicit consumer creation.
            from nats.js.api import ConsumerConfig
            durable_name = f"consumer_{task_type}"
            sub = await self.js.subscribe(
                subject,
                durable=durable_name,
                cb=wrapper,
                config=ConsumerConfig(
                    ack_wait=300,     # 5 min — coordinator + LLM can be slow
                    max_deliver=1,    # No redelivery — avoid duplicate responses
                ),
            )

            self._subscriptions.append(sub)
            logger.info("consuming_tasks",
                       type=task_type,
                       durable=durable_name)

        except Exception as e:
            logger.error("consume_tasks_failed",
                        type=task_type,
                        error=str(e))

    async def request_capability(self,
                                capability: str,
                                data: Dict[str, Any],
                                timeout: int = 30) -> Optional[Dict]:
        """Request service from capable agent (request/reply pattern).

        Args:
            capability: Required capability (e.g., "image.generate")
            data: Request payload
            timeout: Request timeout in seconds

        Returns:
            Response data or None if timeout

        Example:
            result = await messaging.request_capability(
                "image.generate",
                {"prompt": "A cat in space"}
            )
        """
        if not self.is_connected:
            logger.warning("request_capability_failed", reason="not_connected")
            return None

        subject = f"agent.{capability}"
        payload = json.dumps(data).encode()

        try:
            msg = await self.nc.request(subject, payload, timeout=timeout)
            return json.loads(msg.data.decode())

        except asyncio.TimeoutError:
            logger.warning("capability_request_timeout",
                         capability=capability,
                         timeout=timeout)
            return None

        except Exception as e:
            logger.error("capability_request_failed",
                        capability=capability,
                        error=str(e))
            return None

    async def close(self):
        """Close NATS connection and cleanup."""
        if self.nc:
            try:
                # Unsubscribe from all
                for sub in self._subscriptions:
                    try:
                        await sub.unsubscribe()
                    except Exception:
                        pass

                # Close connection
                await self.nc.close()
                self._connected = False
                logger.info("nats_connection_closed")

            except Exception as e:
                logger.error("nats_close_failed", error=str(e))


# Global instance
_messaging: Optional[ClusterMessaging] = None


def get_messaging() -> ClusterMessaging:
    """Get global messaging instance.

    Returns:
        ClusterMessaging instance

    Raises:
        RuntimeError: If messaging not initialized
    """
    global _messaging
    if _messaging is None:
        _messaging = ClusterMessaging()
    return _messaging


async def init_messaging() -> bool:
    """Initialize and connect global messaging instance.

    Returns:
        True if connected successfully
    """
    messaging = get_messaging()
    return await messaging.connect(retry=True)


async def close_messaging():
    """Close global messaging instance."""
    global _messaging
    if _messaging:
        await _messaging.close()
        _messaging = None
