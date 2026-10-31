# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Request tracing for the Python services (i359 C1).

The gateway starts a trace for every request it serves and sends a W3C
``traceparent`` on each ``worker.*`` message it publishes for that request.
A worker continues it here: one span per handled subject, parented on the
gateway's span, sent to Tempo.

No OpenTelemetry SDK. The spans are the same OTLP/HTTP JSON the gateway's
exporter writes (``gateway-rust/src/request_trace.rs``), sent with httpx:

- Tempo has an OTLP HTTP receiver only (no gRPC), which the SDK's default
  exporter is not;
- the SDK reads ``OTEL_*`` environment defaults (exporter endpoint,
  insecure, sampler) that would each need guarding; with no SDK there is no
  such surface, and the endpoint is ours by construction;
- the gateway made the same choice (no new crates).

Every export is TLS checked against the cluster CA (``tls_ca.require_ca``)
with this container's own leaf as the client certificate, because Tempo
requires one. An ``http://`` endpoint, no CA or no leaf means no export, with
a warning naming why — never a plaintext or unverified fallback (followup
510). Spans carry metadata only: names, ids, timings, the subject, never a
payload.
"""

from __future__ import annotations

import contextvars
import os
import queue
import re
import secrets
import socket
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Mapping, Optional, Tuple

import structlog

from .tls_ca import TlsCaMissing, require_ca

logger = structlog.get_logger()

#: Tempo's OTLP HTTP base (``https://tempo:4318``), as the gateway reads it.
TEMPO_URL_ENV = "NOO_TEMPO_OTLP_URL"

#: Spans waiting for export. Full means Tempo is not keeping up: new spans
#: are dropped and counted, never queued without bound.
EXPORT_QUEUE = 8192
EXPORT_BATCH = 512
EXPORT_EVERY_S = 5.0

_TRACEPARENT = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")


def parse_traceparent(value: Optional[str]) -> Optional[Tuple[str, str]]:
    """(trace id, parent span id) from a well-formed ``traceparent``, else None.
    All-zero ids are invalid in W3C trace context and start a new trace."""
    if not value:
        return None
    m = _TRACEPARENT.match(value.strip().lower())
    if not m:
        return None
    trace_id, span_id = m.group(1), m.group(2)
    if set(trace_id) == {"0"} or set(span_id) == {"0"}:
        return None
    return trace_id, span_id


def _new_id(nbytes: int) -> str:
    while True:
        v = secrets.token_hex(nbytes)
        if set(v) != {"0"}:
            return v


class Span:
    """One unit of work in a trace. Attribute values are names and numbers."""

    __slots__ = ("trace_id", "span_id", "parent", "name", "kind", "start_ns", "end_ns", "attrs", "error")

    def __init__(self, name: str, trace_id: str, parent: Optional[str], kind: int = 2) -> None:
        self.trace_id = trace_id
        self.span_id = _new_id(8)
        self.parent = parent
        self.name = name
        self.kind = kind  # OTLP: 1 internal, 2 server, 3 client, 5 consumer
        self.start_ns = time.time_ns()
        self.end_ns = 0
        self.attrs: Dict[str, Any] = {}
        self.error = False

    def traceparent(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-01"

    def to_otlp(self) -> Dict[str, Any]:
        attrs = []
        for k, v in self.attrs.items():
            if isinstance(v, bool) or not isinstance(v, int):
                attrs.append({"key": k, "value": {"stringValue": str(v)}})
            else:
                attrs.append({"key": k, "value": {"intValue": str(v)}})
        out: Dict[str, Any] = {
            "traceId": self.trace_id,
            "spanId": self.span_id,
            "name": self.name,
            "kind": self.kind,
            "startTimeUnixNano": str(self.start_ns),
            "endTimeUnixNano": str(self.end_ns or time.time_ns()),
            "attributes": attrs,
            "status": {"code": 2 if self.error else 1},
        }
        if self.parent:
            out["parentSpanId"] = self.parent
        return out


def otlp_body(spans: List[Span], service_name: str) -> Dict[str, Any]:
    """The OTLP/JSON request body for a batch of this process's spans."""
    resource = [
        {"key": "service.name", "value": {"stringValue": service_name}},
        {"key": "host.name", "value": {"stringValue": socket.gethostname()}},
    ]
    return {
        "resourceSpans": [
            {
                "resource": {"attributes": resource},
                "scopeSpans": [{"scope": {"name": service_name}, "spans": [s.to_otlp() for s in spans]}],
            }
        ]
    }


def tempo_traces_url(base: Optional[str]) -> Optional[str]:
    """The OTLP traces URL, None when Tempo is not configured. Raises
    ValueError for anything but ``https://``: spans go over TLS only."""
    base = (base or "").strip().rstrip("/")
    if not base:
        return None
    if not base.lower().startswith("https://"):
        raise ValueError(f"{TEMPO_URL_ENV}={base} is not https://; spans are exported over TLS only")
    return f"{base}/v1/traces"


class _Exporter:
    """A daemon thread posting batches; a bounded queue in front of it."""

    def __init__(self, url: str, service_name: str, verify: str, cert: Tuple[str, str], client: Any = None) -> None:
        import httpx

        self.url = url
        self.service_name = service_name
        self.dropped = 0
        self._q: "queue.Queue[Span]" = queue.Queue(maxsize=EXPORT_QUEUE)
        self._client = client or httpx.Client(verify=verify, cert=cert, timeout=10.0)
        self._last_warn = 0.0
        threading.Thread(target=self._run, name="trace-export", daemon=True).start()

    def put(self, span: Span) -> None:
        try:
            self._q.put_nowait(span)
        except queue.Full:
            self.dropped += 1
            self._warn("trace_export_queue_full", "spans dropped; Tempo is not keeping up or is down")

    def _warn(self, event: str, detail: str) -> None:
        now = time.monotonic()
        if now - self._last_warn >= 60:
            self._last_warn = now
            logger.warning(event, detail=detail, dropped=self.dropped)

    def post(self, batch: List[Span]) -> None:
        try:
            r = self._client.post(self.url, json=otlp_body(batch, self.service_name))
            if r.status_code >= 300:
                self._warn("trace_export_refused", f"Tempo answered {r.status_code}")
        except Exception as e:  # noqa: BLE001 — tracing never fails the caller
            self._warn("trace_export_failed", str(e))

    def _run(self) -> None:
        while True:
            batch: List[Span] = []
            deadline = time.monotonic() + EXPORT_EVERY_S
            while len(batch) < EXPORT_BATCH:
                try:
                    batch.append(self._q.get(timeout=max(0.0, deadline - time.monotonic())))
                except queue.Empty:
                    break
            if batch:
                self.post(batch)


_exporter: Optional[_Exporter] = None
_current: "contextvars.ContextVar[Optional[Span]]" = contextvars.ContextVar("noo_trace_span", default=None)


def configure(service_name: str = "noo-worker", env: Optional[Mapping[str, str]] = None, client: Any = None) -> bool:
    """Start exporting this process's spans to Tempo. True when it will.

    Reads ``NOO_TEMPO_OTLP_URL``, the cluster CA and this container's leaf
    (``NOO_TLS_CERT`` / ``NOO_TLS_KEY``). Any of them missing or wrong: no
    export, one warning naming it; spans are still made (so their ids reach
    logs and events) but go nowhere. Idempotent."""
    global _exporter
    env = os.environ if env is None else env
    if _exporter is not None:
        return True
    try:
        url = tempo_traces_url(env.get(TEMPO_URL_ENV))
    except ValueError as e:
        logger.warning("tracing_skipped", reason=str(e))
        return False
    if url is None:
        logger.info("tracing_skipped", reason=f"{TEMPO_URL_ENV} not set")
        return False
    try:
        ca = require_ca(env)
    except TlsCaMissing as e:
        logger.warning("tracing_skipped", reason=str(e))
        return False
    cert, key = (env.get("NOO_TLS_CERT") or "").strip(), (env.get("NOO_TLS_KEY") or "").strip()
    if not (cert and key and os.path.isfile(cert) and os.path.isfile(key)):
        logger.warning("tracing_skipped", reason="Tempo requires a client certificate and NOO_TLS_CERT/NOO_TLS_KEY name none")
        return False
    _exporter = _Exporter(url, service_name, ca, (cert, key), client=client)
    logger.info("tracing_initialized", endpoint=url, service=service_name)
    return True


@contextmanager
def span(name: str, traceparent: Optional[str] = None, attrs: Optional[Dict[str, Any]] = None, kind: int = 5) -> Iterator[Span]:
    """A span for the work inside the block, continuing ``traceparent``
    when it is well formed, else the span in scope, else a new trace. Ends,
    and is exported, when the block does; an exception marks it an error and
    propagates."""
    parent = _current.get()
    cont = parse_traceparent(traceparent)
    if cont:
        trace_id, parent_id = cont
    elif parent is not None:
        trace_id, parent_id = parent.trace_id, parent.span_id
    else:
        trace_id, parent_id = _new_id(16), None
    s = Span(name, trace_id, parent_id, kind=kind)
    if attrs:
        s.attrs.update(attrs)
    token = _current.set(s)
    try:
        yield s
    except BaseException:
        s.error = True
        raise
    finally:
        _current.reset(token)
        s.end_ns = time.time_ns()
        if _exporter is not None:
            _exporter.put(s)


def current_trace_id() -> Optional[str]:
    """The trace id (hex) of the span in scope, or None."""
    s = _current.get()
    return s.trace_id if s else None


def current_span_id() -> Optional[str]:
    """The span id (hex) of the span in scope, or None."""
    s = _current.get()
    return s.span_id if s else None
