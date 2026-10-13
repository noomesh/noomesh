# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PersonifAI LLC

"""`Counters`: an add-on's metrics, batched to the gateway's two doors.

`inc(name, value=1, **labels)` sums in memory and flushes as ONE
`POST /api/metrics/increment` per (name, labels); `gauge(name, value,
**labels)` keeps the last value and flushes to `POST /api/metrics/gauge`.
The flush runs every `flush_interval` seconds on a daemon thread, or sooner
once `max_pending` distinct series are waiting, and at `close()`.

It never raises, and it has ITS OWN circuit: a 401/403 (the key has no
`metrics` scope) or a 429 (the 256-series cap) stops sending for 300 s
with one warning, and never touches the auth lanes a real call rides on —
otherwise a missing `metrics` grant would push every real call onto the
fallback lane.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

from .client import GatewayClient
from .errors import GatewayAuthUnavailable
from .settings import METRICS_GAUGE_PATH, METRICS_INCREMENT_PATH, GatewaySettings

log = logging.getLogger("noo_gateway")

#: How long a refused or throttled flush silences the sink.
METRICS_CIRCUIT_SECS = 300.0
#: How long a transport failure silences it (the gateway is probably restarting).
METRICS_TRANSPORT_BACKOFF_SECS = 60.0

_Key = tuple[str, tuple[tuple[str, str], ...]]


def _key(name: str, labels: dict[str, Any]) -> _Key:
    return name, tuple(sorted((str(k), str(v)) for k, v in labels.items()))


class Counters:
    """One per process, built from the same settings as the client.

        counters = Counters(settings)
        counters.inc("embeddings_total", 1, model="harrier")
        counters.gauge("embedding_backlog", 42)
        ...
        counters.close()          # or `await counters.aclose()`
    """

    def __init__(
        self,
        settings: GatewaySettings,
        *,
        flush_interval: float = 15.0,
        max_pending: int = 200,
        client: GatewayClient | None = None,
        background: bool = True,
    ) -> None:
        self.settings = settings
        self.flush_interval = flush_interval
        self.max_pending = max_pending
        self._client = client or GatewayClient(settings, timeout=5.0)
        self._owns_client = client is None
        self._background = background
        self._lock = threading.Lock()
        self._counters: dict[_Key, float] = {}
        self._gauges: dict[_Key, float] = {}
        self._disabled_until = 0.0
        self._warned = False
        self._refused_names: set[str] = set()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._clock = _monotonic

    # ── recording ──────────────────────────────────────────────────────

    def inc(self, name: str, value: float = 1, **labels: Any) -> None:
        """Add `value` to the counter; sent as one summed increment per flush."""
        try:
            if value <= 0:
                return
            with self._lock:
                k = _key(name, labels)
                self._counters[k] = self._counters.get(k, 0.0) + float(value)
                n = len(self._counters) + len(self._gauges)
            self._after_record(n)
        except Exception:  # noqa: BLE001 — metrics must never break the caller
            pass

    def gauge(self, name: str, value: float, **labels: Any) -> None:
        """Set the gauge; the last value before a flush is what travels."""
        try:
            with self._lock:
                self._gauges[_key(name, labels)] = float(value)
                n = len(self._counters) + len(self._gauges)
            self._after_record(n)
        except Exception:  # noqa: BLE001
            pass

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._counters) + len(self._gauges)

    @property
    def disabled(self) -> bool:
        return self._clock() < self._disabled_until

    def _after_record(self, pending: int) -> None:
        if not self._background:
            return
        self._ensure_thread()
        if pending >= self.max_pending:
            self._wake.set()

    def _ensure_thread(self) -> None:
        if self._thread is not None or self._stop.is_set():
            return
        with self._lock:
            if self._thread is None:
                t = threading.Thread(target=self._run, name="noo-gateway-counters", daemon=True)
                self._thread = t
                t.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(self.flush_interval)
            self._wake.clear()
            if self._stop.is_set():
                break
            self.flush()

    # ── sending ────────────────────────────────────────────────────────

    def flush(self) -> None:
        """Send what is pending. Never raises; drops the batch on refusal."""
        try:
            self._flush()
        except Exception as exc:  # noqa: BLE001
            log.debug("gateway_metrics_flush_error consumer=%s: %r", self.settings.consumer, exc)

    def _take(self) -> tuple[dict[_Key, float], dict[_Key, float]]:
        with self._lock:
            counters, self._counters = self._counters, {}
            gauges, self._gauges = self._gauges, {}
        return counters, gauges

    def _flush(self) -> None:
        now = self._clock()
        if now < self._disabled_until:
            self._take()  # silenced: drop rather than grow without bound
            return
        counters, gauges = self._take()
        remainder: dict[_Key, float] = {}
        for (name, labels), total in counters.items():
            whole = int(total)
            if whole < 1:
                remainder[(name, labels)] = total
                continue
            if total - whole > 0:
                remainder[(name, labels)] = total - whole
            if not self._send(METRICS_INCREMENT_PATH, name, whole, labels):
                break
        else:
            for (name, labels), value in gauges.items():
                if not self._send(METRICS_GAUGE_PATH, name, value, labels):
                    break
        if remainder:
            with self._lock:
                for k, v in remainder.items():
                    self._counters[k] = self._counters.get(k, 0.0) + v

    def _send(self, path: str, name: str, value: float, labels: tuple[tuple[str, str], ...]) -> bool:
        """One POST; False means "stop this flush" (the sink is now silenced)."""
        consumer = self.settings.consumer
        if name in self._refused_names:
            return True
        try:
            resp = self._client.post(path, json={"name": name, "value": value, "labels": dict(labels)})
        except GatewayAuthUnavailable:
            self._silence(METRICS_CIRCUIT_SECS, "no credential can open the metrics door")
            return False
        except Exception as exc:  # noqa: BLE001 — transport
            self._silence(METRICS_TRANSPORT_BACKOFF_SECS, f"{type(exc).__name__}: {exc}", level=logging.DEBUG)
            return False
        if resp.is_success:
            return True
        reason = _reason(resp)
        if resp.status_code in (401, 403):
            self._silence(
                METRICS_CIRCUIT_SECS,
                f"HTTP {resp.status_code}: {reason} — the key has no `metrics` scope; add it to "
                "x-noo-addon in the overlay and re-run `noo security service-key provision <addon>`",
            )
            return False
        if resp.status_code == 429:
            self._silence(METRICS_CIRCUIT_SECS, f"HTTP 429: {reason} (the per-add-on series cap)")
            return False
        if resp.status_code == 400:
            # Malformed name or labels: the CALLER's bug, once per name.
            self._refused_names.add(name)
            log.warning(
                "gateway_metrics_refused consumer=%s name=%s status=400 reason=%s: not sending this series again",
                consumer, name, reason,
                # `metric`, not `name`: LogRecord already owns `name`.
                extra={"event": "gateway_metrics_refused", "consumer": consumer, "metric": name, "reason": reason},
            )
            return True
        self._silence(METRICS_TRANSPORT_BACKOFF_SECS, f"HTTP {resp.status_code}: {reason}", level=logging.DEBUG)
        return False

    def _silence(self, secs: float, reason: str, level: int = logging.WARNING) -> None:
        self._disabled_until = self._clock() + secs
        consumer = self.settings.consumer
        if level >= logging.WARNING and self._warned:
            level = logging.DEBUG
        if level >= logging.WARNING:
            self._warned = True
        log.log(
            level,
            "gateway_metrics_circuit_open consumer=%s reason=%s: not sending metrics for %ds",
            consumer, reason, int(secs),
            extra={"event": "gateway_metrics_circuit_open", "consumer": consumer, "reason": reason},
        )

    # ── lifecycle ──────────────────────────────────────────────────────

    def close(self) -> None:
        """Flush once more and stop the thread. Never raises."""
        self._stop.set()
        self._wake.set()
        t = self._thread
        if t is not None and t is not threading.current_thread():
            t.join(timeout=self.flush_interval + 5.0)
        self.flush()
        if self._owns_client:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001
                pass

    async def aflush(self) -> None:
        await asyncio.to_thread(self.flush)

    async def aclose(self) -> None:
        await asyncio.to_thread(self.close)

    def __enter__(self) -> Counters:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _reason(resp: Any) -> str:
    from .errors import reason_from_body

    try:
        return reason_from_body(resp.json())
    except Exception:  # noqa: BLE001
        return reason_from_body(resp.text)


def _monotonic() -> float:
    import time

    return time.monotonic()
