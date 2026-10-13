# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PersonifAI LLC

"""`GatewayAuth`: the ONE way a request to the gateway gets its credential.

An `httpx.Auth` with both flows, so the same object goes on a sync
`httpx.Client`, an `httpx.AsyncClient`, or the `http_client` an OpenAI SDK
wraps. No public function here returns a header dict — that is what makes
"no call site builds an `Authorization` header by hand" a rule a test can
hold (the 2026-09-22 storm was a per-request `headers=` on a client without
`auth=`, so the refusal circuit never saw the 17,000 refusals an hour).

The ladder, chosen PER REQUEST, because the gateway accepts a raw service
key only on the inference surface (`/v1/*`, `/api/external/*`) and the
exchange door, while a control route (`/api/temporal/…`, `/api/metrics/…`,
`PUT /api/config/…`) opens only to an exchanged token:

    key configured?
     ├─ yes ─ token cached & fresh & not cooling down ─→ Bearer <token>
     │        else exchange (single-flight) ─ ok → Bearer <token>
     │                                     └ fail → 300 s cooldown, then:
     │          inference route                     → Bearer <raw key>
     │          control route                       → GatewayAuthUnavailable, nothing sent
     └─ no ── GatewayAuthUnavailable, nothing sent

Answers while presenting a TOKEN: 401 = the token is dead (key revoked,
JWT secret rotated): drop it, cool down, retry ONCE down the ladder. 403 on
the inference surface = the door minted a token its own surface refuses
(noomesh PR 421): retry once with the key, which carries the same grant.
403 on a control route = the grant lacks the word: SURFACED, never hidden
behind any other credential, and logged once with the provision hint. The
client has no shared-secret lane at all: it authenticates
only with the add-on's own key, and an add-on with no key sends nothing.

The circuit: three consecutive refusals on a lane open it for 300 s. An
open lane is skipped; when no lane is left, `GatewayAuthUnavailable` is
raised locally and the gateway sees nothing. One log line when a circuit
opens, one when it closes, both naming the consumer.

Token state is shared per process, keyed by (url, key fingerprint), so the
sync and async flows — and every client in the process — reuse one token
and one circuit. The async flow never does blocking I/O: its exchange goes
through an `httpx.AsyncClient`.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import AsyncGenerator, Generator
from typing import Any

import httpx

from .errors import GatewayAuthUnavailable, reason_from_body
from .settings import ADDON_TOKEN_PATH, GatewaySettings, is_inference_surface

log = logging.getLogger("noo_gateway")

LANE_TOKEN = "token"
LANE_KEY = "key"

#: Refresh this far before the token expires. A token that dies mid-flight
#: is a 401 the caller cannot tell from a revoked key.
REFRESH_MARGIN_SECS = 60.0
#: After a failed exchange or a refused token, do not exchange again for this
#: long. Without it a gateway that predates the door is asked on EVERY call.
COOLDOWN_SECS = 300.0
#: Consecutive refusals on one lane that open its circuit …
CIRCUIT_TRIPS = 3
#: … for this long.
CIRCUIT_OPEN_SECS = 300.0
#: How often a repeated condition (fallback, control-route 403) is logged.
LOG_WINDOW_SECS = 300.0

_PROVISION_HINT = (
    "the key's grant lacks the scope for this route. Check x-noo-addon in the "
    "overlay, then run `noo security service-key provision <addon>`"
)


def _now() -> float:
    return time.monotonic()


class _Circuit:
    """Three consecutive refusals open it for `CIRCUIT_OPEN_SECS`."""

    def __init__(self) -> None:
        self.failures = 0
        self.open_until = 0.0
        self.announced_open = False

    def refusal(self, now: float) -> bool:
        """Record one; True when THIS refusal opened the circuit."""
        self.failures += 1
        if self.failures >= CIRCUIT_TRIPS and now >= self.open_until:
            self.open_until = now + CIRCUIT_OPEN_SECS
            self.failures = 0
            self.announced_open = True
            return True
        return False

    def success(self) -> None:
        self.failures = 0

    def is_open(self, now: float) -> bool:
        return now < self.open_until

    def just_closed(self, now: float) -> bool:
        """True once, the first time it is consulted after opening and expiring."""
        if self.announced_open and now >= self.open_until:
            self.announced_open = False
            return True
        return False


class _State:
    """Per-credential state shared by every `GatewayAuth` in the process."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.async_locks: dict[int, asyncio.Lock] = {}
        self.token: str | None = None
        self.token_good_until = 0.0
        self.confirmed_consumer: str | None = None
        self.cooldown_until = 0.0
        self.circuits = {LANE_TOKEN: _Circuit(), LANE_KEY: _Circuit()}
        self.logged_until: dict[str, float] = {}
        self.door_absent_logged = False

    def async_lock(self) -> asyncio.Lock:
        loop_id = id(asyncio.get_running_loop())
        lock = self.async_locks.get(loop_id)
        if lock is None:
            lock = self.async_locks[loop_id] = asyncio.Lock()
        return lock

    def once_per_window(self, key: str, now: float) -> bool:
        if now < self.logged_until.get(key, 0.0):
            return False
        self.logged_until[key] = now + LOG_WINDOW_SECS
        return True


_states: dict[tuple[str, str], _State] = {}
_states_lock = threading.Lock()


def _state_for(settings: GatewaySettings) -> _State:
    key = (settings.url, settings.key_fingerprint or "no-key")
    with _states_lock:
        state = _states.get(key)
        if state is None:
            state = _states[key] = _State()
        return state


class GatewayAuth(httpx.Auth):
    """Attach to any `httpx` client: `httpx.AsyncClient(auth=GatewayAuth(settings), …)`.

    Prefer `AsyncGatewayClient` / `GatewayClient`, which also carry
    `base_url`, `verify`, `cert` and the test transport from the settings.
    """

    requires_request_body = False
    requires_response_body = False

    def __init__(self, settings: GatewaySettings) -> None:
        self.settings = settings
        self._state = _state_for(settings)

    # ── state a caller may inspect or reset ────────────────────────────

    @property
    def consumer(self) -> str:
        """The name the exchange confirmed, else the configured one."""
        return self._state.confirmed_consumer or self.settings.consumer

    def forget(self) -> None:
        """Drop the cached token, the cooldown and every circuit for this
        credential — after a rotation, or between tests."""
        with self._state.lock:
            self._state.token = None
            self._state.token_good_until = 0.0
            self._state.cooldown_until = 0.0
            self._state.confirmed_consumer = None
            self._state.circuits = {LANE_TOKEN: _Circuit(), LANE_KEY: _Circuit()}
            self._state.logged_until.clear()
            self._state.door_absent_logged = False

    # ── the two flows ──────────────────────────────────────────────────

    def sync_auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        attempts = 0
        tried: set[str] = set()
        while True:
            lane = self._next_lane(request, tried)
            tried.add(lane)
            if lane == LANE_TOKEN:
                credential = self._token_sync()
                if credential is None:
                    continue
            else:
                credential = self._lane_credential(lane)
            request.headers["Authorization"] = f"Bearer {credential}"
            response = yield request
            attempts += 1
            if not self._wants_retry(lane, request, response) or attempts >= 2:
                return

    async def async_auth_flow(self, request: httpx.Request) -> AsyncGenerator[httpx.Request, httpx.Response]:
        attempts = 0
        tried: set[str] = set()
        while True:
            lane = self._next_lane(request, tried)
            tried.add(lane)
            if lane == LANE_TOKEN:
                credential = await self._token_async()
                if credential is None:
                    continue
            else:
                credential = self._lane_credential(lane)
            request.headers["Authorization"] = f"Bearer {credential}"
            response = yield request
            attempts += 1
            if not self._wants_retry(lane, request, response) or attempts >= 2:
                return

    # ── the ladder ─────────────────────────────────────────────────────

    def _ladder(self, path: str) -> list[str]:
        s = self.settings
        lanes: list[str] = []
        if s.key:
            lanes.append(LANE_TOKEN)
            if is_inference_surface(path):
                lanes.append(LANE_KEY)
        return lanes

    def _next_lane(self, request: httpx.Request, tried: set[str]) -> str:
        """The first lane not yet tried whose circuit is closed, else raise."""
        now = _now()
        path = request.url.path
        ladder = self._ladder(path)
        for lane in ladder:
            circuit = self._state.circuits[lane]
            if circuit.just_closed(now):
                log.info(
                    "gateway_auth_circuit_closed consumer=%s lane=%s",
                    self.consumer, lane,
                    extra={"event": "gateway_auth_circuit_closed", "consumer": self.consumer, "lane": lane},
                )
            if lane in tried or circuit.is_open(now):
                continue
            return lane
        reason = self._unavailable_reason(ladder, tried, now)
        if self._state.once_per_window(f"unavailable:{path}", now):
            log.error(
                "gateway_auth_unavailable consumer=%s method=%s path=%s reason=%s: nothing sent",
                self.consumer, request.method, path, reason,
                extra={"event": "gateway_auth_unavailable", "consumer": self.consumer,
                       "method": request.method, "path": path, "reason": reason},
            )
        raise GatewayAuthUnavailable(request.method, path, reason)

    def _unavailable_reason(self, ladder: list[str], tried: set[str], now: float) -> str:
        s = self.settings
        if not s.key:
            return (
                "no NOO_GATEWAY_KEY configured — this add-on has no gateway credential; "
                "run `noo security service-key provision <addon>`"
            )
        if not ladder:
            return "no lane applies"
        parts = []
        for lane in ladder:
            if self._state.circuits[lane].is_open(now):
                parts.append(f"{lane} circuit open")
            elif lane in tried:
                parts.append(f"{lane} refused")
            elif lane == LANE_TOKEN:
                parts.append("exchange failed or cooling down")
        if not is_inference_surface_ladder(ladder):
            parts.append("the raw key is not accepted on a control route")
        return "; ".join(parts) or "every lane exhausted"

    def _lane_credential(self, lane: str) -> str:
        s = self.settings
        if lane == LANE_KEY:
            assert s.key is not None
            return s.key
        raise AssertionError(lane)

    # ── what the answer means ──────────────────────────────────────────

    def _wants_retry(self, lane: str, request: httpx.Request, response: httpx.Response) -> bool:
        st = self._state
        now = _now()
        status = response.status_code
        method, path = request.method, request.url.path
        if status not in (401, 403):
            st.circuits[lane].success()
            return False
        fields = {"event": "gateway_auth_refused", "consumer": self.consumer, "lane": lane,
                  "status": status, "method": method, "path": path}
        if lane == LANE_TOKEN and status == 403 and not is_inference_surface(path):
            # The token is valid; the grant lacks the word. Never fall back:
            # no other credential may hide the missing scope.
            if st.once_per_window(f"scope:{method} {path}", now):
                log.error(
                    "gateway_auth_refused consumer=%s lane=token status=403 method=%s path=%s next=none: %s",
                    self.consumer, method, path, _PROVISION_HINT, extra=fields,
                )
            return False
        if lane == LANE_TOKEN:
            # 401: the token is dead. 403 on the inference surface: the door
            # minted a token its own surface refuses (PR 421). Either way
            # drop it, cool down, and try the next lane once.
            with st.lock:
                st.token = None
                st.token_good_until = 0.0
                st.cooldown_until = now + COOLDOWN_SECS
                opened = st.circuits[LANE_TOKEN].refusal(now)
            nxt = self._next_after_token(path, now)
            log.warning(
                "gateway_auth_refused consumer=%s lane=token status=%s method=%s path=%s next=%s: "
                "dropping the exchanged token for %ss",
                self.consumer, status, method, path, nxt, int(COOLDOWN_SECS),
                extra={**fields, "next": nxt},
            )
            if opened:
                self._announce_open(LANE_TOKEN)
            return nxt != "none"
        # The raw key was refused outright: nothing below it.
        with st.lock:
            opened = st.circuits[lane].refusal(now)
        log.warning(
            "gateway_auth_refused consumer=%s lane=%s status=%s method=%s path=%s next=none",
            self.consumer, lane, status, method, path, extra=fields,
        )
        if opened:
            self._announce_open(lane)
        return False

    def _next_after_token(self, path: str, now: float) -> str:
        for lane in self._ladder(path)[1:]:
            if not self._state.circuits[lane].is_open(now):
                return lane
        return "none"

    def _announce_open(self, lane: str) -> None:
        log.error(
            "gateway_auth_circuit_open consumer=%s lane=%s: %d consecutive refusals; "
            "not presenting this credential for %ds",
            self.consumer, lane, CIRCUIT_TRIPS, int(CIRCUIT_OPEN_SECS),
            extra={"event": "gateway_auth_circuit_open", "consumer": self.consumer, "lane": lane},
        )

    # ── the exchange ───────────────────────────────────────────────────

    def _cached_token(self, now: float) -> str | None:
        st = self._state
        if st.token and now < st.token_good_until:
            return st.token
        return None

    def _may_exchange(self, now: float) -> bool:
        st = self._state
        return now >= st.cooldown_until and not st.circuits[LANE_TOKEN].is_open(now)

    def _token_sync(self) -> str | None:
        st = self._state
        now = _now()
        if (tok := self._cached_token(now)) is not None:
            return tok
        with st.lock:
            now = _now()
            if (tok := self._cached_token(now)) is not None:
                return tok
            if not self._may_exchange(now):
                return None
            s = self.settings
            try:
                with httpx.Client(
                    verify=s.verify, cert=s.cert, timeout=s.exchange_timeout,
                    transport=s.transport,  # type: ignore[arg-type]
                ) as client:
                    resp = client.post(s.url + ADDON_TOKEN_PATH, headers=self._exchange_header())
                    resp.read()
            except Exception as exc:  # noqa: BLE001 — any transport failure is one outcome
                return self._absorb_exchange(None, exc)
            return self._absorb_exchange(resp, None)

    async def _token_async(self) -> str | None:
        st = self._state
        now = _now()
        if (tok := self._cached_token(now)) is not None:
            return tok
        async with st.async_lock():
            now = _now()
            if (tok := self._cached_token(now)) is not None:
                return tok
            if not self._may_exchange(now):
                return None
            s = self.settings
            try:
                async with httpx.AsyncClient(
                    verify=s.verify, cert=s.cert, timeout=s.exchange_timeout,
                    transport=s.transport,  # type: ignore[arg-type]
                ) as client:
                    resp = await client.post(s.url + ADDON_TOKEN_PATH, headers=self._exchange_header())
                    await resp.aread()
            except Exception as exc:  # noqa: BLE001
                with st.lock:
                    return self._absorb_exchange(None, exc)
            with st.lock:
                return self._absorb_exchange(resp, None)

    def _exchange_header(self) -> dict[str, str]:
        # Internal: the door is the ONE place the raw key goes off-surface.
        assert self.settings.key is not None
        return {"Authorization": f"Bearer {self.settings.key}"}

    def _absorb_exchange(self, resp: httpx.Response | None, exc: BaseException | None) -> str | None:
        """Turn the door's answer into a token, or a cooldown and a log line.
        Called under the state lock."""
        st = self._state
        now = _now()
        consumer = self.consumer
        base = {"event": "gateway_auth_refused", "consumer": consumer, "lane": LANE_TOKEN,
                "method": "POST", "path": ADDON_TOKEN_PATH}
        if exc is not None:
            st.cooldown_until = now + COOLDOWN_SECS
            log.warning(
                "addon_token_exchange_failed consumer=%s: %s: %s (falling down the ladder for %ss)",
                consumer, type(exc).__name__, exc, int(COOLDOWN_SECS),
                extra={**base, "event": "addon_token_exchange_failed", "reason": type(exc).__name__},
            )
            return None
        assert resp is not None
        status = resp.status_code
        if status == 200:
            body: Any = None
            try:
                body = resp.json()
                token = str(body["token"])
                ttl = float(body.get("expires_in") or 0)
            except Exception as e:  # noqa: BLE001
                st.cooldown_until = now + COOLDOWN_SECS
                log.warning(
                    "addon_token_exchange_unreadable consumer=%s: %s", consumer, e,
                    extra={**base, "event": "addon_token_exchange_unreadable"},
                )
                return None
            if not token or ttl <= 0:
                st.cooldown_until = now + COOLDOWN_SECS
                log.warning(
                    "addon_token_exchange_unreadable consumer=%s: empty token or ttl", consumer,
                    extra={**base, "event": "addon_token_exchange_unreadable"},
                )
                return None
            st.token = token
            st.token_good_until = now + max(ttl - REFRESH_MARGIN_SECS, 1.0)
            confirmed = body.get("consumer") if isinstance(body, dict) else None
            if isinstance(confirmed, str) and confirmed:
                st.confirmed_consumer = confirmed
            st.circuits[LANE_TOKEN].success()
            return token
        st.cooldown_until = now + COOLDOWN_SECS
        try:
            reason = reason_from_body(resp.json())
        except Exception:  # noqa: BLE001
            reason = reason_from_body(resp.text)
        fields = {**base, "status": status, "reason": reason}
        if status == 404:
            if not st.door_absent_logged:
                st.door_absent_logged = True
                log.info(
                    "addon_token_exchange_unavailable consumer=%s status=404: this gateway has no "
                    "exchange door; presenting the key on the inference surface only",
                    consumer, extra={**fields, "event": "addon_token_exchange_unavailable"},
                )
            return None
        if status == 401:
            opened = st.circuits[LANE_TOKEN].refusal(now)
            log.error(
                "addon_token_exchange_refused consumer=%s status=401 reason=%s: the key is unknown or "
                "revoked; re-provision it (`noo security service-key provision <addon>`)",
                consumer, reason, extra=fields,
            )
        elif status == 403:
            opened = st.circuits[LANE_TOKEN].refusal(now)
            log.error(
                "addon_token_exchange_refused consumer=%s status=403 reason=%s: %s",
                consumer, reason, _PROVISION_HINT, extra=fields,
            )
        elif status == 503:
            opened = False
            log.warning(
                "addon_token_exchange_unavailable consumer=%s status=503 reason=%s",
                consumer, reason, extra={**fields, "event": "addon_token_exchange_unavailable"},
            )
        else:
            opened = False
            log.warning(
                "addon_token_exchange_failed consumer=%s status=%s reason=%s",
                consumer, status, reason, extra={**fields, "event": "addon_token_exchange_failed"},
            )
        if opened:
            self._announce_open(LANE_TOKEN)
        return None


def is_inference_surface_ladder(ladder: list[str]) -> bool:
    return LANE_KEY in ladder
