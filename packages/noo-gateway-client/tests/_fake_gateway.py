# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PersonifAI LLC

"""A fake gateway as an httpx transport — sync AND async — so every test
drives the real `httpx.Client` / `httpx.AsyncClient` under `GatewayAuth`.

Never monkeypatch `httpx.post`: a fake that accepts any kwargs shipped a
TypeError under ten green tests (trellion, 2026-09). The transport sees the
request httpx actually built.
"""

from __future__ import annotations

import itertools
import json
from dataclasses import dataclass, field

import httpx

from noo_gateway import GatewaySettings

CONTROL_PATH = "/api/temporal/adaptations"
INFERENCE_PATH = "/api/external/embeddings"
CHAT_PATH = "/v1/chat/completions"


@dataclass
class Seen:
    kind: str  # "sync" | "async": which transport method httpx called
    method: str
    path: str
    bearer: str | None
    lane: str  # what the fake gateway classified the bearer as


@dataclass
class FakeGateway(httpx.BaseTransport, httpx.AsyncBaseTransport):
    key: str
    door: str = "ok"  # ok | 404 | 401 | 403 | 503 | error | unreadable
    ttl: int = 600
    consumer: str = "svc:test"
    scopes: tuple[str, ...] = ("chat", "embeddings", "temporal", "metrics")
    #: control routes answer 403 to a token (the grant lacks the word)
    control_403: bool = False
    #: the inference surface answers 403 to a token (PR 421's shape)
    surface_refuses_token: bool = False
    #: metrics doors answer this status to any credential (None = 200)
    metrics_status: int | None = None
    seen: list[Seen] = field(default_factory=list)
    minted: list[str] = field(default_factory=list)
    revoked: set[str] = field(default_factory=set)
    _n: itertools.count = field(default_factory=itertools.count)

    # ── httpx transport surface ─────────────────────────────────────────

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self._answer(request, "sync")

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return self._answer(request, "async")

    # ── the gateway's rules, reduced ───────────────────────────────────

    def revoke_tokens(self) -> None:
        self.revoked.update(self.minted)

    @property
    def door_calls(self) -> list[Seen]:
        return [s for s in self.seen if s.path == "/api/addon/token"]

    def calls(self, path: str) -> list[Seen]:
        return [s for s in self.seen if s.path == path]

    def _classify(self, bearer: str | None) -> str:
        if not bearer:
            return "none"
        if bearer == self.key:
            return "key"
        if bearer in self.minted:
            return "revoked" if bearer in self.revoked else "token"
        return "unknown"

    def _answer(self, request: httpx.Request, kind: str) -> httpx.Response:
        auth = request.headers.get("Authorization")
        bearer = auth.removeprefix("Bearer ").strip() if auth and auth.startswith("Bearer ") else None
        path = request.url.path
        lane = self._classify(bearer)
        self.seen.append(Seen(kind, request.method, path, bearer, lane))

        if path == "/api/addon/token":
            return self._door(lane)

        if lane in ("none", "unknown", "revoked"):
            return _json(401, {"error": "unauthorized"})

        if path.startswith(("/v1/", "/api/external/")):
            if lane == "token" and self.surface_refuses_token:
                return _json(403, {"error": {"type": "forbidden", "message": "token refused on surface"}})
            return _json(200, {"ok": True, "lane": lane})

        # control route: token (with the scope); the raw key never
        if lane == "key":
            return _json(401, {"error": "a raw service key opens only the inference surface"})
        if path.startswith("/api/metrics/") and self.metrics_status is not None:
            return _json(self.metrics_status, {"error": f"metrics door says {self.metrics_status}", "retry_after": 30})
        if lane == "token" and self.control_403:
            return _json(403, {"error": "scope missing"})
        return _json(200, {"ok": True, "lane": lane})

    def _door(self, lane: str) -> httpx.Response:
        if lane != "key":
            return _json(401, {"error": {"type": "unauthorized", "message": "the door takes the key"}})
        if self.door == "404":
            return _json(404, {"error": "not found"})
        if self.door == "401":
            return _json(401, {"error": {"type": "unauthorized", "message": "key revoked"}})
        if self.door == "403":
            return _json(403, {"error": {"type": "addon_key_has_no_scopes", "message": "only addon"}})
        if self.door == "503":
            return _json(503, {"error": {"type": "no_jwt_secret", "message": "no secret"}})
        if self.door == "error":
            raise httpx.ConnectError("gateway down")
        if self.door == "unreadable":
            return httpx.Response(200, content=b"not json")
        tok = f"tok-{next(self._n)}"
        self.minted.append(tok)
        return _json(200, {"token": tok, "expires_in": self.ttl, "consumer": self.consumer,
                           "scopes": list(self.scopes)})


def _json(status: int, body: object) -> httpx.Response:
    return httpx.Response(status, content=json.dumps(body).encode(), headers={"content-type": "application/json"})


class Clock:
    """A monotonic clock the tests advance by hand."""

    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, secs: float) -> None:
        self.t += secs



def make_settings(gw: FakeGateway, **overrides: object) -> GatewaySettings:
    values: dict[str, object] = {
        "consumer": "svc:test",
        "url": "https://gw.test:8080",
        "key": gw.key,
        "transport": gw,
    }
    values.update(overrides)
    return GatewaySettings(**values)  # type: ignore[arg-type]

