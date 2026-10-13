# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PersonifAI LLC

"""Pre-wired `httpx` clients: base URL, TLS, client cert, auth and timeout
from one `GatewaySettings`, plus `*_json` helpers that turn the gateway's
refusals into typed exceptions.

They are thin. Everything `httpx.AsyncClient` / `httpx.Client` can do, these
can do; the helpers exist so an add-on does not re-derive "what does a 403
body look like" at every call site.
"""

from __future__ import annotations

from typing import Any

import httpx

from .auth import GatewayAuth
from .errors import GatewayRefused, GatewayResponseError, GatewayThrottled, reason_from_body
from .settings import GatewaySettings


def _client_kwargs(settings: GatewaySettings, kwargs: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "base_url": settings.url,
        "verify": settings.verify,
        "cert": settings.cert,
        "auth": GatewayAuth(settings),
        "timeout": settings.timeout,
    }
    if settings.transport is not None:
        out["transport"] = settings.transport
    out.update(kwargs)
    return out


def raise_for_gateway(response: httpx.Response) -> None:
    """Raise the typed error for a non-2xx answer; return on 2xx.

    401/403 → `GatewayRefused`; 429 → `GatewayThrottled` (with
    `retry_after` from the body or the header); anything else non-2xx →
    `GatewayResponseError`. The body's reason travels on every one.
    """
    if response.is_success:
        return
    method = response.request.method
    path = response.request.url.path
    try:
        body: Any = response.json()
    except Exception:  # noqa: BLE001 — not JSON is a reason too
        body = response.text
    reason = reason_from_body(body)
    status = response.status_code
    if status in (401, 403):
        raise GatewayRefused(status, method, path, reason)
    if status == 429:
        retry_after: float | None = None
        if isinstance(body, dict):
            ra = body.get("retry_after")
            if isinstance(ra, (int, float)):
                retry_after = float(ra)
        if retry_after is None and response.headers.get("retry-after"):
            try:
                retry_after = float(response.headers["retry-after"])
            except ValueError:
                retry_after = None
        raise GatewayThrottled(method, path, retry_after, reason)
    raise GatewayResponseError(status, method, path, reason)


def _json_of(response: httpx.Response) -> Any:
    raise_for_gateway(response)
    if not response.content:
        return None
    return response.json()


class AsyncGatewayClient(httpx.AsyncClient):
    """`httpx.AsyncClient` pointed at the gateway with `GatewayAuth` attached.

        settings = GatewaySettings.from_env(consumer="svc:evolve")
        async with AsyncGatewayClient(settings) as gw:
            body = await gw.post_json("/api/temporal/adaptations", {"edges": [...]})

    Any `httpx.AsyncClient` keyword may be passed and overrides the settings.
    """

    def __init__(self, settings: GatewaySettings, **kwargs: Any) -> None:
        self.settings = settings
        super().__init__(**_client_kwargs(settings, kwargs))

    @property
    def gateway_auth(self) -> GatewayAuth:
        auth = self.auth
        assert isinstance(auth, GatewayAuth)
        return auth

    async def get_json(self, path: str, **kwargs: Any) -> Any:
        return _json_of(await self.get(path, **kwargs))

    async def post_json(self, path: str, json: Any = None, **kwargs: Any) -> Any:
        return _json_of(await self.post(path, json=json, **kwargs))

    async def put_json(self, path: str, json: Any = None, **kwargs: Any) -> Any:
        return _json_of(await self.put(path, json=json, **kwargs))


class GatewayClient(httpx.Client):
    """Sync twin of `AsyncGatewayClient` — for sync callers and for the
    `http_client` an OpenAI SDK wraps (`api_key="unused"`; the auth is here)."""

    def __init__(self, settings: GatewaySettings, **kwargs: Any) -> None:
        self.settings = settings
        super().__init__(**_client_kwargs(settings, kwargs))

    @property
    def gateway_auth(self) -> GatewayAuth:
        auth = self.auth
        assert isinstance(auth, GatewayAuth)
        return auth

    def get_json(self, path: str, **kwargs: Any) -> Any:
        return _json_of(self.get(path, **kwargs))

    def post_json(self, path: str, json: Any = None, **kwargs: Any) -> Any:
        return _json_of(self.post(path, json=json, **kwargs))

    def put_json(self, path: str, json: Any = None, **kwargs: Any) -> Any:
        return _json_of(self.put(path, json=json, **kwargs))
