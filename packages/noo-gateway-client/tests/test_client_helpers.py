# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PersonifAI LLC

"""The `*_json` helpers: typed errors carrying the gateway's reason."""

from __future__ import annotations

import json

import httpx
import pytest

from noo_gateway import (
    AsyncGatewayClient,
    GatewayClient,
    GatewayRefused,
    GatewayResponseError,
    GatewayThrottled,
    GatewaySettings,
    raise_for_gateway,
)
from _fake_gateway import CONTROL_PATH, FakeGateway, make_settings


def test_clients_carry_the_settings(gateway: FakeGateway, settings: GatewaySettings) -> None:
    with GatewayClient(settings) as gw:
        assert str(gw.base_url).rstrip("/") == settings.url
        assert gw.gateway_auth.settings is settings
        assert gw.timeout.read == settings.timeout
    with GatewayClient(settings, timeout=2.0) as gw:
        assert gw.timeout.read == 2.0, "an httpx keyword overrides the settings"


def test_refusal_carries_the_bodys_reason(gateway: FakeGateway, settings: GatewaySettings) -> None:
    gateway.control_403 = True
    with GatewayClient(settings) as gw, pytest.raises(GatewayRefused) as e:
        gw.post_json(CONTROL_PATH, {"x": 1})
    assert (e.value.status, e.value.method, e.value.path) == (403, "POST", CONTROL_PATH)
    assert e.value.reason == "scope missing"


async def test_async_helpers_too(gateway: FakeGateway, settings: GatewaySettings) -> None:
    gateway.control_403 = True
    async with AsyncGatewayClient(settings) as gw:
        assert (await gw.get_json("/api/external/embeddings"))["ok"] is True
        with pytest.raises(GatewayRefused):
            await gw.put_json(CONTROL_PATH, {})


def _resp(status: int, body: object, **headers: str) -> httpx.Response:
    r = httpx.Response(status, content=json.dumps(body).encode(), headers=headers)
    r.request = httpx.Request("POST", "https://gw.test/api/x")
    return r


def test_raise_for_gateway_shapes() -> None:
    raise_for_gateway(_resp(200, {"ok": True}))
    with pytest.raises(GatewayRefused) as e:
        raise_for_gateway(_resp(401, {"error": {"type": "unauthorized", "message": "no"}}))
    assert e.value.reason == "unauthorized: no"
    with pytest.raises(GatewayThrottled) as t:
        raise_for_gateway(_resp(429, {"error": "consumer_quota_exceeded", "retry_after": 12}))
    assert t.value.retry_after == 12.0 and t.value.reason == "consumer_quota_exceeded"
    with pytest.raises(GatewayThrottled) as t2:
        raise_for_gateway(_resp(429, {"error": "x"}, **{"retry-after": "5"}))
    assert t2.value.retry_after == 5.0
    with pytest.raises(GatewayResponseError) as r:
        raise_for_gateway(_resp(500, {"detail": "boom"}))
    assert r.value.status == 500 and r.value.reason == "boom"
    with pytest.raises(GatewayResponseError) as r2:
        raise_for_gateway(httpx.Response(502, content=b"<html>bad gateway</html>",
                                         request=httpx.Request("GET", "https://gw.test/y")))
    assert "bad gateway" in r2.value.reason


def test_empty_success_body_is_none(gateway: FakeGateway) -> None:
    class Empty(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/addon/token":
                return gateway.handle_request(request)
            return httpx.Response(204)

    settings = make_settings(gateway, transport=Empty())
    with GatewayClient(settings) as gw:
        assert gw.get_json("/api/x") is None
