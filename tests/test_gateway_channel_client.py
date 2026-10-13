# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Port-lane item 8 — outbound channel sends go through the Rust gateway.

Pins GatewayChannelClient's consumer-facing surface (the slice of
ChannelManager the proactive loop / coding notify / approval ping used)
and the wire shape of the dispatch POST."""

from __future__ import annotations

from noomesh.channels.gateway_client import GatewayChannelClient


def _clear_channel_env(monkeypatch):
    for keys in (
        ("WHATSAPP_TOKEN", "WHATSAPP_PHONE_ID"),
        ("TELEGRAM_BOT_TOKEN",),
        ("GOOGLE_CHAT_CREDENTIALS", "GOOGLE_CHAT_BEARER_TOKEN"),
    ):
        for k in keys:
            monkeypatch.delenv(k, raising=False)


def test_list_channels_env_detection(monkeypatch):
    _clear_channel_env(monkeypatch)
    client = GatewayChannelClient()
    assert client.list_channels() == []

    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("GOOGLE_CHAT_CREDENTIALS", "/x.json")
    assert set(client.list_channels()) == {"telegram", "google_chat"}


def test_get_adapter_is_configured_sentinel(monkeypatch):
    _clear_channel_env(monkeypatch)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    client = GatewayChannelClient()
    assert client.get_adapter("telegram") is client
    assert client.get_adapter("google_chat") is None
    assert client.get_adapter("nonsense") is None


async def test_resolve_concrete_recipient_passes_through():
    client = GatewayChannelClient()
    assert await client.resolve_recipient("telegram", "12345") == "12345"


async def test_dispatch_posts_send_body(monkeypatch):
    """dispatch() must POST channel/recipient/message (+optional thread_id)
    to {gateway}/api/channels/send and report the payload-level success."""
    import noomesh.channels.gateway_client as gc

    calls = {}

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"success": True}

    class FakeClient:
        def __init__(self, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None):
            calls["url"] = url
            calls["json"] = json
            calls["headers"] = headers
            return FakeResponse()

    monkeypatch.setattr(gc.httpx, "AsyncClient", FakeClient)
    monkeypatch.setenv("NOO_GATEWAY_URL", "https://gw.test:8080")
    monkeypatch.delenv("NOO_CLUSTER_SECRET", raising=False)

    client = GatewayChannelClient()
    ok = await client.dispatch(
        "telegram", "42", "hello", thread_id="th1", rich_blocks=[{"x": 1}]
    )
    assert ok is True
    assert calls["url"] == "https://gw.test:8080/api/channels/send"
    assert calls["json"] == {
        "channel": "telegram",
        "recipient": "42",
        "message": "hello",
        "thread_id": "th1",
    }
    # rich_blocks is absorbed, never forwarded — the Rust route has no field.
    assert "rich_blocks" not in calls["json"]


async def test_dispatch_reports_payload_failure(monkeypatch):
    import noomesh.channels.gateway_client as gc

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"success": False, "error": "no such recipient"}

    class FakeClient:
        def __init__(self, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **kw):
            return FakeResponse()

    monkeypatch.setattr(gc.httpx, "AsyncClient", FakeClient)
    client = GatewayChannelClient()
    assert await client.dispatch("telegram", "42", "hello") is False
