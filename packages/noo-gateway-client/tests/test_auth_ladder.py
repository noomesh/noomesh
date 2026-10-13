# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PersonifAI LLC

"""The ladder, per request, under the real httpx clients."""

from __future__ import annotations

import asyncio
import logging

import httpx
import pytest

from noo_gateway import (
    AsyncGatewayClient,
    GatewayAuth,
    GatewayAuthUnavailable,
    GatewayClient,
    GatewaySettings,
)
from noo_gateway.auth import CIRCUIT_OPEN_SECS, CIRCUIT_TRIPS, COOLDOWN_SECS
from _fake_gateway import CHAT_PATH, CONTROL_PATH, INFERENCE_PATH, FakeGateway, make_settings


# ── the token travels ───────────────────────────────────────────────────


def test_sync_exchanged_token_travels_and_is_reused(gateway: FakeGateway, settings) -> None:
    with GatewayClient(settings) as gw:
        assert gw.get_json(CONTROL_PATH)["lane"] == "token"
        assert gw.post_json(INFERENCE_PATH, {"input": "x"})["lane"] == "token"
    assert len(gateway.door_calls) == 1, "one exchange per token lifetime"
    assert gateway.door_calls[0].lane == "key", "the door is opened with the key"
    assert [s.lane for s in gateway.calls(CONTROL_PATH)] == ["token"]


async def test_async_exchanged_token_travels_without_sync_io(gateway: FakeGateway, settings) -> None:
    async with AsyncGatewayClient(settings) as gw:
        assert (await gw.get_json(CONTROL_PATH))["lane"] == "token"
    door = gateway.door_calls
    assert len(door) == 1
    assert door[0].kind == "async", "the async flow must exchange through an AsyncClient"
    assert all(s.kind == "async" for s in gateway.seen)


def test_sync_and_async_share_one_token(gateway: FakeGateway, settings) -> None:
    with GatewayClient(settings) as gw:
        gw.get_json(CONTROL_PATH)

    async def go() -> None:
        async with AsyncGatewayClient(settings) as agw:
            await agw.get_json(CONTROL_PATH)

    asyncio.run(go())
    assert len(gateway.door_calls) == 1
    assert len({s.bearer for s in gateway.calls(CONTROL_PATH)}) == 1


def test_the_key_only_ever_goes_to_the_door_off_surface(gateway: FakeGateway, settings) -> None:
    gateway.door = "404"  # no door: the key is presented on the surface, nothing elsewhere
    with GatewayClient(settings) as gw:
        assert gw.get_json(INFERENCE_PATH)["lane"] == "key"
        with pytest.raises(GatewayAuthUnavailable):
            gw.get(CONTROL_PATH)
    off_surface_key = [s for s in gateway.seen if s.lane == "key" and s.path != "/api/addon/token"
                       and not s.path.startswith(("/v1/", "/api/external/"))]
    assert off_surface_key == []


async def test_n_concurrent_async_calls_exchange_once(gateway: FakeGateway, settings) -> None:
    async with AsyncGatewayClient(settings) as gw:
        results = await asyncio.gather(*(gw.get_json(CONTROL_PATH) for _ in range(12)))
    assert all(r["lane"] == "token" for r in results)
    assert len(gateway.door_calls) == 1, "single-flight: one exchange for a burst"


def test_refresh_sixty_seconds_before_expiry(gateway: FakeGateway, settings, clock) -> None:
    with GatewayClient(settings) as gw:
        gw.get_json(CONTROL_PATH)
        clock.advance(gateway.ttl - 61)
        gw.get_json(CONTROL_PATH)
        assert len(gateway.door_calls) == 1, "still fresh at exp - 61 s"
        clock.advance(2)
        gw.get_json(CONTROL_PATH)
        assert len(gateway.door_calls) == 2, "refreshed at exp - 59 s"
    assert gateway.calls(CONTROL_PATH)[-1].bearer == gateway.minted[-1]


# ── the door's answers ──────────────────────────────────────────────────


@pytest.mark.parametrize("door", ["404", "401", "403", "503", "error", "unreadable"])
def test_a_failed_exchange_cools_down_and_takes_the_right_lane_per_surface(
    gateway: FakeGateway, settings, clock, door: str
) -> None:
    gateway.door = door
    with GatewayClient(settings) as gw:
        assert gw.get_json(INFERENCE_PATH)["lane"] == "key"
        # A configured key never falls back to any shared secret: nothing sent.
        with pytest.raises(GatewayAuthUnavailable):
            gw.get(CONTROL_PATH)
        assert gateway.calls(CONTROL_PATH) == []
        gw.get_json(CHAT_PATH)
        assert len(gateway.door_calls) == 1, "one attempt per cooldown, not one per call"
        clock.advance(COOLDOWN_SECS + 1)
        gw.get_json(CHAT_PATH)
        assert len(gateway.door_calls) == 2, "asked again after the cooldown"


def test_a_door_that_appears_is_used_after_the_cooldown(gateway: FakeGateway, settings, clock) -> None:
    gateway.door = "404"
    with GatewayClient(settings) as gw:
        with pytest.raises(GatewayAuthUnavailable):
            gw.get(CONTROL_PATH)
        gateway.door = "ok"
        clock.advance(COOLDOWN_SECS + 1)
        assert gw.get_json(CONTROL_PATH)["lane"] == "token"


# ── refusals while presenting a token ───────────────────────────────────


def test_401_with_token_drops_it_and_retries_once_down_the_ladder(gateway: FakeGateway, settings) -> None:
    with GatewayClient(settings) as gw:
        gw.get_json(CONTROL_PATH)
        gateway.revoke_tokens()  # the JWT secret rotated
        # The control route has no next lane for a keyed add-on: the dead
        # token's 401 is surfaced, never retried on another credential.
        assert gw.get(CONTROL_PATH).status_code == 401
        assert gw.get_json(INFERENCE_PATH)["lane"] == "key"
    lanes = [s.lane for s in gateway.calls(CONTROL_PATH)]
    assert lanes == ["token", "revoked"], "no fallback"
    assert len(gateway.door_calls) == 1, "cooling down: no re-exchange on the retry"


def test_403_with_token_on_the_inference_surface_retries_with_the_key(gateway: FakeGateway, settings) -> None:
    gateway.surface_refuses_token = True
    with GatewayClient(settings) as gw:
        assert gw.post_json(INFERENCE_PATH, {"input": "x"})["lane"] == "key"
    assert [s.lane for s in gateway.calls(INFERENCE_PATH)] == ["token", "key"]


def test_403_with_token_on_a_control_route_is_surfaced_and_logged_once(
    gateway: FakeGateway, settings, caplog: pytest.LogCaptureFixture
) -> None:
    gateway.control_403 = True
    caplog.set_level(logging.INFO, logger="noo_gateway")
    with GatewayClient(settings) as gw:
        for _ in range(3):
            r = gw.get(CONTROL_PATH)
            assert r.status_code == 403
        # the token is valid: the inference surface still takes it
        assert gw.get_json(INFERENCE_PATH)["lane"] == "token"
    assert [s.lane for s in gateway.calls(CONTROL_PATH)] == ["token"] * 3, "never another credential"
    refusals = [r for r in caplog.records if r.getMessage().startswith("gateway_auth_refused")]
    assert len(refusals) == 1, [r.getMessage() for r in refusals]
    assert refusals[0].levelno == logging.ERROR
    assert "service-key provision" in refusals[0].getMessage()
    assert "svc:test" in refusals[0].getMessage()


def test_a_keyed_addon_with_the_door_down_sends_nothing_on_a_control_route(gateway: FakeGateway) -> None:
    """The retired NOO_GATEWAY_SHARED_SECRET_FALLBACK rung: the door down, a
    control route — nothing is sent, and no other lane is taken."""
    gateway.door = "404"
    settings = make_settings(gateway)
    assert settings.key
    with GatewayClient(settings) as gw:
        assert gw.get_json(INFERENCE_PATH)["lane"] == "key"
        with pytest.raises(GatewayAuthUnavailable) as e:
            gw.get(CONTROL_PATH)
    assert gateway.calls(CONTROL_PATH) == [], "nothing was sent"
    assert e.value.path == CONTROL_PATH
    assert {c.lane for c in gateway.seen} <= {"key", "none", "unknown"}


@pytest.mark.parametrize("path", [CONTROL_PATH, INFERENCE_PATH, "/api/health"])
def test_no_key_means_nothing_is_sent(gateway: FakeGateway, path: str) -> None:
    settings = make_settings(gateway, key=None)
    with GatewayClient(settings) as gw, pytest.raises(GatewayAuthUnavailable) as e:
        gw.get(path)
    assert "no NOO_GATEWAY_KEY configured" in e.value.reason
    assert "noo security service-key provision" in e.value.reason
    assert gateway.seen == []


@pytest.mark.parametrize("flavor", ["sync", "async"])
async def test_the_shared_secret_is_never_presented(
    gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch, flavor: str
) -> None:
    """Fails without the retirement: a container that holds the fleet/controller
    secrets and NO add-on key used to sign an HMAC and send it. Now the request
    dies locally and the gateway receives ZERO requests."""
    for k in ("NOO_GATEWAY_KEY", "NODE_ID"):
        monkeypatch.delenv(k, raising=False)
    env = {"NOO_CONTROLLER_SECRET": "ctl", "NOO_CLUSTER_SECRET": "fleet"}
    settings = GatewaySettings.from_env(
        "svc:test", env=env, url="https://gw.test:8080", transport=gateway
    )
    assert settings.key is None
    if flavor == "sync":
        with GatewayClient(settings) as gw:
            with pytest.raises(GatewayAuthUnavailable):
                gw.get(CONTROL_PATH)
            with pytest.raises(GatewayAuthUnavailable):
                gw.post(INFERENCE_PATH, json={})
    else:
        async with AsyncGatewayClient(settings) as agw:
            with pytest.raises(GatewayAuthUnavailable):
                await agw.get(CONTROL_PATH)
            with pytest.raises(GatewayAuthUnavailable):
                await agw.post(INFERENCE_PATH, json={})
    assert len(gateway.seen) == 0, "the transport saw no request: no secret was presented"


# ── the circuit ─────────────────────────────────────────────────────────


def test_the_circuit_opens_after_three_refusals_and_logs_once(
    gateway: FakeGateway, clock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="noo_gateway")
    settings = make_settings(gateway)
    gateway.key = "rotated-away"  # the key is refused everywhere
    with GatewayClient(settings) as gw:
        for _ in range(CIRCUIT_TRIPS):
            assert gw.get(INFERENCE_PATH).status_code == 401
        sent = len(gateway.calls(INFERENCE_PATH))
        assert sent == CIRCUIT_TRIPS
        for _ in range(5):
            with pytest.raises(GatewayAuthUnavailable):
                gw.get(INFERENCE_PATH)
        assert len(gateway.calls(INFERENCE_PATH)) == sent, "an open circuit sends nothing"
        opened = [r for r in caplog.records if r.getMessage().startswith("gateway_auth_circuit_open")]
        assert len(opened) == 1, "one line when it opens"
        assert "svc:test" in opened[0].getMessage() and "lane=key" in opened[0].getMessage()
        clock.advance(CIRCUIT_OPEN_SECS + 1)
        assert gw.get(INFERENCE_PATH).status_code == 401, "closed: traffic flows again"
        closed = [r for r in caplog.records
                  if r.getMessage().startswith("gateway_auth_circuit_closed") and "lane=key" in r.getMessage()]
        assert len(closed) == 1


def test_a_success_resets_the_count(gateway: FakeGateway, clock) -> None:
    settings = make_settings(gateway)
    good, bad = gateway.key, "other"
    with GatewayClient(settings) as gw:
        for _ in range(CIRCUIT_TRIPS - 1):
            gateway.key = bad
            assert gw.get(INFERENCE_PATH).status_code == 401
            gateway.key = good
            assert gw.get(INFERENCE_PATH).status_code == 200
        gateway.key = bad
        for _ in range(CIRCUIT_TRIPS - 1):
            assert gw.get(INFERENCE_PATH).status_code == 401
        gateway.key = good
        assert gw.get(INFERENCE_PATH).status_code == 200, "never reached three in a row"


def test_exchange_refusals_open_the_token_lane_and_the_surface_takes_the_key(
    gateway: FakeGateway, settings, clock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="noo_gateway")
    gateway.door = "401"
    with GatewayClient(settings) as gw:
        for i in range(CIRCUIT_TRIPS):
            if i:
                clock.advance(COOLDOWN_SECS + 1)  # past the cooldown, so the door is asked again
            assert gw.get_json(INFERENCE_PATH)["lane"] == "key"
        assert len(gateway.door_calls) == CIRCUIT_TRIPS
        clock.advance(CIRCUIT_OPEN_SECS - 1)  # still inside the circuit window
        gw.get_json(INFERENCE_PATH)
        assert len(gateway.door_calls) == CIRCUIT_TRIPS, "the token lane is open: no more exchanges"
        clock.advance(2)
        gw.get_json(INFERENCE_PATH)
        assert len(gateway.door_calls) == CIRCUIT_TRIPS + 1, "closed again: asked once more"
    assert sum(1 for r in caplog.records if r.getMessage().startswith("gateway_auth_circuit_open")) == 1


# ── the shape of the surface ────────────────────────────────────────────


def test_nothing_public_returns_a_header_dict(settings) -> None:
    import inspect

    import noo_gateway

    auth = GatewayAuth(settings)
    for name, member in inspect.getmembers(auth):
        if name.startswith("_") or not callable(member):
            continue
        assert name in {"sync_auth_flow", "async_auth_flow", "auth_flow", "forget"}, (
            f"GatewayAuth.{name} is public; the only interface is the flow"
        )
    for name in noo_gateway.__all__:
        assert "header" not in name.lower()


def test_the_auth_works_on_a_client_built_by_hand(gateway: FakeGateway, settings) -> None:
    # The OpenAI SDK shape: someone else's client, our auth on it.
    with httpx.Client(auth=GatewayAuth(settings), transport=gateway, base_url=settings.url) as c:
        assert c.post(CHAT_PATH, json={}).json()["lane"] == "token"
