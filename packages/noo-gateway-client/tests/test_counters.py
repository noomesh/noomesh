# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PersonifAI LLC

"""`Counters`: aggregate, flush to both doors, own circuit, never raise."""

from __future__ import annotations

import logging

import pytest

from noo_gateway import Counters, GatewayClient, GatewaySettings
from noo_gateway.metrics import METRICS_CIRCUIT_SECS
from noo_gateway.settings import METRICS_GAUGE_PATH, METRICS_INCREMENT_PATH
from _fake_gateway import CONTROL_PATH, FakeGateway


def _bodies(gateway: FakeGateway, path: str) -> list[dict]:
    # the fake records requests, not bodies; re-read them from the transport log
    return [b for (p, b) in gateway.bodies if p == path]


@pytest.fixture(autouse=True)
def record_bodies(gateway: FakeGateway, monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    gateway.bodies = []  # type: ignore[attr-defined]
    original = gateway._answer

    def answer(request, kind):
        if request.content:
            gateway.bodies.append((request.url.path, json.loads(request.content)))  # type: ignore[attr-defined]
        return original(request, kind)

    monkeypatch.setattr(gateway, "_answer", answer)


def test_increments_are_summed_per_series_and_gauges_keep_the_last(
    gateway: FakeGateway, settings: GatewaySettings
) -> None:
    c = Counters(settings, background=False)
    c.inc("embeddings_total", 1, model="a")
    c.inc("embeddings_total", 2, model="a")
    c.inc("embeddings_total", model="b")
    c.gauge("backlog", 10)
    c.gauge("backlog", 4)
    c.gauge("backlog", 7, model="a")
    assert c.pending == 4
    c.flush()
    assert c.pending == 0
    incs = _bodies(gateway, METRICS_INCREMENT_PATH)
    assert sorted((b["name"], b["labels"]["model"], b["value"]) for b in incs) == [
        ("embeddings_total", "a", 3), ("embeddings_total", "b", 1)]
    gauges = _bodies(gateway, METRICS_GAUGE_PATH)
    assert sorted(((b["labels"].get("model", ""), b["value"]) for b in gauges)) == [("", 4.0), ("a", 7.0)]
    assert all(s.lane == "token" for s in gateway.calls(METRICS_INCREMENT_PATH))
    c.close()


def test_fractions_carry_over_and_nothing_below_one_is_sent(gateway: FakeGateway, settings) -> None:
    c = Counters(settings, background=False)
    c.inc("x_total", 0.6)
    c.flush()
    assert _bodies(gateway, METRICS_INCREMENT_PATH) == []
    c.inc("x_total", 0.6)
    c.flush()
    assert [b["value"] for b in _bodies(gateway, METRICS_INCREMENT_PATH)] == [1]
    c.close()


def test_a_403_silences_the_sink_once_and_leaves_the_auth_lanes_alone(
    gateway: FakeGateway, settings: GatewaySettings, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="noo_gateway")
    gateway.metrics_status = 403  # the key has no `metrics` scope
    c = Counters(settings, background=False)
    c.inc("a_total")
    c.flush()
    c.inc("a_total")
    c.flush()
    c.flush()
    assert len(gateway.calls(METRICS_INCREMENT_PATH)) == 1, "one refusal, then silence"
    assert c.disabled
    warned = [r for r in caplog.records if r.getMessage().startswith("gateway_metrics_circuit_open")
              and r.levelno >= logging.WARNING]
    assert len(warned) == 1 and "svc:test" in warned[0].getMessage() and "metrics" in warned[0].getMessage()
    # the next REAL call still rides the token, not a fallback lane
    with GatewayClient(settings) as gw:
        assert gw.get_json(CONTROL_PATH)["lane"] == "token"
    c.close()


def test_a_429_silences_for_the_window_then_resumes(gateway: FakeGateway, settings) -> None:
    c = Counters(settings, background=False)
    t = [1000.0]
    c._clock = lambda: t[0]
    gateway.metrics_status = 429
    c.inc("a_total")
    c.flush()
    gateway.metrics_status = None
    c.inc("a_total")
    c.flush()
    assert len(gateway.calls(METRICS_INCREMENT_PATH)) == 1, "silenced"
    t[0] += METRICS_CIRCUIT_SECS + 1
    c.inc("a_total")
    c.flush()
    assert len(gateway.calls(METRICS_INCREMENT_PATH)) == 2, "resumed"
    c.close()


def test_a_400_refuses_that_series_only(gateway: FakeGateway, settings) -> None:
    import json

    import httpx

    original = gateway._answer

    def answer(request, kind):
        resp = original(request, kind)  # records the body, then we override the answer
        if request.url.path == METRICS_INCREMENT_PATH and json.loads(request.content)["name"] == "Bad":
            return httpx.Response(400, json={"error": "counter name must be snake_case"})
        return resp

    gateway._answer = answer  # type: ignore[method-assign]
    c = Counters(settings, background=False)
    c.inc("Bad")
    c.inc("good_total")
    c.flush()
    c.inc("Bad")
    c.flush()
    assert [b["name"] for b in _bodies(gateway, METRICS_INCREMENT_PATH)] == ["Bad", "good_total"], "Bad once, never again"
    c.close()


def test_never_raises(gateway: FakeGateway, settings) -> None:
    gateway.door = "404"
    bad = GatewaySettings(consumer="svc:x", url="https://gw.test", key=None, transport=gateway)
    c = Counters(bad, background=False)  # no credential at all: GatewayAuthUnavailable inside
    c.inc("a_total")
    c.flush()
    assert gateway.calls(METRICS_INCREMENT_PATH) == []
    c.inc("a_total", value=-1)  # ignored
    c.gauge("g", float("nan"))  # sent and refused by the gateway; not our problem here
    c.close()


def test_background_flush_on_max_pending_and_at_close(gateway: FakeGateway, settings) -> None:
    c = Counters(settings, flush_interval=60.0, max_pending=3)
    c.inc("a_total")
    c.inc("b_total")
    assert gateway.calls(METRICS_INCREMENT_PATH) == []
    c.inc("c_total")
    import time

    for _ in range(200):
        if len(gateway.calls(METRICS_INCREMENT_PATH)) == 3:
            break
        time.sleep(0.01)
    assert len(gateway.calls(METRICS_INCREMENT_PATH)) == 3, "max_pending woke the thread"
    c.inc("d_total")
    c.close()
    assert len(gateway.calls(METRICS_INCREMENT_PATH)) == 4, "close flushes"


async def test_aclose_flushes(gateway: FakeGateway, settings) -> None:
    c = Counters(settings, background=False)
    c.inc("a_total")
    await c.aclose()
    assert len(gateway.calls(METRICS_INCREMENT_PATH)) == 1
