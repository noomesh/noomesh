# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""NATS reconnect resilience for the Python client (noo-trellion worker pool).

Companion to the Go node-agent tests in
``node-agent-go/internal/messaging`` and ``internal/jobs``. The incident
these guard: on 2026-08-02 two nodes lost the bus when the controller's NATS
container was recreated and never rejoined, while still heartbeating over
HTTPS — so nothing anywhere reported a problem and three dispatched jobs
died in ``dispatched``.
"""

import asyncio

import pytest

from noomesh.cluster.messaging import ClusterMessaging


class _FakeNC:
    """Minimal stand-in for a nats-py connection."""

    def __init__(self, connected: bool = True):
        self.is_connected = connected


def _client() -> ClusterMessaging:
    m = ClusterMessaging("nats://test:4222")
    m.nc = _FakeNC()
    m._connected = True
    return m


def test_is_connected_follows_the_live_socket():
    """`is_connected` used to be a sticky flag set once at connect and
    cleared only by close(). It reported healthy straight through an outage,
    which disarmed the scheduler's completion-listener repair (its
    re-subscribe only fires on a disconnected -> connected edge)."""
    m = _client()
    assert m.is_connected is True

    m.nc.is_connected = False
    assert m.is_connected is False, (
        "is_connected must consult the socket, not a flag that only close() clears"
    )

    m.nc.is_connected = True
    assert m.is_connected is True


def test_is_connected_false_without_a_connection():
    m = ClusterMessaging("nats://test:4222")
    assert m.is_connected is False


async def test_reconnect_reverifies_streams():
    """A NATS server that comes back with a fresh JetStream store has no
    EVENTS/TASKS/AGENT_MESSAGES. Every js.publish then fails forever while
    the client reports a perfectly healthy connection — the stranded-jobs
    shape. The reconnect callback re-checks them (the gateway owns creation)."""
    m = _client()
    calls = []

    async def fake_init():
        calls.append("init")

    m._verify_streams = fake_init
    await m._on_reconnected()

    assert calls == ["init"], "streams must be re-verified after a reconnect"


async def test_reconnect_fires_registered_hooks():
    m = _client()
    m._verify_streams = lambda: None

    fired = []

    async def async_hook():
        fired.append("async")

    def sync_hook():
        fired.append("sync")

    m.on_reconnect(async_hook)
    m.on_reconnect(sync_hook)
    await m._on_reconnected()

    assert sorted(fired) == ["async", "sync"]


async def test_a_failing_hook_does_not_block_the_others():
    m = _client()
    m._verify_streams = lambda: None
    fired = []

    def boom():
        raise RuntimeError("re-bind failed")

    m.on_reconnect(boom)
    m.on_reconnect(lambda: fired.append("second"))

    await m._on_reconnected()  # must not raise
    assert fired == ["second"]


async def test_lifecycle_callbacks_exist_and_are_awaitable():
    """nats-py only calls what was passed to connect(); all four must be
    present or the outage is silent."""
    m = _client()
    for cb in (m._on_disconnected(), m._on_closed(), m._on_error(Exception("x"))):
        assert asyncio.iscoroutine(cb)
        await cb


async def test_connect_wires_callbacks(monkeypatch):
    import noomesh.cluster.messaging as mod

    # Credentials are fail-closed the earlier change; this test is
    # about the lifecycle callbacks, so opt in to anonymous explicitly.
    monkeypatch.setenv("NOO_NATS_ALLOW_ANONYMOUS", "1")

    captured = {}

    class _JS:
        pass

    class _NC(_FakeNC):
        def jetstream(self):
            return _JS()

    async def fake_connect(url, **kwargs):
        captured.update(kwargs)
        return _NC()

    monkeypatch.setattr(mod.nats, "connect", fake_connect)

    m = ClusterMessaging("nats://test:4222")

    async def noop_streams():
        return None

    m._verify_streams = noop_streams

    assert await m.connect(retry=True) is True

    for cb in ("error_cb", "disconnected_cb", "reconnected_cb", "closed_cb"):
        assert captured.get(cb) is not None, f"{cb} was not passed to nats.connect()"
    assert captured["max_reconnect_attempts"] == -1, "must reconnect indefinitely"
    assert captured["allow_reconnect"] is True
    # Per-client inbox prefix, so a permission rule can grant this principal
    # its own inbox and nobody else's.
    assert captured["inbox_prefix"] == b"_INBOX_worker"


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
