# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PersonifAI LLC

"""Fixtures. The fake gateway itself lives in `_fake_gateway.py`."""

from __future__ import annotations

import uuid

import pytest

import noo_gateway.auth as auth_mod
from _fake_gateway import Clock, FakeGateway, make_settings
from noo_gateway import GatewaySettings


@pytest.fixture(autouse=True)
def _isolated_auth_state():
    """Every test starts with no token, cooldown or circuit state.

    Auth state is process-wide per (url, key fingerprint), and the
    `fresh_key` trick below cannot separate tests that use no key: they all
    share the one `no-key` state. A test that opens a circuit under the fake
    `clock` (which starts at 1000 s) leaves it "open until" ~1300-1600 s on
    that fake timeline; a later test reading the REAL monotonic clock, on a
    runner booted less than ~25 minutes ago, would still see it open (the
    fresh-CI-runner failure of 2026-10-01, PRs #617/#618).
    """
    with auth_mod._states_lock:
        auth_mod._states.clear()
    yield
    with auth_mod._states_lock:
        auth_mod._states.clear()


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    c = Clock()
    monkeypatch.setattr(auth_mod, "_now", c)
    return c


@pytest.fixture
def fresh_key() -> str:
    # Token state is shared per (url, key fingerprint) for the process; a
    # unique key per test keeps tests from seeing each other's circuits.
    return "nk_" + uuid.uuid4().hex


@pytest.fixture
def gateway(fresh_key: str) -> FakeGateway:
    return FakeGateway(key=fresh_key)


@pytest.fixture
def settings(gateway: FakeGateway) -> GatewaySettings:
    return make_settings(gateway)
