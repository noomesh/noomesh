# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""pytest-asyncio is configured so async tests RUN, not skip or no-op.

pytest-asyncio 1.x removed the ``event_loop`` fixture and warns until the
default fixture loop scope is set. The suite relies on ``asyncio_mode = auto``
(hundreds of bare ``async def test_...`` with no marker). If a plugin release
ever stopped treating those as async tests, the failure mode must be loud: this
file fails, instead of the async half of the suite quietly doing nothing.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest
import pytest_asyncio

_RAN: list[str] = []


def test_the_plugin_is_loaded_in_auto_mode_with_a_declared_loop_scope(pytestconfig) -> None:
    assert pytestconfig.pluginmanager.hasplugin("asyncio")
    assert int(pytest_asyncio.__version__.split(".")[0]) >= 1
    assert pytestconfig.getini("asyncio_mode") == "auto"
    assert pytestconfig.getini("asyncio_default_fixture_loop_scope") == "function"


async def test_a_bare_async_test_runs_on_a_running_loop() -> None:
    loop = asyncio.get_running_loop()
    await asyncio.sleep(0)
    _RAN.append("bare")
    assert loop.is_running()


@pytest_asyncio.fixture
async def _async_fixture() -> str:
    # An async fixture shares the test's loop at function scope.
    return f"loop-{id(asyncio.get_running_loop())}"


async def test_an_async_fixture_shares_the_tests_loop(_async_fixture) -> None:
    assert _async_fixture == f"loop-{id(asyncio.get_running_loop())}"
    _RAN.append("fixture")


def test_every_collected_coroutine_test_is_handled_by_the_plugin(request) -> None:
    """Auto mode marks every coroutine test; an unmarked one would not be awaited."""
    items = request.session.items
    coroutines = [
        i for i in items
        if isinstance(getattr(i, "obj", None), type(lambda: 0)) and inspect.iscoroutinefunction(i.obj)
    ]
    assert coroutines, "no coroutine tests were collected at all"
    unmarked = [i.nodeid for i in coroutines if i.get_closest_marker("asyncio") is None]
    assert not unmarked, f"coroutine tests the asyncio plugin does not own: {unmarked[:5]}"


def test_the_async_tests_above_actually_executed() -> None:
    # Runs after them (file order): both async bodies appended their marker.
    assert _RAN == ["bare", "fixture"]
