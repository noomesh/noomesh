# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A surfaces=core noo-worker must not try ML-pack inits (no trellion there).

Live 2026-10-06: six `No module named 'trellion'` warnings at every start of
the slim worker, burying the real greenlet failures beside them.
"""
from __future__ import annotations

import asyncio
import sys
from types import ModuleType, SimpleNamespace

import pytest

from noomesh.gateway import worker_pool as wp


class _Msg:
    is_connected = True
    nc = None  # start_worker_pool returns right after the audit logger init


def _run(monkeypatch, surfaces):
    if surfaces is None:
        monkeypatch.delenv("NOO_WORKER_SURFACES", raising=False)
    else:
        monkeypatch.setenv("NOO_WORKER_SURFACES", surfaces)
    calls = []
    monkeypatch.setattr(wp, "_trellion_engine", lambda: calls.append("engine"))
    events = []
    fake = SimpleNamespace(
        info=lambda ev, **kw: events.append(("info", ev, kw)),
        warning=lambda ev, **kw: events.append(("warning", ev, kw)),
        debug=lambda *a, **k: None,
        error=lambda *a, **k: None,
    )
    monkeypatch.setattr(wp, "log", fake)
    monkeypatch.setattr(wp, "_log_code_source", lambda: None)
    asyncio.run(wp.start_worker_pool(_Msg()))
    return calls, events


@pytest.mark.parametrize("surfaces", ["core", " CORE "])
def test_core_skips_trellion_engine_warm_and_says_so_once(monkeypatch, surfaces):
    calls, events = _run(monkeypatch, surfaces)
    assert calls == []
    names = [e[1] for e in events]
    assert "worker_pool.trellion_engine_warm_failed" not in names
    skipped = [e for e in events if e[1] == "worker_pool.ml_pack_init_skipped"]
    assert len(skipped) == 1 and skipped[0][0] == "info"
    assert "rag" in skipped[0][2]["skipped"]


@pytest.mark.parametrize("surfaces", [None, "all", "ml", "ml-intel", "bogus"])
def test_ml_capable_surfaces_still_warm_the_engine(monkeypatch, surfaces):
    calls, events = _run(monkeypatch, surfaces)
    assert calls == ["engine"]
    assert not [e for e in events if e[1] == "worker_pool.ml_pack_init_skipped"]


def test_serves_ml_pack_matches_workers_surface_gate():
    import os
    for val, want in [("core", False), ("all", True), ("ml", True), ("ml-intel", True)]:
        os.environ["NOO_WORKER_SURFACES"] = val
        try:
            assert wp._serves_ml_pack() is want
        finally:
            del os.environ["NOO_WORKER_SURFACES"]


_ML_MODULES = [
    "noomesh.memory.conversation_store",
    "noomesh.memory.rag_integration",
    "noomesh.memory.manager",
    "trellion.live._intel",
    "noomesh.memory.video.config",
    "noomesh.memory.video.manager",
]


def _init_services(monkeypatch, surfaces):
    """Run _init_python_services with every trellion-backed import trapped.

    The trap records the attempt, then raises like a missing package would,
    so the test does not depend on trellion being (un)installed here.
    """
    attempted: list[str] = []

    def trap(name):
        mod = ModuleType(name)

        def _getattr(attr):
            attempted.append(name)
            raise ImportError("No module named 'trellion'")

        mod.__getattr__ = _getattr  # type: ignore[attr-defined]
        return mod

    for name in _ML_MODULES:
        monkeypatch.setitem(sys.modules, name, trap(name))
    monkeypatch.setenv("NOO_WORKER_SURFACES", surfaces)
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@127.0.0.1:1/x")
    monkeypatch.delenv("PAGEINDEX_DSN", raising=False)
    events = []
    fake = SimpleNamespace(
        info=lambda ev, **kw: events.append(("info", ev)),
        warning=lambda ev, **kw: events.append(("warning", ev)),
        debug=lambda *a, **k: None,
        error=lambda *a, **k: None,
    )
    monkeypatch.setattr(wp, "log", fake)
    asyncio.run(wp._init_python_services(_Msg()))
    return attempted, events


def test_core_never_attempts_a_trellion_backed_init(monkeypatch):
    attempted, events = _init_services(monkeypatch, "core")
    assert attempted == []
    noise = [e for e in events if e[0] == "warning" and any(
        k in e[1] for k in ("rag_init", "memory_system_init", "conversation_store_init",
                            "retrieval_tracker_init", "recall_memory_init"))]
    assert noise == []


def test_all_surface_still_attempts_them(monkeypatch):
    """The gate must not strip the ML pack from noo-trellion."""
    attempted, _ = _init_services(monkeypatch, "all")
    assert set(attempted) >= {
        "noomesh.memory.conversation_store",
        "noomesh.memory.rag_integration",
        "noomesh.memory.manager",
        "trellion.live._intel",
        "noomesh.memory.video.config",
    }
