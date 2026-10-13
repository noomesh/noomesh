# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Two startup warnings that fired on every HEALTHY trellion start.

Live, host8, stack-v0.2.101, 2026-10-10 00:48 (and every start since 10-03):

* ``worker_pool.no_nats`` from noo-trellion and noo-trellion-intel. The
  caller was trellion's ``PageIndexRAG.startup()``, which calls
  ``start_worker_pool`` with its own unset messaging handle from inside
  ``_init_python_services``. The same process then started the real pool on
  its connected handle and subscribed every subject. Not bus-deaf; a false
  alarm. The warning must stay for a handle that really has no bus.
* ``worker.retrieval_tracker_init_failed "No module named
  'noomesh.memory.retrieval_tracker'"`` from noo-trellion, the open tier,
  where the Intelligent tier is absent by design (noo-trellion-intel logged
  ``worker.retrieval_tracker_initialized`` in the same second). The tracker
  is now reached through trellion's add-on seam; absent tier = one info line.
"""
from __future__ import annotations

import asyncio
import sys
from types import ModuleType, SimpleNamespace

import pytest

from noomesh.gateway import worker_pool as wp


def _capture(monkeypatch):
    events: list[tuple[str, str, dict]] = []
    fake = SimpleNamespace(
        info=lambda ev, **kw: events.append(("info", ev, kw)),
        warning=lambda ev, **kw: events.append(("warning", ev, kw)),
        debug=lambda ev, **kw: events.append(("debug", ev, kw)),
        error=lambda ev, **kw: events.append(("error", ev, kw)),
    )
    monkeypatch.setattr(wp, "log", fake)
    return events


def _warnings(events):
    return [e for e in events if e[0] in ("warning", "error")]


# ── worker_pool.no_nats ────────────────────────────────────────────────────


def test_embedded_caller_without_a_handle_is_not_a_warning(monkeypatch):
    """PageIndexRAG.startup() passes None; that is not a pool with no bus."""
    events = _capture(monkeypatch)
    monkeypatch.setattr(wp, "_pool_started", False)
    asyncio.run(wp.start_worker_pool(None))
    assert _warnings(events) == []
    assert [e[1] for e in events] == ["worker_pool.start_skipped"]


class _Disconnected:
    is_connected = False
    nc = None


def test_a_handle_with_no_bus_still_warns(monkeypatch):
    events = _capture(monkeypatch)
    monkeypatch.setattr(wp, "_pool_started", False)
    asyncio.run(wp.start_worker_pool(_Disconnected()))
    warned = [e for e in _warnings(events) if e[1] == "worker_pool.no_nats"]
    assert len(warned) == 1


class _FakeNC:
    def __init__(self):
        self.subjects: list[str] = []

    async def subscribe(self, subject, queue=None, cb=None):
        assert queue == wp.WORKER_QUEUE_GROUP
        self.subjects.append(subject)


class _Connected:
    is_connected = True

    def __init__(self):
        self.nc = _FakeNC()


def test_pool_subscribes_once_however_often_it_is_started(monkeypatch):
    """A second start with a live handle must not double every subscription."""
    events = _capture(monkeypatch)
    monkeypatch.setattr(wp, "_pool_started", False)
    monkeypatch.setattr(wp, "_log_code_source", lambda: None)
    monkeypatch.setattr(wp, "_trellion_engine", lambda: None)
    monkeypatch.setenv("NOO_WORKER_SURFACES", "core")
    from noomesh.gateway import audit_log
    monkeypatch.setattr(audit_log, "init_audit_logger", lambda **kw: None)
    monkeypatch.setattr(audit_log, "audit_sink_engine", lambda: (None, "test"))
    monkeypatch.setattr(audit_log, "audit", lambda *a, **k: None)
    from noomesh.gateway import deps
    monkeypatch.setattr(deps.services, "messaging", None, raising=False)
    handlers = {"worker.test.a": object(), "worker.test.b": object()}
    monkeypatch.setattr(wp, "all_handlers", lambda: handlers)

    m = _Connected()
    asyncio.run(wp.start_worker_pool(m))
    asyncio.run(wp.start_worker_pool(m))
    assert sorted(m.nc.subjects) == sorted(handlers)
    assert [e[1] for e in events].count("worker_pool.started") == 1
    assert _warnings(events) == []


# ── retrieval tracker ──────────────────────────────────────────────────────


def _seam(monkeypatch, *, available: bool, tracker_init=None):
    """Fake trellion's provider seam: ``addon_provider(role)`` answers or raises."""
    seam = ModuleType("trellion.live._intel")
    asked: list[str] = []

    def addon_provider(role):
        asked.append(role)
        if tracker_init is None:
            raise ImportError(f"{role}: requires the Intelligent tier")
        return tracker_init

    seam.addon_provider = addon_provider  # type: ignore[attr-defined]
    seam.intel_available = lambda: available  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "trellion.live._intel", seam)
    return asked


def test_open_tier_skips_the_tracker_with_one_info_line(monkeypatch):
    events = _capture(monkeypatch)
    asked = _seam(monkeypatch, available=False)
    wp._init_retrieval_tracker()
    assert _warnings(events) == []
    skipped = [e for e in events if e[1] == "worker.retrieval_tracker_skipped"]
    assert len(skipped) == 1 and skipped[0][0] == "info"
    assert "noo-trellion-intel" in skipped[0][2]["reason"]
    assert asked == []


def test_intel_tier_initialises_the_tracker_through_the_seam(monkeypatch, tmp_path):
    events = _capture(monkeypatch)
    inits: list[str | None] = []
    asked = _seam(monkeypatch, available=True, tracker_init=lambda persist_path=None: inits.append(persist_path))
    path = str(tmp_path / "retrieval_tracker.json")
    monkeypatch.setenv("RETRIEVAL_TRACKER_PATH", path)

    wp._init_retrieval_tracker()

    assert asked == ["retrieval_tracker_init"]
    assert inits == [path]
    assert ("info", "worker.retrieval_tracker_initialized", {}) in events
    assert _warnings(events) == []


def test_installed_tier_that_cannot_start_the_tracker_still_warns(monkeypatch):
    """The loss-of-function case stays loud."""
    events = _capture(monkeypatch)
    _seam(monkeypatch, available=True, tracker_init=None)
    wp._init_retrieval_tracker()
    warned = [e for e in _warnings(events) if e[1] == "worker.retrieval_tracker_init_failed"]
    assert len(warned) == 1


def test_real_intel_tier_tracker_initialises(monkeypatch, tmp_path):
    """Where trellion and an Intelligent-tier add-on are both installed, the
    tracker comes up through the real seam (entry point + HostServices)."""
    intel = pytest.importorskip("trellion.live._intel")
    if not hasattr(intel, "addon_provider") or not intel.intel_available():
        pytest.skip("no provider-capable trellion with an Intelligent-tier add-on installed")
    try:
        init = intel.addon_provider("retrieval_tracker_init")
    except ImportError:
        pytest.skip("the installed add-on declares no retrieval_tracker_init role")
    events = _capture(monkeypatch)
    monkeypatch.setenv("RETRIEVAL_TRACKER_PATH", str(tmp_path / "retrieval_tracker.json"))
    assert callable(init)
    wp._init_retrieval_tracker()
    assert _warnings(events) == []
    assert ("info", "worker.retrieval_tracker_initialized", {}) in events
