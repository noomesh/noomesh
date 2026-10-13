# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""``worker.api.snapshots.consolidate`` request shapes.

The handler read ``kind`` and ``params`` straight off the body. A flat body left
params empty, so the default ``topic`` slice died on ``params["canonical_name"]``
and the snapshot row said only ``{"error": "'canonical_name'"}``. A body with
params got the worker pool's principal injected into ``params`` and could not
be serialised onto the row at all. These tests need no database: trellion is
replaced by recording stubs, and the principal is the real one.
"""
from __future__ import annotations

import asyncio
import json
import sys
import types

import pytest

from noomesh.gateway import bus_principal
from noomesh.workers import snapshots as w

TOPIC = {"entity_type": "topic", "canonical_name": "Widgets", "hops": 2}


@pytest.mark.parametrize(
    "request_body",
    [
        pytest.param({"kind": "topic", "params": dict(TOPIC), "label": "L"}, id="contract"),
        pytest.param({"kind": "topic", **TOPIC, "label": "L"}, id="flat"),
        pytest.param(
            {"params": {"kind": "topic", "params": dict(TOPIC), "label": "L"}}, id="envelope"
        ),
    ],
)
def test_every_accepted_shape_yields_the_same_slice(request_body):
    assert w._consolidate_fields(request_body) == ("topic", TOPIC, "L")


def test_no_kind_still_defaults_to_topic_but_keeps_its_params():
    assert w._consolidate_fields({"params": dict(TOPIC)}) == ("topic", TOPIC, None)


def test_pool_injected_keys_never_reach_the_slice_spec():
    principal = bus_principal.Principal("alice", "user", "operator", ["read"])
    request = bus_principal.apply_to_request(
        {"kind": "time_window", "params": {"from": "2026-01-01", "to": "2026-02-01"}}, principal
    )
    # The bug: the principal object rode in on params and broke json.dumps.
    with pytest.raises(TypeError):
        json.dumps(request["params"])
    kind, params, _ = w._consolidate_fields(request)
    assert kind == "time_window"
    assert not any(k.startswith("_") for k in params)
    assert params["from"] == "2026-01-01"
    json.dumps(params)  # serialisable now


def test_failure_reason_format_is_pinned():
    assert w._failure_reason(KeyError("canonical_name")) == "KeyError: 'canonical_name'"
    assert w._failure_reason(ValueError("topic slice needs params")) == (
        "ValueError: topic slice needs params"
    )
    assert len(w._failure_reason(RuntimeError("x" * 900))) == 500


def _install_fake_trellion(monkeypatch, slice_error: Exception | None):
    """Recording stand-ins for the three trellion names the handler imports."""
    seen: dict = {"created": None, "failed": None, "complete": None}

    class SliceSpec:
        def __init__(self, kind, params, label=None):
            self.kind, self.params, self.label = kind, params, label

    class SnapshotStore:
        def __init__(self, engine):
            pass

        async def create_snapshot(self, slice_kind, slice_spec, label=None):
            json.dumps(slice_spec)  # what the real store does with it
            seen["created"] = (slice_kind, slice_spec, label)
            return "snap-1"

        async def mark_failed(self, snapshot_id, reason):
            seen["failed"] = (snapshot_id, reason)
            seen["done"].set()

        async def mark_complete(self, snapshot_id, stats):
            seen["complete"] = (snapshot_id, stats)
            seen["done"].set()

    class _Slicer:
        async def slice(self, spec):
            if slice_error is not None:
                raise slice_error
            return [], []

    class SnapshotOrchestrator:
        def __init__(self, engine):
            self._slicer = _Slicer()

    mod = types.ModuleType("trellion.snapshots")
    mod.SliceSpec, mod.SnapshotStore, mod.SnapshotOrchestrator = (
        SliceSpec, SnapshotStore, SnapshotOrchestrator,
    )
    monkeypatch.setitem(sys.modules, "trellion", types.ModuleType("trellion"))
    monkeypatch.setitem(sys.modules, "trellion.snapshots", mod)
    monkeypatch.setattr(w, "_trellion_engine", lambda: object())
    return seen


async def test_consolidation_over_a_small_graph_reports_ok(monkeypatch):
    seen = _install_fake_trellion(monkeypatch, None)
    seen["done"] = asyncio.Event()
    principal = bus_principal.Principal("alice", "user", "operator", ["read"])
    request = bus_principal.apply_to_request({"kind": "topic", "params": dict(TOPIC)}, principal)

    reply = await w._snapshots_consolidate(request)
    await asyncio.wait_for(seen["done"].wait(), 5)

    assert seen["failed"] is None
    assert seen["complete"][0] == "snap-1"
    assert seen["created"][0] == "topic"
    # The signed user_id is a legitimate slice param (user_attention reads it);
    # the pool's _requester / _principal are not.
    assert seen["created"][1] == {**TOPIC, "user_id": "alice"}
    assert reply  # the caller gets something to poll with


async def test_a_failed_consolidation_reports_type_and_message(monkeypatch):
    seen = _install_fake_trellion(monkeypatch, KeyError("canonical_name"))
    seen["done"] = asyncio.Event()

    await w._snapshots_consolidate({"kind": "topic", "params": dict(TOPIC)})
    await asyncio.wait_for(seen["done"].wait(), 5)

    assert seen["failed"] == ("snap-1", "KeyError: 'canonical_name'")


@pytest.mark.parametrize(
    "body",
    [
        pytest.param({}, id="empty"),  # what the v0.2.85 rehearsal POSTed
        pytest.param({"kind": "topic"}, id="kind-only"),
        pytest.param({"kind": "topic", "params": {}}, id="empty-params"),
    ],
)
async def test_a_request_with_no_slice_is_refused_before_any_row_exists(monkeypatch, body):
    # Through the real pool signing: `{}` arrives carrying the caller's user_id,
    # which must not count as a slice.
    seen = _install_fake_trellion(monkeypatch, None)
    principal = bus_principal.Principal("alice", "user", "admin", ["admin"])
    reply = await w._snapshots_consolidate(bus_principal.apply_to_request(dict(body), principal))
    assert seen["created"] is None, "no snapshot row for a request that cannot slice"
    assert "consolidate needs a slice" in reply["error"]
    assert '"canonical_name"' in reply["error"]  # names what a topic needs


async def test_trellions_validation_refuses_a_kind_missing_its_params_before_any_row(monkeypatch):
    seen = _install_fake_trellion(monkeypatch, None)
    mod = sys.modules["trellion.snapshots"]

    def validate(self):
        if self.kind == "time_window" and "from" not in self.params:
            raise ValueError("time_window slice needs params ['from', 'to']; got params keys ['to']")

    mod.SliceSpec.validate = validate
    reply = await w._snapshots_consolidate({"kind": "time_window", "params": {"to": "2026-10-01"}})
    assert seen["created"] is None
    assert reply["error"] == (
        "consolidate cannot slice: time_window slice needs params ['from', 'to']; got params keys ['to']"
    )


async def test_user_attention_with_only_the_signed_user_id_is_a_real_slice(monkeypatch):
    seen = _install_fake_trellion(monkeypatch, None)
    seen["done"] = asyncio.Event()
    principal = bus_principal.Principal("alice", "user", "operator", ["read"])
    reply = await w._snapshots_consolidate(
        bus_principal.apply_to_request({"kind": "user_attention"}, principal)
    )
    await asyncio.wait_for(seen["done"].wait(), 5)
    assert "error" not in reply
    assert seen["created"][0] == "user_attention"
