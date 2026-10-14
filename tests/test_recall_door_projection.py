# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""i69b: the recall door must not look hollow.

Found on the live fleet: ``noo_recall_search top_k=3`` returned 4 hits with
``text: ""`` / ``metadata: {}``, and ``noo_recall_prominent`` returned
``records: []`` over 8,430 records. Causes pinned here:

  * search read ``request["params"]["query"]`` (the route forwards the body
    flat) and hardcoded top_k=5;
  * search hits were bare frame hits -- no body, no kind;
  * prominent called a manager method trellion does not have -> always [].
"""
from __future__ import annotations

from dataclasses import dataclass, field

from noomesh.workers import recall as wrecall


@dataclass
class _Hit:
    record_id: str
    frame_id: str
    record_type: str
    score: float = 0.9
    prominence_score: float = 0.5
    text: str = ""
    metadata: dict = field(default_factory=dict)


class _VM:
    _started = True

    def __init__(self, hits):
        self.hits = hits
        self.calls = []

    async def search(self, query, top_k=5, persona_id=None):
        self.calls.append((query, top_k))
        return self.hits  # a store that ignores top_k, like the live one


# episode rows: id, record_type, index_name, summary, prom, access, meta,
#               query_text, intent, outcome
ROWS = {
    "t1": ("t1", "traversal", "traversals", "traversal frame", 0.9, 3, {},
           "how do I rotate the key", "howto", 0.8),
    "c1": ("c1", "conversation", "conversations", "chat about keys", 0.7, 1,
           {"src": "x"}, None, None, None),
    "t2": ("t2", "traversal", "traversals", "traversal frame", 0.4, 0, {},
           None, None, None),
}


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _Conn:
    def __init__(self, eng):
        self.eng = eng

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def execute(self, stmt, params=None):
        self.eng.params = params
        if "ids" in (params or {}):
            return _Result([ROWS[i] for i in params["ids"] if i in ROWS])
        ordered = sorted(ROWS.values(), key=lambda r: -r[4])
        return _Result(ordered[: params["k"]])


class _Engine:
    params = None

    def connect(self):
        return _Conn(self)


def _wire(monkeypatch, vm):
    monkeypatch.setattr(wrecall, "_get_recall_memory", lambda: vm)
    monkeypatch.setattr(wrecall, "_trellion_engine", lambda: _Engine())


async def test_search_reads_flat_body_and_honours_top_k(monkeypatch):
    vm = _VM([_Hit(i, i, "traversal" if i != "c1" else "conversation")
              for i in ("t1", "c1", "t2", "t1")])
    _wire(monkeypatch, vm)
    out = await wrecall._recall_search({"query": "rotate key", "top_k": 3})
    assert vm.calls == [("rotate key", 3)]
    assert len(out) == 3


async def test_search_fills_body_and_kind(monkeypatch):
    vm = _VM([_Hit("t1", "t1", "traversal"), _Hit("c1", "c1", "conversation")])
    _wire(monkeypatch, vm)
    t1, c1 = await wrecall._recall_search({"query": "q", "top_k": 5})
    assert t1["kind"] == "traversal"
    assert t1["text"] == "how do I rotate the key"
    assert t1["metadata"]["intent"] == "howto"
    assert c1["kind"] == "conversation" and c1["text"] == "chat about keys"
    assert c1["metadata"] == {"src": "x"}


async def test_search_empty_traversal_says_so(monkeypatch):
    vm = _VM([_Hit("t2", "t2", "traversal")])
    _wire(monkeypatch, vm)
    (h,) = await wrecall._recall_search({"query": "q"})
    # t2 has no query_text: the summary is the body; never a silent "".
    assert h["kind"] == "traversal" and h["text"] == "traversal frame"
    # A hit whose row is gone entirely is named, not blank-without-reason.
    vm.hits = [_Hit("gone", "gone", "traversal")]
    (g,) = await wrecall._recall_search({"query": "q"})
    assert g["kind"] == "traversal" and g["text"] == ""
    assert "traversal" in g["text_unavailable"]


async def test_search_legacy_params_envelope_still_works(monkeypatch):
    vm = _VM([])
    _wire(monkeypatch, vm)
    await wrecall._recall_search({"params": {"query": "old", "top_k": 2}})
    assert vm.calls == [("old", 2)]


async def test_prominent_includes_traversals_and_honours_top_k(monkeypatch):
    _wire(monkeypatch, _VM([]))
    res = await wrecall._recall_prominent({"top_k": 2})
    recs = res["data"]["records"]
    assert [r["record_id"] for r in recs] == ["t1", "c1"]
    assert recs[0]["kind"] == "traversal" and recs[0]["text"] == "how do I rotate the key"
    assert recs[0]["prominence"] == 0.9


async def test_prominent_engine_down_is_failure_not_empty(monkeypatch):
    monkeypatch.setattr(wrecall, "_get_recall_memory", lambda: _VM([]))
    monkeypatch.setattr(wrecall, "_trellion_engine", lambda: None)
    res = await wrecall._recall_prominent({})
    assert res["success"] is False
