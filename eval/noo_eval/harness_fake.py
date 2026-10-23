# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A fake gateway for harness-compare: the fixture (dry-run) mode.

Answers the calls :mod:`noo_eval.harness_compare` makes — desired config,
the node list, the harness placement PUT/DELETE, ``/api/tasks`` and
``/api/usage/summary`` — from canned data, through ``httpx.MockTransport``,
so the pipeline and the report run in CI with no gateway. Time is a
:class:`FakeClock` that the engine's ``sleep`` advances, so a run takes no
wall time and its numbers are the same every time.

The canned kinds differ on purpose, so the report has something to show:
``noo`` is quick and writes no usage row (as today), ``copilot`` cannot
delegate, ``claude-code`` passes everything at a higher token cost, and
``codex`` passes everything between the two. A test that needs a refused
kind passes its own ``profiles``. EVERY value a fixture run reports is
SYNTHETIC.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import unquote

import httpx


class FakeClock:
    """Monotonic time that moves only when someone sleeps."""

    def __init__(self, start: float = 1_790_000_000.0):
        self.t = start

    def __call__(self) -> float:
        return self.t

    async def sleep(self, s: float) -> None:
        self.t += max(s, 0.001)

    def iso(self) -> str:
        return datetime.fromtimestamp(self.t, timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class KindProfile:
    polls: int = 2                    # GETs before a task settles
    loops: int = 1
    prompt_per_task: int = 0          # 0 = writes no harness:<kind> usage row
    completion_per_task: int = 0
    fails: dict[str, str] = field(default_factory=dict)   # objective substring -> error
    refused: str = ""                 # the node refuses this kind with this reason


PROFILES: dict[str, KindProfile] = {
    "noo": KindProfile(polls=2, loops=1),
    "copilot": KindProfile(polls=3, loops=2, prompt_per_task=1800, completion_per_task=220,
                           fails={"delegate": "noo_task_delegate was not offered to this harness\n(trace)"}),
    "claude-code": KindProfile(polls=4, loops=2, prompt_per_task=5200, completion_per_task=410),
    "codex": KindProfile(polls=3, loops=2, prompt_per_task=3400, completion_per_task=300),
}

# objective substring -> the result a passing run answers with
ANSWERS = [   # first match wins: the delegation objective quotes the one-word one
    ("delegate", "Delegated to a child task; it answered: pong"),
    ("nodes", "This mesh has two nodes: awolf (controller, GPU) and pop-os (CPU)."),
    ("single word", "ok"),
]


class FakeHarnessGateway:
    def __init__(self, node: str = "awolf", original_kind: Optional[str] = "noo",
                 clock: Optional[FakeClock] = None,
                 profiles: Optional[dict[str, KindProfile]] = None, synthesized: bool = False):
        self.node = node
        self.clock = clock or FakeClock()
        self.profiles = profiles or PROFILES
        self.placement: Optional[dict] = None
        if original_kind is not None:
            self.placement = {"backend": "harness", "role": "harness", "model": "auto", "tls": False,
                              "desired_state": "running", "env": {"NOO_HARNESS_KIND": original_kind,
                                                                  "NOO_HARNESS_LOG": "info"}}
        if synthesized:
            # The auto policy's placement: reported, never stored.
            self.placement = {"backend": "harness", "role": "harness", "model": "auto", "tls": False,
                              "desired_state": "running", "env": {}, "synthesized": True}
            original_kind = "noo"
        self.running_kind = original_kind
        self.down_beats = 0           # heartbeats the harness reports stopped after a kind change
        # What the heartbeat says the harness RUNS (host_services.harness.kind):
        # None = the kind it was started with; "" = says none (an older
        # agent); any other string = stuck on that kind (a harness that
        # never picked up the new placement).
        self.report_kind: Optional[str] = None
        self.beat = 0
        self.tasks: dict[str, dict] = {}
        self.usage: dict[str, list[int]] = {"llamacpp": [9000, 800, 12]}
        self.writes: list[tuple[str, str, Optional[dict]]] = []

    # ── node ──
    def _kind(self) -> Optional[str]:
        if self.placement is None:
            return None
        return (self.placement.get("env") or {}).get("NOO_HARNESS_KIND") or "noo"

    def _node(self) -> dict:
        self.beat += 1
        kind = self._kind()
        prof = self.profiles.get(kind or "", KindProfile())
        refusals = []
        if kind is None:
            state = "absent"
        elif prof.refused:
            state, refusals = "stopped", [{"scope": "placement", "target": "harness", "reason": prof.refused}]
        elif self.down_beats > 0:
            self.down_beats -= 1
            state = "stopped"
        else:
            state = "running"
            self.running_kind = kind
        harness = {"state": state, "runtime": "systemd"}
        if state == "running":
            reported = self.running_kind if self.report_kind is None else self.report_kind
            if reported:
                harness["kind"] = reported
        return {"id": self.node, "hostname": self.node, "status": "online",
                "last_heartbeat": f"beat-{self.beat}",
                "host_services": {"harness": harness},
                "reconcile_refusals": refusals}

    # ── tasks ──
    def _answer(self, objective: str) -> str:
        low = objective.lower()
        for needle, text in ANSWERS:
            if needle in low:
                return text
        return "done"

    def _create(self, body: dict) -> dict:
        tid = f"00000000-0000-4000-8000-{len(self.tasks) + 1:012d}"
        kind = self.running_kind if self._kind() == self.running_kind else None
        dispatched = kind is not None and self.placement is not None
        t = {"id": tid, "objective": body["objective"], "state": "running", "loops": 0,
             "loop_budget": body.get("loop_budget") or 8, "node": self.node if dispatched else "gateway-ctl",
             "result": None, "error": None, "created_at": self.clock.iso(), "updated_at": self.clock.iso(),
             "_kind": kind, "_polls": 0}
        self.tasks[tid] = t
        return {"task": self._public(t), "node": t["node"], "dispatched": dispatched,
                "why": None if dispatched else "node 'awolf' has a harness and it did not answer within 3s"}

    def _public(self, t: dict) -> dict:
        return {k: v for k, v in t.items() if not k.startswith("_")}

    def _poll(self, tid: str) -> Optional[dict]:
        t = self.tasks.get(tid)
        if t is None:
            return None
        if t["state"] == "running":
            t["_polls"] += 1
            prof = self.profiles.get(t["_kind"] or "", KindProfile())
            t["loops"] = min(t["_polls"], prof.loops)
            if t["_polls"] >= prof.polls:
                low = t["objective"].lower()
                err = next((e for needle, e in prof.fails.items() if needle in low), None)
                t["state"], t["updated_at"] = ("failed" if err else "done"), self.clock.iso()
                if err:
                    t["error"] = err
                else:
                    t["result"] = self._answer(t["objective"])
                if prof.prompt_per_task and t["_kind"]:
                    row = self.usage.setdefault(f"harness:{t['_kind']}", [0, 0, 0])
                    row[0] += prof.prompt_per_task * t["loops"]
                    row[1] += prof.completion_per_task * t["loops"]
                    row[2] += t["loops"]
        children = [{"id": t["id"] + "-c1", "state": "done"}] if ("delegate" in t["objective"].lower()
                                                                   and t["state"] == "done") else []
        return {"task": self._public(t), "children": children, "tools": {"count": t["loops"], "names": []}}

    # ── transport ──
    def handle(self, request: httpx.Request) -> httpx.Response:
        path, method = unquote(request.url.path), request.method
        body = json.loads(request.content) if request.content else None
        node_base = f"/api/cluster/nodes/{self.node}"
        if method == "GET" and path == f"{node_base}/desired-config":
            return httpx.Response(200, json={"node_id": self.node,
                                             "placements": [self.placement] if self.placement else []})
        if method == "GET" and path == "/api/cluster/nodes":
            return httpx.Response(200, json={"nodes": [self._node()], "stats": {}})
        if path == f"{node_base}/placements/harness":
            self.writes.append((method, path, body))
            if method == "PUT":
                kind = (body.get("env") or {}).get("NOO_HARNESS_KIND")
                if kind and kind not in self.profiles:
                    return httpx.Response(400, json={"error": f"NOO_HARNESS_KIND must be one of {', '.join(self.profiles)}"})
                changed = kind != self._kind()
                self.placement = {"backend": "harness", "role": "harness", "model": body.get("model"),
                                  "tls": False, "desired_state": body.get("desired_state", "running"),
                                  "env": body.get("env") or {}}
                if changed:
                    self.down_beats = 2
                return httpx.Response(200, json={"ok": True, "node_id": self.node, "backend": "harness"})
            if method == "DELETE":
                self.placement, self.running_kind = None, None
                return httpx.Response(200, json={"ok": True})
        if method == "POST" and path == "/api/tasks":
            return httpx.Response(200, json=self._create(body or {}))
        if method == "GET" and path.startswith("/api/tasks/"):
            got = self._poll(path.rsplit("/", 1)[-1])
            return httpx.Response(200, json=got) if got else httpx.Response(404, json={"error": "task not found"})
        if method == "GET" and path == "/api/usage/summary":
            rows = [{"key": k, "prompt_tokens": v[0], "completion_tokens": v[1], "requests": v[2]}
                    for k, v in self.usage.items()]
            return httpx.Response(200, json={"window": "month", "group": "backend", "scope": "eval-user",
                                             "rows": rows})
        return httpx.Response(404, json={"error": f"fake gateway: no route {method} {path}"})

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url="http://fake-gateway", transport=httpx.MockTransport(self.handle))
