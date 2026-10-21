# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""harness-compare: run one task set under each harness KIND on one node.

"Which harness is better here" as a number. For each kind in the scenario,
in order:

1. **Place** it: ``PUT /api/cluster/nodes/{node}/placements/harness`` with
   ``NOO_HARNESS_KIND`` merged onto the stored placement's env (the gateway
   REPLACES env with what is sent, the same reason `noo cluster place`
   merges client-side).
2. **Wait** until the node is dispatchable. The gateway's own answer
   (``harness_node_explained``) is not exposed on a route of its own, so
   readiness is read off the node record: at least ``settle_s`` after the
   placement, on a heartbeat newer than the one seen at placement time,
   ``host_services.harness.state == running``, ``host_services.harness.kind``
   naming the kind just placed (the agent reports the kind the harness was
   started with — without it a harness still running the PREVIOUS kind, or
   one that fell back to ``noo``, would be measured as this one), and no
   ``harness`` refusal.
   The gateway's verdict still arrives per task: ``POST /api/tasks``
   answers ``dispatched`` and ``why``, and with ``require_dispatch`` a task
   the controller ran in process fails (it measured the controller, not
   the kind).
3. **Run** each task: ``POST /api/tasks``, poll ``GET /api/tasks/{id}``
   until ``done|failed|stopped`` or the task's timeout, then evaluate its
   ``check``.

The original placement is put back at the end, and on error; a node that
had no harness placement gets the one this run created removed.

Tokens: usage rows carry no task id, and ``/api/usage/summary`` has no
``harness_kind`` group. So a task's tokens are the DIFFERENCE in the
``backend = harness:<kind>`` row of ``GET /api/usage/summary?group=backend``
taken before and after it (rows are written fire-and-forget, hence
``usage_settle_s``). Under a user-tier token the summary is that user's
own; under an operator token it is install-wide, and concurrent traffic of
the same kind is counted too: the run says which in ``token_method``. A
kind that writes no ``harness:<kind>`` row (``noo``: its loops record no
token usage today) reads "not reported", never 0.
"""
from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import quote

import httpx

from .scenario import CompareTask, HarnessCompareSpec, parse_check
from .schema import HarnessCompare, KindRun, TaskRun

TERMINAL = {"done", "failed", "stopped"}
KIND_ENV = "NOO_HARNESS_KIND"
RESULT_CHARS = 2000

Sleep = Callable[[float], Awaitable[None]]
Clock = Callable[[], float]


# ── checks ──────────────────────────────────────────────────────────────

def evaluate_check(check: str, state: str, result: str) -> tuple[bool, str]:
    """``(passed, reason)`` for a task's check against its final state and
    result text. ``reason`` is empty on a pass."""
    kind, arg = parse_check(check)
    text = result or ""
    if kind == "state":
        return (state == arg, "" if state == arg else f"state is {state or 'unknown'}, wanted {arg}")
    if kind == "nonempty":
        return (bool(text.strip()), "" if text.strip() else "empty result")
    if kind == "contains":
        ok = arg.lower() in text.lower()
        return ok, "" if ok else f"result does not contain {arg!r}"
    if kind == "regex":
        ok = re.search(arg, text) is not None
        return ok, "" if ok else f"result does not match /{arg}/"
    raise ValueError(f"unhandled check kind {kind}")   # parse_check admits only the above


def first_line(s: str) -> str:
    for line in (s or "").splitlines():
        if line.strip():
            return line.strip()[:200]
    return ""


# ── gateway reads ──────────────────────────────────────────────────────

def _q(s: str) -> str:
    return quote(s, safe="")


async def read_harness_placement(client: httpx.AsyncClient, node: str) -> Optional[dict]:
    """The node's stored ``harness`` placement, or None when it has none.
    Raises when the desired config cannot be read: a run that cannot read
    the original cannot restore it, so it does not start."""
    r = await client.get(f"/api/cluster/nodes/{_q(node)}/desired-config")
    r.raise_for_status()
    for p in r.json().get("placements") or []:
        if p.get("backend") == "harness" and (p.get("role") or "harness") == "harness":
            return p
    return None


def kind_of(placement: Optional[dict]) -> Optional[str]:
    if placement is None:
        return None
    env = placement.get("env") or {}
    return env.get(KIND_ENV) or "noo"


async def node_record(client: httpx.AsyncClient, node: str) -> Optional[dict]:
    r = await client.get("/api/cluster/nodes")
    r.raise_for_status()
    for n in r.json().get("nodes") or []:
        if node in (n.get("id"), n.get("node_id"), n.get("hostname")):
            return n
    return None


def harness_state(n: Optional[dict]) -> str:
    return (((n or {}).get("host_services") or {}).get("harness") or {}).get("state") or ""


def harness_running_kind(n: Optional[dict]) -> str:
    """The kind the node says its harness is RUNNING (``host_services.harness.kind``);
    empty when it says none (stopped, or an agent too old to report it)."""
    return (((n or {}).get("host_services") or {}).get("harness") or {}).get("kind") or ""


def harness_refusal(n: Optional[dict]) -> str:
    for r in (n or {}).get("reconcile_refusals") or []:
        if r.get("target") == "harness":
            return r.get("reason") or "refused"
    return ""


async def usage_snapshot(client: httpx.AsyncClient) -> tuple[Optional[dict], Optional[str]]:
    """``({backend: (prompt, completion, requests)}, scope)`` this month, or
    ``(None, None)`` when the summary cannot be read."""
    try:
        r = await client.get("/api/usage/summary", params={"window": "month", "group": "backend"})
        r.raise_for_status()
        body = r.json()
    except (httpx.HTTPError, ValueError):
        return None, None
    rows = {row["key"]: (int(row.get("prompt_tokens") or 0), int(row.get("completion_tokens") or 0),
                         int(row.get("requests") or 0)) for row in body.get("rows") or []}
    return rows, body.get("scope")


def usage_delta(before: Optional[dict], after: Optional[dict], kind: str) -> tuple[Optional[int], Optional[int], str]:
    """Tokens a task added to ``harness:<kind>``, and how that was decided."""
    key = f"harness:{kind}"
    if before is None or after is None:
        return None, None, "usage summary unreadable"
    b, a = before.get(key, (0, 0, 0)), after.get(key, (0, 0, 0))
    dp, dc, dr = a[0] - b[0], a[1] - b[1], a[2] - b[2]
    if dr <= 0 or dp < 0 or dc < 0:
        return None, None, f"no {key} usage row written"
    return dp, dc, f"usage diff {key} ({dr} call(s))"


def _ts(s: Any) -> Optional[datetime]:
    if not isinstance(s, str) or not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


# ── the engine ─────────────────────────────────────────────────────────

class Comparer:
    """One run. ``ops`` places (operator); ``tasks`` creates tasks and reads
    usage (the same client unless the scenario names a user token).
    ``clock``/``sleep`` are injectable so the fixture runs in no time."""

    def __init__(self, spec: HarnessCompareSpec, ops: httpx.AsyncClient,
                 tasks: Optional[httpx.AsyncClient] = None, *,
                 clock: Clock = time.monotonic, sleep: Sleep = asyncio.sleep,
                 log: Callable[[str], None] = print):
        self.spec, self.ops, self.tasks = spec, ops, tasks or ops
        self.clock, self.sleep, self.log = clock, sleep, log
        self.out = HarnessCompare(node=spec.node, kinds=list(spec.kinds))
        self.original: Optional[dict] = None
        self.scope_seen: Optional[str] = None
        self.usage_read = False

    # placement ---------------------------------------------------------
    def _body_for(self, kind: str) -> dict:
        orig = self.original or {}
        env = dict(orig.get("env") or {})
        env[KIND_ENV] = kind
        return {"model": orig.get("model") or "auto", "desired_state": "running",
                "role": "harness", "env": env}

    async def place(self, kind: str) -> KindRun:
        kr = KindRun(kind=kind)
        node = self.spec.node
        try:
            before = await node_record(self.ops, node)
            hb0 = (before or {}).get("last_heartbeat")
            r = await self.ops.put(f"/api/cluster/nodes/{_q(node)}/placements/harness", json=self._body_for(kind))
            if r.status_code >= 400:
                kr.error = f"placement refused ({r.status_code}): {first_line(r.text)}"
                return kr
            kr.placed = True
            t0 = self.clock()
            state = running = ""
            while True:
                n = await node_record(self.ops, node)
                elapsed = self.clock() - t0
                state = harness_state(n)
                running = harness_running_kind(n)
                fresh = hb0 is None or (n or {}).get("last_heartbeat") != hb0
                if elapsed >= self.spec.settle_s and fresh:
                    refused = harness_refusal(n)
                    if refused:
                        kr.error = f"node refused the {kind} harness: {first_line(refused)}"
                        return kr
                    if state == "running" and running == kind:
                        kr.ready, kr.ready_s = True, round(elapsed, 1)
                        return kr
                if elapsed >= self.spec.ready_timeout_s:
                    kr.error = (f"harness not running {self.spec.ready_timeout_s:.0f}s after placing {kind} "
                                f"(last reported state: {state or 'unreported'}, running kind: "
                                f"{running or 'unreported — an agent older than the kind report never qualifies'})")
                    return kr
                await self.sleep(self.spec.poll_s)
        except httpx.HTTPError as e:
            kr.error = f"placing {kind}: {type(e).__name__}: {e}"
            return kr

    async def restore(self) -> None:
        node = self.spec.node
        path = f"/api/cluster/nodes/{_q(node)}/placements/harness"
        orig = self.original
        try:
            if orig is None:
                r = await self.ops.delete(path, params={"role": "harness"})
                what = "removed the harness placement this run created"
            else:
                body = {"model": orig.get("model") or "auto",
                        "desired_state": orig.get("desired_state") or "running",
                        "role": "harness", "env": orig.get("env") or {}}
                r = await self.ops.put(path, json=body)
                what = f"restored kind {kind_of(orig)}"
            if r.status_code >= 400:
                raise httpx.HTTPStatusError(f"{r.status_code}: {first_line(r.text)}", request=r.request, response=r)
            self.out.restored, self.out.restore_note = True, what
        except httpx.HTTPError as e:
            back = kind_of(orig) or "noo"
            self.out.restored = False
            self.out.restore_note = (f"RESTORE FAILED ({e}); put it back with "
                                     f"`noo cluster place {node} harness auto --kind {back}`")
        self.log(f"[noo-eval] {self.out.restore_note}")

    # tasks -------------------------------------------------------------
    async def run_task(self, kind: str, set_name: str, t: CompareTask) -> TaskRun:
        tr = TaskRun(kind=kind, task_set=set_name, task=t.name, check=t.check)
        body: dict[str, Any] = {"objective": t.objective}
        if t.model:
            body["model"] = t.model
        if t.loop_budget is not None:
            body["loop_budget"] = t.loop_budget
        timeout = t.timeout_s or self.spec.task_timeout_s
        before, scope = await usage_snapshot(self.tasks)
        if before is not None:
            self.usage_read, self.scope_seen = True, scope
        try:
            t_start = self.clock()
            r = await self.tasks.post("/api/tasks", json=body)
            if r.status_code >= 400:
                tr.state, tr.note = "error", f"task refused ({r.status_code}): {first_line(r.text)}"
                return tr
            created = r.json()
            rec = created.get("task") or {}
            tr.task_id = rec.get("id", "")
            tr.node = created.get("node") or rec.get("node") or ""
            tr.dispatched = bool(created.get("dispatched"))
            tr.why = created.get("why") or ""
            got: dict = {}
            timed_out = False
            while True:
                g = await self.tasks.get(f"/api/tasks/{_q(tr.task_id)}")
                g.raise_for_status()
                got = g.json()
                rec = got.get("task") or {}
                if rec.get("state") in TERMINAL:
                    break
                if self.clock() - t_start >= timeout:
                    timed_out = True
                    break
                await self.sleep(self.spec.poll_s)
            wall = self.clock() - t_start
            tr.state = rec.get("state") or ""
            tr.loops = int(rec.get("loops") or 0)
            tr.node = rec.get("node") or tr.node
            tr.result = (rec.get("result") or rec.get("error") or "")[:RESULT_CHARS]
            tr.children = len(got.get("children") or [])
            if isinstance(got.get("tools"), dict):
                tr.tools = int(got["tools"].get("count") or 0)
            c, u = _ts(rec.get("created_at")), _ts(rec.get("updated_at"))
            tr.wall_s = round((u - c).total_seconds(), 1) if (c and u and not timed_out) else round(wall, 1)
            if timed_out:
                tr.note = (f"timed out after {timeout:.0f}s in state {tr.state or 'unknown'} "
                           f"(left running; stop it with POST /api/tasks/{tr.task_id}/stop)")
                tr.state = f"timeout ({tr.state})" if tr.state else "timeout"
        except httpx.HTTPError as e:
            tr.state = tr.state or "error"
            tr.note = f"{type(e).__name__}: {e}"
            return tr
        await self.sleep(self.spec.usage_settle_s)
        after, _ = await usage_snapshot(self.tasks)
        tr.prompt_tokens, tr.completion_tokens, tr.tokens_source = usage_delta(before, after, kind)
        if tr.note:      # timed out
            return tr
        passed, reason = evaluate_check(t.check, tr.state, tr.result)
        if self.spec.require_dispatch and (not tr.dispatched or (tr.node and tr.node != self.spec.node)):
            passed = False
            reason = (f"not run by {self.spec.node}'s harness (node {tr.node or 'none'}): "
                      f"{tr.why or 'the gateway ran it in process'}")
        tr.passed = passed
        if not passed:
            # The task's own error says more than "state is failed".
            tr.note = f"{reason} — {first_line(tr.result)}" if (tr.state == "failed" and tr.result) else reason
        return tr

    # the run -----------------------------------------------------------
    async def run(self) -> HarnessCompare:
        spec = self.spec
        self.original = await read_harness_placement(self.ops, spec.node)
        self.out.original_kind = kind_of(self.original)
        self.log(f"[noo-eval] harness-compare on {spec.node}: kinds {', '.join(spec.kinds)} "
                 f"(original: {self.out.original_kind or 'no harness placement'})")
        try:
            for kind in spec.kinds:
                kr = await self.place(kind)
                self.out.kind_runs.append(kr)
                self.log(f"[noo-eval]   {kind}: " + (f"ready in {kr.ready_s}s" if kr.ready else kr.error))
                for ts in spec.task_sets:
                    for t in ts.tasks:
                        if t.kinds is not None and kind not in t.kinds:
                            self.out.runs.append(TaskRun(kind=kind, task_set=ts.name, task=t.name, check=t.check,
                                                         skipped=True, note=f"not run under {kind}"))
                            continue
                        if not kr.ready:
                            self.out.runs.append(TaskRun(kind=kind, task_set=ts.name, task=t.name, check=t.check,
                                                         state="not run", note=kr.error))
                            continue
                        tr = await self.run_task(kind, ts.name, t)
                        self.log(f"[noo-eval]     {t.name}: {'PASS' if tr.passed else 'FAIL'} "
                                 f"{tr.state} loops={tr.loops} wall={tr.wall_s}s" + (f" — {first_line(tr.note)}" if tr.note else ""))
                        self.out.runs.append(tr)
        finally:
            await self.restore()
        self.out.token_method = self._token_method()
        return self.out

    def _token_method(self) -> str:
        if not self.usage_read:
            return "tokens not recorded: GET /api/usage/summary could not be read"
        who = (f"scoped to {self.scope_seen}" if self.scope_seen
               else "INSTALL-WIDE (operator token): concurrent traffic of the same kind is counted too")
        return ("per-task tokens = before/after difference of the harness:<kind> row of "
                f"/api/usage/summary?group=backend, {who}. Usage rows carry no task id; "
                "a kind that writes no harness:<kind> row (noo) reads 'not reported'.")


async def run_compare(spec: HarnessCompareSpec, ops: httpx.AsyncClient,
                      tasks: Optional[httpx.AsyncClient] = None, **kw) -> HarnessCompare:
    return await Comparer(spec, ops, tasks, **kw).run()


# ── aggregation ────────────────────────────────────────────────────────

def summarize(hc: HarnessCompare) -> list[dict]:
    """One row per (task set, kind), in run order: the report's table."""
    rows: list[dict] = []
    sets: list[str] = []
    for r in hc.runs:
        if r.task_set not in sets:
            sets.append(r.task_set)
    for s in sets:
        for kind in hc.kinds:
            runs = [r for r in hc.runs if r.task_set == s and r.kind == kind and not r.skipped]
            skipped = sum(1 for r in hc.runs if r.task_set == s and r.kind == kind and r.skipped)
            ran = [r for r in runs if r.task_id]
            walls = [r.wall_s for r in ran if r.wall_s is not None]
            tok = [r for r in runs if r.prompt_tokens is not None]
            rows.append({
                "task_set": s,
                "harness_kind": kind,
                "passed": sum(1 for r in runs if r.passed),
                "total": len(runs),
                "skipped": skipped,
                "mean_loops": round(sum(r.loops for r in ran) / len(ran), 2) if ran else None,
                "mean_wall_s": round(sum(walls) / len(walls), 1) if walls else None,
                "prompt_tokens": sum(r.prompt_tokens or 0 for r in tok) if tok else None,
                "completion_tokens": sum(r.completion_tokens or 0 for r in tok) if tok else None,
                "tokens_reported": f"{len(tok)}/{len(runs)}",
                "failures": [f"{r.task}: {first_line(r.note) or r.state}" for r in runs if not r.passed],
            })
    return rows


def report_json(hc: HarnessCompare, scenario: str) -> dict:
    """The JSON twin of the HTML report."""
    return {
        "scenario": scenario,
        "node": hc.node,
        "kinds": hc.kinds,
        "original_kind": hc.original_kind,
        "restored": hc.restored,
        "restore_note": hc.restore_note,
        "token_method": hc.token_method,
        "summary": summarize(hc),
        "kind_runs": [k.model_dump() for k in hc.kind_runs],
        "runs": [r.model_dump() for r in hc.runs],
    }
