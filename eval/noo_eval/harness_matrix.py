# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""harness-matrix: the harness compare on every node, backend and model.

"How does each harness do on each kind of device, and with which model" as
a table and charts, run on demand (and on a schedule once wanted: it is one
command). For each cell of the scenario, in order:

1. **Skip** a cell the scenario marks ``skip`` (a node known not to serve),
   or one whose node reports no chat backend: it is recorded as SKIPPED with
   the reason, never as a failure of the harnesses.
2. **Place a variant** (when the cell has ``variants``): put ``model`` on
   ``backend`` for the run. Refused when the model is not already on the
   node (``available_models``): a benchmark never starts a download. Then
   wait until the node serves it (``running_backends``).
3. **Compare**: the one-node harness compare (:mod:`noo_eval.harness_compare`)
   with the matrix's kinds and task sets, which places each kind and puts
   the node's original harness placement back.
4. **Restore** the variant's backend placement, and on error.

Every row records what the node IS (hardware, backend, model, agent
version) so the report can slice by harness, backend, hardware and model.

Before anything is written, :func:`preflight` refuses to start while any of
the scenario's ``busy_locks`` is held (a Rust build on a measured box skews
every number), and a scenario with variants needs ``allow_placement_changes``:
a variant takes the node's chat model away from its live users for the run.
"""
from __future__ import annotations

import asyncio
import fcntl
import json
import os
import statistics
import time
from pathlib import Path
from typing import Any, Callable, Optional

import httpx

from . import harness_compare
from .harness_compare import _q, first_line, node_record
from .scenario import HarnessMatrixSpec, MatrixCell, ModelVariant
from .schema import Hardware, HarnessMatrix, MatrixCellRun

# Chat backends a cell can be served by, in the order one is picked when a
# node runs several (the class table's engine order: vLLM first).
CHAT_BACKENDS = ("vllm", "vllm-secondary", "llamacpp", "ollama")


# ── preflight ───────────────────────────────────────────────────────────

def held_locks(paths: list[str]) -> list[str]:
    """The ``busy_locks`` someone holds now (a non-blocking ``flock`` fails).
    A path that does not exist is not held: nothing has ever taken it."""
    held = []
    for p in paths:
        path = os.path.expanduser(p)
        if not os.path.exists(path):
            continue
        with open(path, "a") as fh:
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                held.append(p)
            else:
                fcntl.flock(fh, fcntl.LOCK_UN)
    return held


def preflight(spec: HarnessMatrixSpec, *, allow_placement_changes: bool) -> str:
    """Why the run must not start, or "" when it may."""
    held = held_locks(spec.busy_locks)
    if held:
        return f"busy: {', '.join(held)} is held (a build or another run is using a measured box); try again when it is free"
    if spec.has_variants() and not allow_placement_changes:
        return ("this scenario swaps models on live nodes (variants): pass --allow-placement-changes "
                "to confirm the window is yours (their users lose that model for the run)")
    return ""


# ── what a node is ──────────────────────────────────────────────────────

def hardware_of(n: Optional[dict]) -> Hardware:
    """Hardware facts from a node record; each one None when not reported."""
    n = n or {}
    caps = n.get("capabilities") or {}
    facts = caps.get("facts") or {}

    def pick(key: str) -> Any:
        for src in (n, caps, facts):
            if src.get(key) not in (None, ""):
                return src.get(key)
        return None

    def num(key: str) -> Optional[float]:
        v = pick(key)
        return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None

    def whole(key: str) -> Optional[int]:
        v = num(key)
        return int(v) if v is not None else None

    unified = bool(pick("unified_memory"))
    gpu = pick("gpu_model") or ("apple-unified" if unified else None)
    return Hardware(
        gpu=gpu, vram_gb=num("vram_gb"), unified_memory=unified, ram_gb=num("ram_gb"),
        cpu_cores=whole("cpu_cores"), arch=pick("arch"), tier=whole("tier"), stack=pick("app_version"),
    )


def chat_backend(n: Optional[dict]) -> tuple[str, str]:
    """``(backend, model)`` the node serves chat with, or ("", "") when none:
    the first of :data:`CHAT_BACKENDS` it reports with a named model."""
    running = (n or {}).get("running_backends") or (n or {}).get("backends") or {}
    for bt in CHAT_BACKENDS:
        m = running.get(bt)
        if isinstance(m, str) and m:
            return bt, m
    return "", ""


def has_model(n: Optional[dict], model: str) -> bool:
    """The node already holds ``model`` (its ``available_models``, names or
    ``{"name": …}`` entries; a ``:latest`` tag matches its bare name)."""
    def norm(s: str) -> str:
        return s.removesuffix(":latest").lower()
    names = set()
    for v in (n or {}).get("available_models") or []:
        name = v if isinstance(v, str) else (v or {}).get("name")
        if name:
            names.add(norm(name))
    return norm(model) in names


# ── the run ─────────────────────────────────────────────────────────────

Clock = Callable[[], float]
Sleep = Callable[[float], Any]


class Matrix:
    """One matrix run. ``clock``/``sleep`` are injectable (fixture, tests)."""

    def __init__(self, spec: HarnessMatrixSpec, ops: httpx.AsyncClient,
                 tasks: Optional[httpx.AsyncClient] = None, *,
                 clock: Clock = time.monotonic, sleep: Sleep = asyncio.sleep,
                 log: Callable[[str], None] = print):
        self.spec, self.ops, self.tasks = spec, ops, tasks or ops
        self.clock, self.sleep, self.log = clock, sleep, log
        self.out = HarnessMatrix(kinds=list(spec.kinds))

    async def _placement(self, node: str, backend: str) -> Optional[dict]:
        r = await self.ops.get(f"/api/cluster/nodes/{_q(node)}/desired-config")
        r.raise_for_status()
        for p in r.json().get("placements") or []:
            if p.get("backend") == backend:
                return p
        return None

    async def _put(self, node: str, backend: str, body: dict) -> str:
        """PUT a backend placement; "" on success, else why not."""
        r = await self.ops.put(f"/api/cluster/nodes/{_q(node)}/placements/{_q(backend)}", json=body)
        return "" if r.status_code < 400 else f"placement refused ({r.status_code}): {first_line(r.text)}"

    async def _await_model(self, node: str, backend: str, model: str) -> bool:
        deadline = self.clock() + self.spec.model_ready_timeout_s
        while self.clock() < deadline:
            n = await node_record(self.ops, node)
            if ((n or {}).get("running_backends") or {}).get(backend) == model:
                return True
            await self.sleep(self.spec.poll_s)
        return False

    async def _compare(self, node: str):
        return await harness_compare.run_compare(
            self.spec.compare_spec(node), self.ops, self.tasks,
            clock=self.clock, sleep=self.sleep, log=self.log)

    async def run_cell(self, cell: MatrixCell, variant: Optional[ModelVariant]) -> MatrixCellRun:
        n = await node_record(self.ops, cell.node)
        cr = MatrixCellRun(node=cell.node, hardware=hardware_of(n))
        if n is None:
            cr.skipped, cr.skip_reason = True, "the gateway does not know this node"
            return cr
        if variant is None:
            cr.backend, cr.model = chat_backend(n)
            if not cr.backend:
                cr.skipped, cr.skip_reason = True, "the node serves no chat model now"
                return cr
            cr.compare = await self._compare(cell.node)
            return cr

        cr.backend, cr.model, cr.variant = variant.backend, variant.model, True
        if not has_model(n, variant.model):
            cr.skipped = True
            cr.skip_reason = f"{variant.model} is not on {cell.node} (a benchmark never downloads; stage it first)"
            return cr
        original = await self._placement(cell.node, variant.backend)
        body = {**(original or {}), "backend": variant.backend, "model": variant.model,
                "desired_state": "running", "role": (original or {}).get("role") or "chat"}
        err = await self._put(cell.node, variant.backend, body)
        if err:
            cr.skipped, cr.skip_reason = True, err
            return cr
        try:
            if not await self._await_model(cell.node, variant.backend, variant.model):
                cr.skipped = True
                cr.skip_reason = f"{variant.model} was not serving within {self.spec.model_ready_timeout_s:.0f}s"
            else:
                cr.compare = await self._compare(cell.node)
        finally:
            cr.restored, cr.restore_note = await self._restore(cell.node, variant.backend, original)
        return cr

    async def _restore(self, node: str, backend: str, original: Optional[dict]) -> tuple[bool, str]:
        try:
            if original is None:
                r = await self.ops.delete(f"/api/cluster/nodes/{_q(node)}/placements/{_q(backend)}")
                ok = r.status_code < 400 or r.status_code == 404
                return ok, "" if ok else f"remove refused ({r.status_code}): {first_line(r.text)}"
            err = await self._put(node, backend, original)
            return (not err), err
        except httpx.HTTPError as e:
            return False, f"{type(e).__name__}: {e}"

    async def run(self) -> HarnessMatrix:
        for cell in self.spec.cells:
            if cell.skip:
                self.out.cells.append(MatrixCellRun(node=cell.node, skipped=True, skip_reason=cell.skip))
                self.log(f"[noo-eval] {cell.node}: SKIP ({cell.skip})")
                continue
            for variant in (cell.variants or [None]):
                label = f"{cell.node}" + (f" {variant.backend}:{variant.model}" if variant else "")
                self.log(f"[noo-eval] cell {label}")
                try:
                    cr = await self.run_cell(cell, variant)
                except httpx.HTTPError as e:
                    cr = MatrixCellRun(node=cell.node, skipped=True,
                                       skip_reason=f"gateway error: {type(e).__name__}: {e}")
                if cr.skipped:
                    self.log(f"[noo-eval] {label}: SKIP ({cr.skip_reason})")
                self.out.cells.append(cr)
        return self.out


async def run_matrix(spec: HarnessMatrixSpec, ops: httpx.AsyncClient,
                     tasks: Optional[httpx.AsyncClient] = None, **kw) -> HarnessMatrix:
    return await Matrix(spec, ops, tasks, **kw).run()


# ── rows, history, summaries ────────────────────────────────────────────

def rows(hm: HarnessMatrix, *, run_id: str, scenario: str) -> list[dict]:
    """One flat row per (cell, kind, task), plus one per skipped cell:
    every dimension the report slices by is a column."""
    out = []
    for c in hm.cells:
        base = {"run": run_id, "scenario": scenario, "node": c.node, "backend": c.backend,
                "model": c.model, "variant": c.variant, **{f"hw_{k}": v for k, v in c.hardware.model_dump().items()}}
        if c.skipped or c.compare is None:
            out.append({**base, "kind": None, "task": None, "status": "skipped", "note": c.skip_reason})
            continue
        for t in c.compare.runs:
            status = "skipped" if t.skipped else ("pass" if t.passed else "fail")
            out.append({**base, "kind": t.kind, "task_set": t.task_set, "task": t.task, "status": status,
                        "wall_s": t.wall_s, "loops": t.loops, "prompt_tokens": t.prompt_tokens,
                        "completion_tokens": t.completion_tokens, "dispatched": t.dispatched,
                        "note": first_line(t.note) if t.note else ""})
    return out


def append_history(path: str | Path, new_rows: list[dict]) -> Path:
    """Append rows to a JSON-lines history file (created if absent)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a") as fh:
        for r in new_rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    return p


def read_history(path: str | Path) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


def cell_label(r: dict) -> str:
    """How a cell is named in charts: node · backend · model (short)."""
    model = (r.get("model") or "").split("/")[-1]
    return " · ".join(x for x in (r.get("node"), r.get("backend"), model) if x)


def slice_by(rs: list[dict], dim: str) -> dict[str, dict[str, dict]]:
    """``{dim value: {kind: {"passed", "ran", "pass_rate", "median_wall_s"}}}``
    over measured rows (skipped rows and skipped tasks excluded). ``dim`` is a
    row column (``node``, ``backend``, ``model``, ``hw_gpu``, ...) or ``cell``."""
    acc: dict[str, dict[str, dict]] = {}
    for r in rs:
        if r.get("status") not in ("pass", "fail") or not r.get("kind"):
            continue
        key = cell_label(r) if dim == "cell" else str(r.get(dim) if r.get(dim) is not None else "unknown")
        a = acc.setdefault(key, {}).setdefault(r["kind"], {"passed": 0, "ran": 0, "walls": []})
        a["ran"] += 1
        a["passed"] += r["status"] == "pass"
        if r.get("wall_s") is not None:
            a["walls"].append(r["wall_s"])
    for kinds in acc.values():
        for a in kinds.values():
            a["pass_rate"] = a["passed"] / a["ran"] if a["ran"] else 0.0
            a["median_wall_s"] = statistics.median(a.pop("walls")) if a.get("walls") else None
            a.pop("walls", None)
    return acc


def trend(history: list[dict]) -> dict[str, list[tuple[int, float]]]:
    """Pass rate per kind per run, in history order: ``{kind: [(i, rate)]}``."""
    order: list[str] = []
    per: dict[str, dict[str, list[int]]] = {}
    for r in history:
        if r.get("status") not in ("pass", "fail") or not r.get("kind"):
            continue
        if r["run"] not in order:
            order.append(r["run"])
        per.setdefault(r["kind"], {}).setdefault(r["run"], []).append(r["status"] == "pass")
    return {k: [(i, 100.0 * sum(v) / len(v)) for i, run in enumerate(order) if (v := runs.get(run))]
            for k, runs in per.items()}
