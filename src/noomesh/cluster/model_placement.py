# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Availability-aware model placement matcher (self-managing fleet).

Given a model id + the current node fleet, pick the best node to run it on:
capable (enough VRAM/RAM for the catalog's VRAM estimate) AND already-cached
where possible, else flag a pull. This is the piece that stops hand-assigning
models — it joins the model catalog (requirements) with each node's
``available_models`` (the cached-model reporting inventory) and capability.

Pure functions over plain node dicts (as returned by ``noo cluster status
--json`` / ``/api/cluster/nodes``) so it's trivially testable and callable from
the placement/reconcile paths.
"""
from __future__ import annotations

from typing import Any, Optional

from .model_catalog import FALLBACK_MODELS, ModelCatalog, _extract_param_count


def estimate_model_vram(model_id: str, quant: Optional[str] = None) -> float:
    """VRAM (GB) a model needs. Uses the catalog's params/quant when the id is
    known, else parses the param count from the id. 0.0 if undeterminable."""
    for models in FALLBACK_MODELS.values():
        for m in models:
            if m.get("id") == model_id:
                return ModelCatalog.estimate_vram_gb(
                    m.get("params_b"), quant or m.get("quant")) or 0.0
    est = ModelCatalog.estimate_vram_gb(_extract_param_count(model_id), quant)
    return est or 0.0


def model_is_cached(model_id: str, available: list[str] | None) -> bool:
    """Is ``model_id`` in a node's reported inventory? Tolerant of org prefixes
    and Ollama ``name:tag`` forms (google/gemma-4-12B ~ gemma-4-12b ~ gemma4:12b)."""
    if not available:
        return False
    mid = model_id.lower()
    base = mid.split("/")[-1]
    for a in available:
        al = str(a).lower()
        if al == mid or al == base or al.startswith(base + ":") or base in al or al in base:
            return True
    return False


def match_node_for_model(
    model_id: str,
    nodes: list[dict[str, Any]],
    *,
    vram_need: Optional[float] = None,
) -> dict[str, Any]:
    """Pick the best node for ``model_id``.

    ``nodes``: dicts with ``node_id``/``id``, ``vram_gb``, ``ram_gb``,
    ``current_load``, ``available_models``, ``online``. Returns
    ``{node_id, needs_pull, vram_need, on_gpu, reason}`` for the winner, or
    ``{"error": ..., "vram_need": ...}`` when nothing fits.

    Ranking (lower score wins): already-cached beats needs-pull; GPU beats CPU;
    then best-fit (least wasted VRAM); then least loaded.
    """
    if vram_need is None:
        vram_need = estimate_model_vram(model_id)

    candidates: list[tuple[float, dict, bool, bool]] = []
    for n in nodes:
        if not n.get("online", True):
            continue
        vram = float(n.get("vram_gb") or 0.0)
        ram = float(n.get("ram_gb") or 0.0)
        on_gpu = vram >= vram_need and vram > 0
        # CPU fallback: no GPU (or too small), but enough system RAM to run it.
        on_cpu = (not on_gpu) and ram >= max(vram_need * 1.3, 2.0)
        if not (on_gpu or on_cpu):
            continue
        cached = model_is_cached(model_id, n.get("available_models"))
        load = float(n.get("current_load") or 0.0)
        waste = (vram - vram_need) if on_gpu else 0.0
        score = (
            (0 if cached else 100)      # cached beats pull
            + (0 if on_gpu else 40)     # GPU beats CPU
            + waste                     # best-fit: don't burn a big GPU on a small model
            + load * 10                 # then least-loaded
        )
        candidates.append((score, n, cached, on_gpu))

    if not candidates:
        return {
            "error": f"no online node can run {model_id} (needs ~{vram_need:g}GB)",
            "vram_need": vram_need,
        }
    candidates.sort(key=lambda c: c[0])
    _, node, cached, on_gpu = candidates[0]
    return {
        "node_id": node.get("node_id") or node.get("id"),
        "needs_pull": not cached,
        "on_gpu": on_gpu,
        "vram_need": vram_need,
        "reason": (
            f"{'cached' if cached else 'pull required'} · "
            f"{'GPU' if on_gpu else 'CPU'} · ~{vram_need:g}GB"
        ),
    }


def _norm_model_name(m: str) -> str:
    """Loose model key for comparing running vs desired: strip org + :tag, then
    drop non-alphanumerics so microsoft/Phi-4 == ollama phi4."""
    import re
    base = str(m or "").lower().split("/")[-1].split(":")[0]
    return re.sub(r"[^a-z0-9]", "", base)


def reconcile_models(
    desired_models: list[str],
    nodes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Idempotent desired-state reconcile for models: for each desired model NOT
    already running on some node (per ``running_backends``), plan its placement;
    already-running ones are skipped. Returns the placement plan for the gap —
    empty when the fleet already satisfies the desired set. This is what a
    scheduled loop calls to keep the fleet converged with no hand-assignment.
    """
    running = set()
    for n in nodes:
        for m in (n.get("running_backends") or {}).values():
            if m:
                running.add(_norm_model_name(m))
    to_place = [m for m in desired_models if _norm_model_name(m) not in running]
    return plan_model_placements(to_place, nodes)


def plan_model_placements(
    models: list[str],
    nodes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Plan placement for a SET of desired models across the fleet — the
    reconcile-loop primitive. Each accepted placement bumps that node's
    effective load and marks the model cached-there, so subsequent models
    spread out instead of all piling onto the single best node. Returns one
    ``{model, ...}`` entry per input model (winner + needs_pull, or an error).
    """
    working = [dict(n) for n in nodes]
    by_id = {(n.get("node_id") or n.get("id")): n for n in working}
    plan: list[dict[str, Any]] = []
    for model in models:
        d = match_node_for_model(model, working)
        plan.append({"model": model, **d})
        nid = d.get("node_id")
        if nid and nid in by_id:
            node = by_id[nid]
            node["current_load"] = float(node.get("current_load") or 0.0) + 0.25
            am = node.setdefault("available_models", [])
            if model not in am:
                am.append(model)  # it'll be pulled → treat as present for the next pick
    return plan
