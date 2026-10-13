# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Async load driver — issues scenario traffic against a live gateway.

Records one :class:`ReqRecord` per request, tagging the serving node from the
response (``x-noo-node`` header, or a ``node`` field in the JSON body). Uses the
external-inference contract (``/v1/*`` + ``/api/external/*``) with the shared
service bearer.
"""
from __future__ import annotations

import asyncio
import random
import time

import httpx

from .scenario import Persona, Scenario, Workload
from .schema import ReqRecord

_DEFAULT_BODY = {
    "/v1/chat/completions": lambda w: {
        "model": w.model or "gemma-4-12b",
        "messages": [{"role": "user", "content": w.prompt}],
        "max_tokens": 64,
    },
    "/api/external/inference": lambda w: {
        "model": w.model or "gemma-4-12b", "prompt": w.prompt, "max_tokens": 64,
    },
    "/api/external/embeddings": lambda w: {
        "model": w.model or "bge", "input": w.prompt,
    },
    "/api/external/rerank": lambda w: {
        "model": w.model or "bge-reranker", "query": w.prompt,
        "documents": ["doc a", "doc b", "doc c"],
    },
    "/api/external/classify": lambda w: {"text": w.prompt},
}


def _weighted(items, key):
    weights = [max(0.0001, key(i)) for i in items]
    return random.choices(items, weights=weights, k=1)[0]


def _body(w: Workload) -> dict:
    base = _DEFAULT_BODY.get(w.endpoint, lambda w: {"prompt": w.prompt})(w)
    base.update(w.payload)
    return base


def _serving_node(resp: httpx.Response) -> str:
    node = resp.headers.get("x-noo-node") or resp.headers.get("x-noo-inference-node")
    if node:
        return node
    try:
        data = resp.json()
        return data.get("node") or data.get("_node") or data.get("served_by") or ""
    except Exception:
        return ""


async def _one(client: httpx.AsyncClient, scn: Scenario, t0: float) -> ReqRecord:
    persona: Persona = _weighted(scn.personas, lambda p: p.weight)
    wl: Workload = _weighted(scn.workloads, lambda w: w.weight)
    started = time.monotonic()
    headers = {"x-noo-user": persona.id, "x-noo-location": persona.location}
    ok, status, node = False, 0, ""
    try:
        resp = await client.post(wl.endpoint, json=_body(wl), headers=headers)
        status = resp.status_code
        ok = resp.is_success
        node = _serving_node(resp)
    except Exception:
        status = 0
    return ReqRecord(
        t_offset_s=started - t0,
        user=persona.id,
        location=persona.location,
        endpoint=wl.endpoint,
        model=wl.model,
        node=node,
        latency_ms=(time.monotonic() - started) * 1000,
        ok=ok,
        status=status,
    )


async def run_load(scn: Scenario, base_url: str, token: str = "", verify=True) -> list[ReqRecord]:
    """Drive ``scn`` against ``base_url`` for ``scn.duration_s`` and return records.

    ``verify`` is passed straight to httpx: True (system CAs), a CA-bundle path,
    or False for a self-signed local gateway.
    """
    records: list[ReqRecord] = []
    limits = httpx.Limits(max_connections=scn.concurrency * 2)
    auth = {"Authorization": f"Bearer {token}"} if token else {}
    async with httpx.AsyncClient(base_url=base_url, headers=auth, limits=limits,
                                 timeout=30.0, verify=verify) as client:
        t0 = time.monotonic()
        interval = (1.0 / scn.rps) if scn.rps > 0 else 0.0

        # A fixed pool of `concurrency` workers, each issuing requests
        # back-to-back until the deadline. This bounds in-flight work (no
        # unbounded task pile-up) so a slow/busy backend can't make the run
        # balloon far past duration_s.
        async def worker():
            while time.monotonic() - t0 < scn.duration_s:
                records.append(await _one(client, scn, t0))
                if interval:
                    await asyncio.sleep(interval)

        await asyncio.gather(*(asyncio.create_task(worker()) for _ in range(scn.concurrency)),
                             return_exceptions=True)
    records.sort(key=lambda r: r.t_offset_s)
    return records
