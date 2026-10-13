# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Fault injection — the availability control test.

Injects a fault mid-run and watches the cluster's own health surface to time
detection and recovery. Kept intentionally minimal and *opt-in*: real node
kills require cluster-admin creds, so the default injector is a no-op that
records the intended fault for the report. Wire ``NodeKillInjector`` with a
callable that actually stops/starts the node (e.g. via ``noo cluster`` or the
node-agent control API) when you want live chaos testing.
"""
from __future__ import annotations

import asyncio
import time
from typing import Awaitable, Callable, Optional

import httpx

from .scenario import FaultSpec
from .schema import FaultEvent


async def _node_online(base_url: str, token: str, node_id: str) -> bool:
    auth = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        async with httpx.AsyncClient(base_url=base_url, headers=auth, timeout=8.0, verify=True) as c:
            r = await c.get("/api/cluster/nodes")
            for n in (r.json().get("nodes", []) if r.is_success else []):
                if (n.get("node_id") or n.get("id")) == node_id:
                    return bool(n.get("online", n.get("status") == "online"))
    except Exception:
        return False
    return False


class NodeKillInjector:
    """Stop a node, watch for the cluster to mark it offline, then restore.

    ``stop`` / ``start`` are async callables you provide (they do the actual
    kill). Detection = time until ``/api/cluster/nodes`` shows it offline.
    Recovery = time from restore until it shows online again (MTTR).
    """

    def __init__(self, base_url: str, token: str,
                 stop: Optional[Callable[[str], Awaitable[None]]] = None,
                 start: Optional[Callable[[str], Awaitable[None]]] = None):
        self.base_url, self.token = base_url, token
        self.stop, self.start = stop, start

    async def run(self, spec: FaultSpec, t0: float) -> FaultEvent:
        ev = FaultEvent(t_offset_s=time.monotonic() - t0, kind=spec.kind, target=spec.target)
        if self.stop is None:
            ev.note = "dry-run (no stop callable wired) — intended fault recorded only"
            return ev
        # inject
        await self.stop(spec.target)
        t_inject = time.monotonic()
        # detect
        for _ in range(60):
            if not await _node_online(self.base_url, self.token, spec.target):
                ev.detected_s = time.monotonic() - t_inject
                break
            await asyncio.sleep(1)
        # restore + measure recovery
        if self.start is not None:
            await self.start(spec.target)
            t_restore = time.monotonic()
            for _ in range(120):
                if await _node_online(self.base_url, self.token, spec.target):
                    ev.recovered_s = time.monotonic() - t_restore
                    break
                await asyncio.sleep(1)
            ev.note = "restored"
        return ev


async def schedule_faults(injector: NodeKillInjector, specs: list[FaultSpec], t0: float) -> list[FaultEvent]:
    """Fire each spec at its ``at_s`` offset, concurrently with the load phase."""
    async def fire(spec: FaultSpec) -> FaultEvent:
        delay = spec.at_s - (time.monotonic() - t0)
        if delay > 0:
            await asyncio.sleep(delay)
        return await injector.run(spec, t0)

    if not specs:
        return []
    return list(await asyncio.gather(*(fire(s) for s in specs)))
