# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Collect cluster topology + security posture from the live surface.

Topology comes from the gateway ``/api/cluster/nodes`` endpoint; security
counters come from Prometheus instant queries (the ``noo_auth_failures_5m`` /
``noo_exec_denials_5m`` gauges wired in H-L4). All best-effort: a missing
surface degrades to empty, never raises.
"""
from __future__ import annotations

import asyncio
import json
import socket

import httpx

from .schema import NodeInfo, SecurityPosture


async def collect_topology_cli() -> list[NodeInfo]:
    """Real topology via ``noo cluster status --json`` (uses the CLI's own
    mTLS/token auth, so no gateway bearer needed). Locations aren't tracked by
    the cluster today, so every node is tagged ``tailnet``; role is inferred by
    matching the local hostname to the controller. Returns [] on any failure.
    """
    raw = None
    for cli in ("noo", "pai"):          # `noo` is the CLI; `pai` is its retired name
        try:
            proc = await asyncio.create_subprocess_exec(
                cli, "cluster", "status", "--json",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            raw = json.loads(out.decode())
            break
        except Exception:
            continue
    if raw is None:
        return []

    this_host = socket.gethostname()
    nodes: list[NodeInfo] = []
    for n in raw.get("nodes", raw if isinstance(raw, list) else []):
        node_id = n.get("id") or n.get("hostname") or "unknown"
        caps = n.get("capabilities") or {}
        backends = sorted((n.get("running_backends") or {}).keys()) \
            or caps.get("backends") or []
        vram = float(n.get("vram_gb") or caps.get("vram_gb") or 0)
        nodes.append(NodeInfo(
            node_id=node_id,
            role="controller" if node_id == this_host else "worker",
            # Real location when the node reports one (NODE_LOCATION, broadcast
            # via heartbeat); falls back to "tailnet" for nodes that don't.
            location=n.get("location") or "tailnet",
            online=n.get("status") in ("online", "busy", "ready"),
            gpu_model=(n.get("gpu_model") or caps.get("gpu_model")) if vram > 0 else None,
            vram_gb=vram,
            backends=list(backends),
            cached_models=list(n.get("available_models") or []),
            tier=int(n.get("tier") or caps.get("tier") or 3),
        ))
    return nodes


async def collect_topology(base_url: str, token: str = "") -> list[NodeInfo]:
    auth = {"Authorization": f"Bearer {token}"} if token else {}
    nodes: list[NodeInfo] = []
    try:
        async with httpx.AsyncClient(base_url=base_url, headers=auth, timeout=15.0, verify=True) as c:
            r = await c.get("/api/cluster/nodes")
            r.raise_for_status()
            data = r.json()
            raw = data.get("nodes", data) if isinstance(data, dict) else data
            for n in raw:
                nodes.append(NodeInfo(
                    node_id=n.get("node_id") or n.get("id") or "unknown",
                    role=n.get("role", "worker"),
                    location=n.get("location") or n.get("region") or "unknown",
                    online=bool(n.get("online", n.get("status") == "online")),
                    gpu_model=n.get("gpu_model"),
                    vram_gb=float(n.get("vram_gb", 0) or 0),
                    backends=n.get("backends", []) or [],
                    tier=int(n.get("tier", 3) or 3),
                ))
    except Exception:
        pass
    return nodes


async def _prom_scalar(client: httpx.AsyncClient, query: str) -> float:
    try:
        r = await client.get("/api/v1/query", params={"query": query})
        r.raise_for_status()
        result = r.json()["data"]["result"]
        return float(result[0]["value"][1]) if result else 0.0
    except Exception:
        return 0.0


async def collect_security(prom_url: str) -> SecurityPosture:
    sp = SecurityPosture()
    try:
        async with httpx.AsyncClient(base_url=prom_url, timeout=15.0, verify=True) as c:
            sp.auth_failures = int(await _prom_scalar(c, "noo_auth_failures_5m"))
            sp.exec_denials = int(await _prom_scalar(c, "noo_exec_denials_5m"))
            sp.rate_limited = int(await _prom_scalar(c, "noo_rate_limited_5m"))
            sp.audit_rows_written = int(await _prom_scalar(c, "noo_audit_rows_total"))
    except Exception:
        pass
    return sp
