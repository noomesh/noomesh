# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Deterministic demo dataset — a believable multi-axis run with no live cluster.

Mirrors a small fleet (controller-a gemma-4 GPU controller, node-a 26B CPU thinker +
bge embeddings, edge-node tier-3, plus a second federated controller) so the
rendered report shows the true shape of a live evaluation. Seeded RNG → the
same numbers every time (reproducible; no wall-clock read).
"""
from __future__ import annotations

import random

from .schema import (FaultEvent, IsolationTest, NodeInfo, ReplEvent, ReqRecord,
                     RunResult, SecurityPosture)

_RNG = random.Random(20260711)

# Real fleet shape (from cluster memory) + one federated peer controller.
_NODES = [
    NodeInfo(node_id="controller-a", role="controller", location="home-lab", online=True,
             gpu_model="RTX 4090", vram_gb=24.0, backends=["vllm", "embedding"], tier=1),
    NodeInfo(node_id="node-a", role="worker", location="home-lab", online=True,
             gpu_model="RTX 3060", vram_gb=12.0, backends=["llamacpp", "embedding"], tier=2),
    NodeInfo(node_id="edge-node", role="worker", location="us-east", online=True,
             gpu_model=None, vram_gb=0.0, backends=["llamacpp"], tier=3),
    NodeInfo(node_id="edge-eu", role="worker", location="eu-west", online=True,
             gpu_model="RTX 4070", vram_gb=12.0, backends=["vllm"], tier=2),
]

# per-node base latency (ms) and jitter by workload family
_LAT = {
    ("controller-a", "chat"): (420, 140), ("controller-a", "embed"): (28, 10),
    ("node-a", "chat"): (1350, 380), ("node-a", "embed"): (34, 12),
    ("edge-node", "chat"): (2600, 700),
    ("edge-eu", "chat"): (480, 160),
}
_ROUTE = {  # workload family -> candidate nodes (weighted by index)
    "chat": ["controller-a", "controller-a", "edge-eu", "node-a", "edge-node"],
    "embed": ["controller-a", "node-a"],
    "rerank": ["controller-a"],
}
_USERS = [
    ("alice", "home-lab", 0.35, "project-atlas-launch-code-7731"),
    ("bob", "us-east", 0.25, "bob-medical-record-A"),
    ("carol", "eu-west", 0.20, "carol-salary-figure"),
    ("dave", "us-east", 0.12, None),
    ("erin", "home-lab", 0.08, None),
]
_ENDPOINTS = [
    ("/v1/chat/completions", "chat", "gemma-4-12b", 0.55),
    ("/api/external/inference", "chat", "gemma-4-12b", 0.15),
    ("/api/external/embeddings", "embed", "bge", 0.22),
    ("/api/external/rerank", "rerank", "bge-reranker", 0.08),
]


def _pick(weighted):
    items = [x[:-1] if len(x) > 2 else x[0] for x in weighted]
    return _RNG.choices(items, weights=[x[-1] for x in weighted], k=1)[0]


def build_demo() -> RunResult:
    duration = 120.0
    kill_at, restore_recovered = 60.0, 18.0  # edge-node killed at t+60, MTTR 18s
    reqs: list[ReqRecord] = []

    n = 1600
    for i in range(n):
        t = _RNG.uniform(0, duration)
        user, uloc, _, _secret = _RNG.choices(_USERS, weights=[u[2] for u in _USERS], k=1)[0]
        ep, fam, model, _ = _RNG.choices(_ENDPOINTS, weights=[e[3] for e in _ENDPOINTS], k=1)[0]
        node = _RNG.choice(_ROUTE[fam])
        # edge-node is offline during the fault window → its traffic reroutes to controller-a, a few fail
        failed = False
        if node == "edge-node" and kill_at <= t <= kill_at + restore_recovered:
            if _RNG.random() < 0.25:
                failed = True
            else:
                node = "controller-a"  # rerouted
        base, jit = _LAT.get((node, fam), (500, 150))
        lat = max(5.0, _RNG.gauss(base, jit))
        # tail: 3% slow requests
        if _RNG.random() < 0.03:
            lat *= _RNG.uniform(1.8, 3.2)
        ok = not failed and _RNG.random() > 0.004
        reqs.append(ReqRecord(
            t_offset_s=round(t, 2), user=user, location=uloc, endpoint=ep,
            model=model, node=node if ok else "", latency_ms=round(lat, 1),
            ok=ok, status=200 if ok else (503 if failed else 500),
        ))
    reqs.sort(key=lambda r: r.t_offset_s)

    faults = [FaultEvent(
        t_offset_s=kill_at, kind="node_kill", target="edge-node",
        detected_s=4.0, recovered_s=restore_recovered,
        note="edge-node killed; scheduler rerouted chat traffic to controller-a, 25% in-flight failed until reconnect",
    )]

    # Cross-user isolation probes (H-D1 control). Single-user deploy today → all isolated.
    isolation = [
        IsolationTest(user_a="alice", user_b="bob",
                      probe="memory_search('atlas launch code')", leaked=False,
                      detail="bob's session scoped to bob; alice's secret not returned"),
        IsolationTest(user_a="carol", user_b="dave",
                      probe="conversation_context(other user)", leaked=False,
                      detail="persona_id filter applied at store layer"),
        IsolationTest(user_a="bob", user_b="erin",
                      probe="rag_query('medical record')", leaked=False,
                      detail="RAG namespace partitioned by canonical user"),
    ]

    # Federated push: controller-a primary + edge-eu-ctrl secondary controller.
    replication = []
    for k in range(0, int(duration) + 1, 10):
        replication.append(ReplEvent(t_offset_s=float(k), controller="edge-eu-ctrl",
                                     lag_s=round(_RNG.uniform(0.4, 1.6), 2), ok=True))
        # lag spikes during the fault window
        if kill_at <= k <= kill_at + 20:
            replication[-1].lag_s = round(_RNG.uniform(2.5, 4.5), 2)

    return RunResult(
        scenario="SYNTHETIC DEMO — fabricated data, not your cluster",
        axes=["node", "user", "location", "controller"],
        started_at="(synthetic — seeded RNG)",
        duration_s=duration,
        gateway="example.invalid (fake)",
        topology=_NODES,
        requests=reqs,
        faults=faults,
        isolation_tests=isolation,
        replication=replication,
        security=SecurityPosture(auth_failures=6, exec_denials=2, rate_limited=3,
                                 audit_rows_written=1642),
        notes=[
            "⚠️ SYNTHETIC — every number here is fabricated by a seeded RNG to show the "
            "report LAYOUT. 'edge-eu' does not exist; locations, GPUs, latencies, faults, "
            "and replication are all invented. For real data run `python -m noo_eval topology`.",
            "The example fleet is controller-a + node-a + edge-node, all on the tailnet (no EU node).",
            "Isolation probes illustrate the H-D1 control test: they must all read 'isolated' before multi-user mode ships.",
        ],
    )
