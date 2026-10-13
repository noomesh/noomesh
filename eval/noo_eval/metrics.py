# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Aggregation helpers — turn raw ``ReqRecord`` lists into report-ready stats."""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field

from .schema import ReqRecord, RunResult


def percentile(values: list[float], p: float) -> float:
    """Nearest-rank percentile. ``p`` in [0, 100]."""
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(math.ceil(p / 100.0 * len(s))) - 1))
    return s[k]


@dataclass
class LatencyStats:
    count: int = 0
    ok: int = 0
    p50: float = 0.0
    p95: float = 0.0
    p99: float = 0.0
    mean: float = 0.0

    @property
    def error_rate(self) -> float:
        return 0.0 if self.count == 0 else 1.0 - self.ok / self.count

    @classmethod
    def of(cls, recs: list[ReqRecord]) -> "LatencyStats":
        lat = [r.latency_ms for r in recs if r.ok]
        ok = sum(1 for r in recs if r.ok)
        return cls(
            count=len(recs),
            ok=ok,
            p50=percentile(lat, 50),
            p95=percentile(lat, 95),
            p99=percentile(lat, 99),
            mean=(sum(lat) / len(lat)) if lat else 0.0,
        )


@dataclass
class Aggregates:
    overall: LatencyStats
    by_node: dict[str, LatencyStats] = field(default_factory=dict)
    by_model: dict[str, LatencyStats] = field(default_factory=dict)
    by_location: dict[str, LatencyStats] = field(default_factory=dict)
    by_user: dict[str, LatencyStats] = field(default_factory=dict)
    routing: dict[str, int] = field(default_factory=dict)          # node -> request count
    throughput: list[tuple[float, int]] = field(default_factory=list)  # (bucket_start_s, count)
    mttr: dict[str, float] = field(default_factory=dict)           # fault target -> recovery s

    @property
    def total_requests(self) -> int:
        return self.overall.count


def _group(recs: list[ReqRecord], key) -> dict[str, LatencyStats]:
    buckets: dict[str, list[ReqRecord]] = defaultdict(list)
    for r in recs:
        buckets[key(r) or "unknown"].append(r)
    return {k: LatencyStats.of(v) for k, v in sorted(buckets.items())}


def throughput_series(recs: list[ReqRecord], bucket_s: float, duration_s: float) -> list[tuple[float, int]]:
    n = max(1, int(math.ceil(duration_s / bucket_s)))
    counts = [0] * n
    for r in recs:
        b = min(n - 1, int(r.t_offset_s // bucket_s))
        counts[b] += 1
    return [(i * bucket_s, c) for i, c in enumerate(counts)]


def aggregate(run: RunResult, bucket_s: float = 5.0) -> Aggregates:
    recs = run.requests
    agg = Aggregates(overall=LatencyStats.of(recs))
    agg.by_node = _group(recs, lambda r: r.node)
    agg.by_model = _group(recs, lambda r: r.model)
    agg.by_location = _group(recs, lambda r: r.location)
    agg.by_user = _group(recs, lambda r: r.user)
    routing: dict[str, int] = defaultdict(int)
    for r in recs:
        routing[r.node or "unknown"] += 1
    agg.routing = dict(sorted(routing.items()))
    agg.throughput = throughput_series(recs, bucket_s, run.duration_s or 1.0)
    agg.mttr = {
        f.target: f.recovered_s
        for f in run.faults
        if f.recovered_s is not None
    }
    return agg
