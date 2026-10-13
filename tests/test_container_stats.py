# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for Docker container stats CPU/memory/IO calculations.

The node_agent module lives in ``docker/`` and depends on the Docker SDK
which isn't installed in the test venv.  We replicate the calculation
logic here so we can unit-test the maths independently.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Replicate the core calculation from NodeAgent.get_container_stats()
# This is the exact same logic as in docker/node_agent.py — if you change
# the algorithm there, update these helpers too.
# ---------------------------------------------------------------------------

def compute_container_stats(raw: dict) -> dict:
    """Compute derived metrics from a raw Docker stats JSON snapshot."""
    # ── CPU % ──
    cpu_delta = (
        raw.get("cpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0)
        - raw.get("precpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0)
    )
    system_delta = (
        raw.get("cpu_stats", {}).get("system_cpu_usage", 0)
        - raw.get("precpu_stats", {}).get("system_cpu_usage", 0)
    )
    num_cpus = raw.get("cpu_stats", {}).get("online_cpus") or len(
        raw.get("cpu_stats", {}).get("cpu_usage", {}).get("percpu_usage", []) or [1]
    )
    cpu_pct = (cpu_delta / system_delta * num_cpus * 100.0) if system_delta > 0 else 0.0

    # ── Memory ──
    mem_stats = raw.get("memory_stats", {})
    mem_usage = mem_stats.get("usage", 0)
    cache = mem_stats.get("stats", {}).get("inactive_file", 0)
    if cache:
        mem_usage = max(mem_usage - cache, 0)
    mem_limit = mem_stats.get("limit", 0)
    mem_pct = (mem_usage / mem_limit * 100.0) if mem_limit > 0 else 0.0

    # ── Net I/O ──
    networks = raw.get("networks", {})
    net_rx = sum(iface.get("rx_bytes", 0) for iface in networks.values())
    net_tx = sum(iface.get("tx_bytes", 0) for iface in networks.values())

    # ── Block I/O ──
    blkio = raw.get("blkio_stats", {}).get("io_service_bytes_recursive") or []
    block_read = sum(e.get("value", 0) for e in blkio if e.get("op", "").lower() == "read")
    block_write = sum(e.get("value", 0) for e in blkio if e.get("op", "").lower() == "write")

    MB = 1024 * 1024

    return {
        "cpu_percent": round(cpu_pct, 2),
        "mem_usage_mb": round(mem_usage / MB, 1),
        "mem_limit_mb": round(mem_limit / MB, 1),
        "mem_percent": round(mem_pct, 1),
        "net_rx_mb": round(net_rx / MB, 2),
        "net_tx_mb": round(net_tx / MB, 2),
        "block_read_mb": round(block_read / MB, 2),
        "block_write_mb": round(block_write / MB, 2),
    }


# ---------------------------------------------------------------------------
# Helpers to build raw Docker stats payloads
# ---------------------------------------------------------------------------

def _make_raw_stats(
    *,
    cpu_total: int = 200_000_000,
    precpu_total: int = 100_000_000,
    system_cpu: int = 2_000_000_000,
    presystem_cpu: int = 1_000_000_000,
    online_cpus: int = 4,
    mem_usage: int = 200 * 1024 * 1024,
    mem_limit: int = 1024 * 1024 * 1024,
    inactive_file: int = 0,
    rx_bytes: int = 5 * 1024 * 1024,
    tx_bytes: int = 2 * 1024 * 1024,
    blkio_read: int = 10 * 1024 * 1024,
    blkio_write: int = 3 * 1024 * 1024,
) -> dict:
    return {
        "cpu_stats": {
            "cpu_usage": {"total_usage": cpu_total, "percpu_usage": [0] * online_cpus},
            "system_cpu_usage": system_cpu,
            "online_cpus": online_cpus,
        },
        "precpu_stats": {
            "cpu_usage": {"total_usage": precpu_total, "percpu_usage": [0] * online_cpus},
            "system_cpu_usage": presystem_cpu,
        },
        "memory_stats": {
            "usage": mem_usage,
            "limit": mem_limit,
            "stats": {"inactive_file": inactive_file},
        },
        "networks": {
            "eth0": {"rx_bytes": rx_bytes, "tx_bytes": tx_bytes},
        },
        "blkio_stats": {
            "io_service_bytes_recursive": [
                {"op": "Read", "value": blkio_read},
                {"op": "Write", "value": blkio_write},
            ],
        },
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCPUCalculation:
    def test_basic_cpu_percent(self):
        """CPU% = (delta_cpu / delta_system) * num_cpus * 100."""
        raw = _make_raw_stats(
            cpu_total=200_000_000,
            precpu_total=100_000_000,
            system_cpu=2_000_000_000,
            presystem_cpu=1_000_000_000,
            online_cpus=4,
        )
        result = compute_container_stats(raw)
        # delta_cpu=100M, delta_system=1G, cpus=4 → 100M/1G*4*100 = 40%
        assert result["cpu_percent"] == 40.0

    def test_zero_system_delta(self):
        """When system delta is zero, CPU% should be 0."""
        raw = _make_raw_stats(system_cpu=1_000, presystem_cpu=1_000)
        result = compute_container_stats(raw)
        assert result["cpu_percent"] == 0.0

    def test_high_cpu_single_core(self):
        """Single-core container using most of its slice."""
        raw = _make_raw_stats(
            cpu_total=950_000_000,
            precpu_total=0,
            system_cpu=1_000_000_000,
            presystem_cpu=0,
            online_cpus=1,
        )
        result = compute_container_stats(raw)
        assert result["cpu_percent"] == 95.0

    def test_multi_cpu_scaling(self):
        """8-core system, delta ratios yield correct scaling."""
        raw = _make_raw_stats(
            cpu_total=500_000_000,
            precpu_total=0,
            system_cpu=1_000_000_000,
            presystem_cpu=0,
            online_cpus=8,
        )
        result = compute_container_stats(raw)
        # 500M/1G * 8 * 100 = 400%
        assert result["cpu_percent"] == 400.0

    def test_percpu_fallback_when_no_online_cpus(self):
        """Falls back to len(percpu_usage) when online_cpus is absent."""
        raw = _make_raw_stats(online_cpus=2)
        # Remove online_cpus key, but keep percpu_usage list of length 2
        del raw["cpu_stats"]["online_cpus"]
        result = compute_container_stats(raw)
        # delta_cpu=100M, delta_system=1G, cpus=2 → 20%
        assert result["cpu_percent"] == 20.0


class TestMemoryCalculation:
    def test_basic_memory(self):
        raw = _make_raw_stats(mem_usage=512 * 1024 * 1024, mem_limit=1024 * 1024 * 1024)
        result = compute_container_stats(raw)
        assert result["mem_usage_mb"] == 512.0
        assert result["mem_limit_mb"] == 1024.0
        assert result["mem_percent"] == 50.0

    def test_memory_minus_cache(self):
        """Memory should subtract inactive_file cache (cgroup v1)."""
        raw = _make_raw_stats(
            mem_usage=300 * 1024 * 1024,
            mem_limit=1024 * 1024 * 1024,
            inactive_file=100 * 1024 * 1024,
        )
        result = compute_container_stats(raw)
        assert result["mem_usage_mb"] == 200.0

    def test_cache_larger_than_usage(self):
        """Cache > usage should clamp to 0, not go negative."""
        raw = _make_raw_stats(
            mem_usage=50 * 1024 * 1024,
            mem_limit=1024 * 1024 * 1024,
            inactive_file=100 * 1024 * 1024,
        )
        result = compute_container_stats(raw)
        assert result["mem_usage_mb"] == 0.0
        assert result["mem_percent"] == 0.0

    def test_zero_mem_limit(self):
        raw = _make_raw_stats(mem_limit=0)
        result = compute_container_stats(raw)
        assert result["mem_percent"] == 0.0


class TestNetworkIO:
    def test_single_interface(self):
        raw = _make_raw_stats(rx_bytes=10 * 1024 * 1024, tx_bytes=5 * 1024 * 1024)
        result = compute_container_stats(raw)
        assert result["net_rx_mb"] == 10.0
        assert result["net_tx_mb"] == 5.0

    def test_multiple_interfaces(self):
        raw = _make_raw_stats(rx_bytes=10 * 1024 * 1024, tx_bytes=5 * 1024 * 1024)
        raw["networks"]["eth1"] = {"rx_bytes": 2 * 1024 * 1024, "tx_bytes": 1 * 1024 * 1024}
        result = compute_container_stats(raw)
        assert result["net_rx_mb"] == 12.0
        assert result["net_tx_mb"] == 6.0

    def test_no_networks(self):
        raw = _make_raw_stats()
        raw["networks"] = {}
        result = compute_container_stats(raw)
        assert result["net_rx_mb"] == 0.0
        assert result["net_tx_mb"] == 0.0


class TestBlockIO:
    def test_read_write(self):
        raw = _make_raw_stats(blkio_read=20 * 1024 * 1024, blkio_write=8 * 1024 * 1024)
        result = compute_container_stats(raw)
        assert result["block_read_mb"] == 20.0
        assert result["block_write_mb"] == 8.0

    def test_none_blkio(self):
        """io_service_bytes_recursive can be None (cgroup v2 with no I/O)."""
        raw = _make_raw_stats()
        raw["blkio_stats"]["io_service_bytes_recursive"] = None
        result = compute_container_stats(raw)
        assert result["block_read_mb"] == 0.0
        assert result["block_write_mb"] == 0.0

    def test_empty_blkio(self):
        raw = _make_raw_stats()
        raw["blkio_stats"]["io_service_bytes_recursive"] = []
        result = compute_container_stats(raw)
        assert result["block_read_mb"] == 0.0
        assert result["block_write_mb"] == 0.0

    def test_mixed_case_ops(self):
        """Docker may return ops as 'read'/'write' (lowercase)."""
        raw = _make_raw_stats()
        raw["blkio_stats"]["io_service_bytes_recursive"] = [
            {"op": "read", "value": 1024 * 1024},
            {"op": "write", "value": 2 * 1024 * 1024},
            {"op": "sync", "value": 500},
        ]
        result = compute_container_stats(raw)
        assert result["block_read_mb"] == 1.0
        assert result["block_write_mb"] == 2.0


class TestEmptyStats:
    def test_completely_empty_dict(self):
        """An empty stats dict should return all zeros without crashing."""
        result = compute_container_stats({})
        assert result["cpu_percent"] == 0.0
        assert result["mem_usage_mb"] == 0.0
        assert result["mem_limit_mb"] == 0.0
        assert result["mem_percent"] == 0.0
        assert result["net_rx_mb"] == 0.0
        assert result["net_tx_mb"] == 0.0
        assert result["block_read_mb"] == 0.0
        assert result["block_write_mb"] == 0.0
