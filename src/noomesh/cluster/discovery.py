# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Cluster discovery — probe SSH reachability + cluster registration state.

Used by the ``noo_cluster_discover`` MCP tool. Pure read-only network
probes + DB lookups; no state changes anywhere.

Two probe types:

- **TCP/22 reach** — short-timeout connect to port 22. A TCP RST or
  timeout means "can't reach"; a SUCCESSFUL connect means "SSH is
  listening." We don't try to authenticate — that would require
  credentials and would generate failed-login noise on the target.
- **DB-registered** — cross-check against ``cluster_nodes`` to see if
  the host is already an enrolled cluster member.

Discovery sources:

1. Concrete entries in the inventory file (`trusted_hosts[].host`)
2. IPs expanded from inventory subnet entries (`trusted_hosts[].subnet`)
3. Optional ad-hoc subnet passed by the caller

Subnet expansion is bounded to /20 (4k hosts) to keep the probe fast
and to avoid accidentally scanning a large network.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import asdict, dataclass
from typing import Optional

from .inventory import Inventory, TrustedHost, load_inventory


_SSH_PORT = 22
_PROBE_TIMEOUT = 1.5  # seconds; quick fail for unreachable
_MAX_SUBNET_HOSTS = 4096  # /20
_MAX_PARALLEL = 64


@dataclass
class HostProbe:
    """Result of probing one host."""
    host: str
    user: str
    role: str = ""
    notes: str = ""
    auto_enroll: bool = False
    in_inventory: bool = False
    ssh_reachable: bool = False
    already_registered: bool = False
    registered_node_id: Optional[str] = None


async def _probe_ssh(host: str, timeout: float = _PROBE_TIMEOUT) -> bool:
    """Try to open a TCP connection to host:22. No auth attempted."""
    try:
        loop = asyncio.get_running_loop()
        # Resolve the hostname first (gives a clearer reachable=False
        # for DNS failures vs port-unreachable). Run in executor since
        # gethostbyname is sync.
        await loop.run_in_executor(None, socket.gethostbyname, host)
        fut = asyncio.open_connection(host, _SSH_PORT)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _probe_many(hosts: list[str], parallel: int = _MAX_PARALLEL) -> dict[str, bool]:
    """Probe many hosts concurrently with a concurrency cap."""
    sem = asyncio.Semaphore(parallel)
    results: dict[str, bool] = {}

    async def one(h: str) -> None:
        async with sem:
            results[h] = await _probe_ssh(h)

    await asyncio.gather(*(one(h) for h in hosts))
    return results


def _expand(inventory: Inventory, ad_hoc_subnet: Optional[str]) -> list[TrustedHost]:
    """Build the full host list from inventory + optional ad-hoc subnet.

    Each ad-hoc-discovered IP is wrapped in a TrustedHost with
    ``in_inventory=False`` semantics (caller picks the user)."""
    rows: list[TrustedHost] = []
    seen: set[str] = set()

    # 1. Concrete inventory entries
    for h in inventory.trusted_concrete():
        if h.host and h.host not in seen:
            rows.append(h)
            seen.add(h.host)

    # 2. Subnet entries from inventory
    for entry in inventory.discovery_subnets():
        try:
            net = ipaddress.ip_network(entry.subnet, strict=False)
        except ValueError:
            continue
        if net.num_addresses > _MAX_SUBNET_HOSTS:
            continue  # refuse huge ranges
        for ip in entry.expand_subnet():
            if ip in seen:
                continue
            seen.add(ip)
            rows.append(TrustedHost(
                host=ip,
                user=entry.user,
                role=entry.role,
                notes=f"discovered in {entry.subnet}",
                auto_enroll=False,  # discovered ≠ pre-trusted
            ))

    # 3. Ad-hoc subnet passed by caller
    if ad_hoc_subnet:
        try:
            net = ipaddress.ip_network(ad_hoc_subnet, strict=False)
            if net.num_addresses <= _MAX_SUBNET_HOSTS:
                for ip in net.hosts():
                    s = str(ip)
                    if s in seen:
                        continue
                    seen.add(s)
                    rows.append(TrustedHost(
                        host=s,
                        user="noo",
                        role="",
                        notes=f"ad-hoc scan of {ad_hoc_subnet}",
                        auto_enroll=False,
                    ))
        except ValueError:
            pass

    return rows


async def _registered_hosts() -> dict[str, str]:
    """Return {ip_or_hostname: node_id} for already-enrolled nodes."""
    try:
        from .node import get_node_registry
    except Exception:
        return {}
    try:
        registry = get_node_registry()
    except Exception:
        return {}
    if not registry:
        return {}
    out: dict[str, str] = {}
    for node in registry.list_nodes():
        # Match on either IP or hostname
        ip = getattr(node, "ip", None) or getattr(node, "address", None)
        host = getattr(node, "hostname", None)
        node_id = getattr(node, "node_id", None)
        if not node_id:
            continue
        if ip:
            out[str(ip)] = node_id
        if host:
            out[str(host)] = node_id
    return out


async def discover(
    *,
    subnet: Optional[str] = None,
    skip_unreachable: bool = True,
    inventory_path: Optional[str] = None,
) -> dict:
    """Run the discovery probe.

    Args:
        subnet: optional ad-hoc CIDR to scan in addition to the
            inventory entries.
        skip_unreachable: when True, hosts that don't answer on port
            22 are omitted from the response. When False, they're
            included with ``ssh_reachable=False``.
        inventory_path: override the default inventory path.

    Returns:
        dict with ``inventory_path``, ``trusted_hosts`` (in inventory),
        ``discovered_hosts`` (from subnet scans, not in inventory), and
        ``cluster_registered`` (already-enrolled nodes).
    """
    from pathlib import Path
    inv = load_inventory(Path(inventory_path) if inventory_path else None)
    candidates = _expand(inv, subnet)

    # Mark which entries came from the inventory (not from ad-hoc/subnet
    # expansion). The two latter cases use auto-generated TrustedHost
    # objects that aren't strictly "in inventory."
    inv_hosts = {h.host for h in inv.trusted_concrete() if h.host}

    # Probe SSH reachability in parallel
    reach = await _probe_many([h.host for h in candidates if h.host])

    # Cross-check the cluster registry
    registered = await _registered_hosts()

    trusted: list[dict] = []
    discovered: list[dict] = []

    for h in candidates:
        if not h.host:
            continue
        ssh_ok = reach.get(h.host, False)
        if skip_unreachable and not ssh_ok and h.host not in inv_hosts:
            continue
        node_id = registered.get(h.host)
        probe = HostProbe(
            host=h.host,
            user=h.user,
            role=h.role,
            notes=h.notes,
            auto_enroll=h.auto_enroll,
            in_inventory=h.host in inv_hosts,
            ssh_reachable=ssh_ok,
            already_registered=bool(node_id),
            registered_node_id=node_id,
        )
        if probe.in_inventory:
            trusted.append(asdict(probe))
        elif ssh_ok or not skip_unreachable:
            discovered.append(asdict(probe))

    return {
        "inventory_path": str(inv.path),
        "inventory_exists": inv.path.exists(),
        "trusted_hosts": trusted,
        "discovered_hosts": discovered,
        "cluster_registered": [
            {"node_id": nid, "address": addr} for addr, nid in registered.items()
        ],
    }
