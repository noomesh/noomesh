# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Cluster inventory file — pre-known hosts the agent can act on.

Lives at ``$XDG_CONFIG_HOME/noo/cluster-inventory.yaml`` (default
``~/.config/noo/cluster-inventory.yaml``). Per-user, kept out of the
repo so credentials-adjacent details don't accidentally get committed.

Schema:

    trusted_hosts:
      - host: 192.0.2.69          # required, IP or hostname
        user: youruser              # required, SSH user
        role: gpu_tier2             # optional, hint for the playbook
        notes: "host8 laptop"      # optional, free text
        auto_enroll: true           # optional, default false

      - subnet: 10.0.0.0/24         # alternate form — discovery range
        user: noo
        auto_enroll: false          # discovery is allowed, each host
                                    # found needs human approval

``auto_enroll: true`` means "this host is already trusted (SSH key
already in authorized_keys, NOPASSWD sudo set up); the agent may
enroll without going through the approval queue." It does NOT mean
"the agent will automatically enroll" — the agent still has to be
asked or have a reason. It removes the manual click-to-approve.

``auto_enroll`` defaults to **false** (safe default — every action
needs explicit approval).
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

import yaml


_DEFAULT_PATH_ENV = "NOO_CLUSTER_INVENTORY"


def inventory_path() -> Path:
    """Resolve the inventory file path with override + XDG fallback.

    The env-var path is honored only if its parent directory is writable.
    This protects against a common misconfiguration where the .env file
    leaks the container-internal path (e.g. /data/config/...) into the host
    shell — the host has no /data, so writes would 13-EACCES.
    """
    explicit = os.environ.get(_DEFAULT_PATH_ENV)
    if explicit:
        p = Path(explicit).expanduser().resolve()
        parent = p.parent
        # If parent exists and is writable, OR doesn't exist but can be created,
        # use the env-specified path. Otherwise fall through to XDG default.
        if parent.exists() and os.access(parent, os.W_OK):
            return p
        if not parent.exists():
            try:
                parent.mkdir(parents=True, exist_ok=True)
                return p
            except (OSError, PermissionError):
                pass
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "noo" / "cluster-inventory.yaml"


@dataclass
class TrustedHost:
    """A single line in the inventory file."""
    host: Optional[str] = None
    subnet: Optional[str] = None
    user: str = "noo"
    role: str = ""
    notes: str = ""
    auto_enroll: bool = False

    def is_subnet(self) -> bool:
        return bool(self.subnet)

    def expand_subnet(self) -> Iterator[str]:
        """Yield concrete IPs from a subnet entry. /32 hosts also welcome."""
        if not self.subnet:
            return
        try:
            net = ipaddress.ip_network(self.subnet, strict=False)
        except ValueError:
            return
        for ip in net.hosts():
            yield str(ip)


@dataclass
class Inventory:
    """Parsed inventory. Empty (`hosts=[]`) when the file doesn't exist —
    the agent can still propose ad-hoc adds, just no whitelisted ones."""
    path: Path
    hosts: list[TrustedHost] = field(default_factory=list)

    def trusted_concrete(self) -> list[TrustedHost]:
        """Inventory entries with an explicit host (not subnet)."""
        return [h for h in self.hosts if h.host and not h.is_subnet()]

    def discovery_subnets(self) -> list[TrustedHost]:
        """Inventory entries that are subnet ranges (for discovery scans)."""
        return [h for h in self.hosts if h.is_subnet()]

    def find(self, host: str) -> Optional[TrustedHost]:
        """Look up a host. Matches concrete entries first, then any
        subnet that contains the host's IP."""
        for h in self.trusted_concrete():
            if h.host == host:
                return h
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return None
        for entry in self.discovery_subnets():
            try:
                if ip in ipaddress.ip_network(entry.subnet, strict=False):
                    return entry
            except ValueError:
                continue
        return None


def load_inventory(path: Optional[Path] = None) -> Inventory:
    """Read + parse the inventory file. Returns an empty Inventory when
    the file is missing — that's a valid state, not an error."""
    p = path or inventory_path()
    if not p.exists():
        return Inventory(path=p, hosts=[])
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return Inventory(path=p, hosts=[])
    rows = raw.get("trusted_hosts") or []
    parsed: list[TrustedHost] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        parsed.append(TrustedHost(
            host=row.get("host"),
            subnet=row.get("subnet"),
            user=row.get("user", "noo"),
            role=row.get("role", ""),
            notes=row.get("notes", ""),
            auto_enroll=bool(row.get("auto_enroll", False)),
        ))
    return Inventory(path=p, hosts=parsed)


def write_inventory(inv: Inventory) -> None:
    """Persist an inventory back to disk. Creates parent dirs as needed."""
    inv.path.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    for h in inv.hosts:
        row: dict = {"user": h.user}
        if h.host:
            row["host"] = h.host
        if h.subnet:
            row["subnet"] = h.subnet
        if h.role:
            row["role"] = h.role
        if h.notes:
            row["notes"] = h.notes
        if h.auto_enroll:
            row["auto_enroll"] = True
        rows.append(row)
    inv.path.write_text(
        yaml.safe_dump({"trusted_hosts": rows}, sort_keys=False),
        encoding="utf-8",
    )
