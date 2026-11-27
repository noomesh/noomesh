# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Which containers consume which certificates.

Shared by the CLI rotation orchestrator (host-side, docker restart) and the
heartbeat cert_auto_rotate action (in-container, host-spool restart) so both
reload the same consumers after a rotation.
"""
from __future__ import annotations

from pathlib import Path


def cert_consumers(name: str, role: str, local_hostname: str = "") -> list[str]:
    """Container names that must reload when the cert at ``name`` rotates.

    ``name`` is the pki-relative path (e.g. ``services/nats/service.crt``).
    Worker node certs are shipped by ansible and reloaded on the worker —
    only the controller-local node-agent is returned, and only when the
    node cert belongs to ``local_hostname``.
    """
    if role == "gateway":
        return ["noo-gateway"]
    if role == "service":
        svc = Path(name).parent.name
        out = [f"noo-{svc}", f"noo-stunnel-{svc}"]
        if svc == "vllm":
            # vllm-secondary's door mounts the same services/vllm leaf.
            out += ["noo-stunnel-vllm-secondary", "noo-vllm-secondary"]
        return out
    if role == "node" and local_hostname and Path(name).parent.name == local_hostname:
        return ["noo-node-agent"]
    return []
