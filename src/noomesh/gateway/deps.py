# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Central service registry for gateway router modules.

ℹ️ MIXED — The FastAPI ``Depends(require_*)`` machinery here is dead
weight in production (Rust gateway owns the request path). However,
``ssl_verify`` and ``client_cert`` are imported by 6 harness Python files
(MCP client, MCP tools_legacy, sensors, browser, prompt-skill evolver) to
configure their HTTP clients. Those usages stay live until the design
Phase 2 introduces an ``HttpContextProvider`` injected into the harness.

Populated during app.py lifespan startup.  Router modules use
``Depends(require_*)`` to get services with automatic 503 on None.
"""
from __future__ import annotations

import os
from typing import Any, Optional

from fastapi import HTTPException


def ssl_verify():
    """Return the TLS verify setting for gateway-internal HTTP clients.

    Verifies the CA chain AND the hostname.

    This used to set ``check_hostname = False``, on the theory that
    "cluster nodes register with LAN IPs, Docker container names, or
    hostnames" and strict matching was unreliable. The cost of that
    theory was that ANY leaf the cluster CA ever
    issued — every node cert, every service cert, one compromised
    worker — could impersonate any other cluster host to these Python
    clients, which is most of what the CA was there to prevent.

    The names are in the certs. ``noo-cli`` `pki.rs` bakes them in at
    issuance: a service cert carries `<service>` and `localhost` as DNS
    SANs (`issue_service_cert`), a node cert carries `<node_id>`,
    `localhost`, the registered agent IP and every `extra_ip` the node
    reported (`issue_node_cert`), and the gateway cert carries its
    hostname, `gateway`, `noo-controller`, `noo-gateway` and the
    instance-prefixed alias (`issue_gateway_cert`). A dial that fails
    hostname verification is naming a host the cert does not claim: the
    fix is another SAN at issuance (`noo security pki issue --san …`,
    then `noo security pki verify` for the drift check), never turning
    the check off for every caller.
    """
    ca = os.environ.get("NOO_TLS_CA", "")
    if ca and os.path.isfile(ca):
        import ssl
        ctx = ssl.create_default_context(cafile=ca)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx
    return True


def client_cert() -> tuple[str, str] | None:
    """Return (cert_path, key_path) for mTLS client authentication.

    Returns None if no client cert is configured.
    """
    cert = os.environ.get("NOO_TLS_CERT", "")
    key = os.environ.get("NOO_TLS_KEY", "")
    if cert and key and os.path.isfile(cert) and os.path.isfile(key):
        return (cert, key)
    return None


class Services:
    """Central service registry, populated during lifespan startup."""

    # Core
    conversation_store: Optional[Any] = None
    memory_system: Optional[Any] = None
    embedding_worker: Optional[Any] = None
    coordinator: Optional[Any] = None
    # Knowledge
    pageindex_rag: Optional[Any] = None
    recall_memory: Optional[Any] = None
    # Cluster
    backend_manager: Optional[Any] = None
    node_registry: Optional[Any] = None
    scheduler: Optional[Any] = None
    autonomy_engine: Optional[Any] = None
    # Scheduling & monitoring
    heartbeat_scheduler: Optional[Any] = None
    # Alerts (function ref + client set)
    broadcast_alert_fn: Optional[Any] = None
    connected_clients: Optional[Any] = None
    # Database
    db_dsn: Optional[str] = None
    # Channel manager
    channel_manager: Optional[Any] = None
    # Settings
    settings_store: Optional[Any] = None
    # Cloud
    cloud_manager: Optional[Any] = None
    # Proactive
    proactive_agent: Optional[Any] = None
    # Messaging (NATS connection — set by worker pool or gateway lifespan)
    messaging: Optional[Any] = None
    # Controller hostname
    controller_hostname: str = "localhost"
    # Gateway port
    gateway_port: str = "8080"

    # Deprecated name of `recall_memory`; removed with the
    # other old spellings in the release after 0.6.0.
    @property
    def video_memory(self) -> Optional[Any]:
        return self.recall_memory

    @video_memory.setter
    def video_memory(self, value: Optional[Any]) -> None:
        self.recall_memory = value


services = Services()


def _make_dep(attr: str, label: str | None = None):
    """Factory for FastAPI Depends() -- returns a callable that raises 503 if service is None."""
    label = label or attr.replace("_", " ").title()

    def dep():
        val = getattr(services, attr, None)
        if val is None:
            raise HTTPException(status_code=503, detail=f"{label} not initialized")
        return val

    dep.__name__ = f"require_{attr}"
    return dep


require_conversation_store = _make_dep("conversation_store")
require_scheduler = _make_dep("scheduler")
require_autonomy_engine = _make_dep("autonomy_engine")
require_heartbeat_scheduler = _make_dep("heartbeat_scheduler")
require_broadcast_alert = _make_dep("broadcast_alert_fn", "Alert system")
