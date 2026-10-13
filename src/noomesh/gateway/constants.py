# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Shared gateway constants — single source of truth for values duplicated across modules."""

from ..backends import port_map as _backend_port_map

# Default ports for inference backends (used in URL construction and health
# checks). Derived from the BackendProfile registry (noomesh.backends) —
# add/override backends there, not here.
BACKEND_PORTS: dict[str, int] = _backend_port_map()

# Docker service name prefixes for backends
BACKEND_SERVICE_PREFIX = "noo"


def backend_url(backend_type: str, node_hostname: str | None = None, scheme: str | None = None) -> str:
    """Construct a backend URL from type and optional node hostname."""
    # https unless the caller says otherwise: every backend listener is
    # mTLS, and the gateway cannot run without the CA that used to gate this.
    if scheme is None:
        scheme = "https"
    port = BACKEND_PORTS.get(backend_type, 8000)
    host = node_hostname or f"{BACKEND_SERVICE_PREFIX}-{backend_type}"
    return f"{scheme}://{host}:{port}"
