# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Shared helper functions for gateway routers.

ℹ️ MIXED — Most helpers (``get_node_agent_url``; the node-agent client and
header helpers were deleted) were duplicated across deprecated Python routers
and are functionally dead in prod. ``get_backend_url`` is still imported
by ``agents/parallel_collab.py`` and a few MCP tools to assemble worker
URLs. Phase 2 will turn ``get_backend_url`` into a ``BackendResolver``
provider; the rest dies with the deprecated routers.

These were originally defined in ``app.py`` and duplicated across several
router modules.  Every module that needs them should import from here:

    from .helpers import (
        get_node_agent_url, get_backend_url, _default_url, _local_gateway_url,
    )
"""

from __future__ import annotations

import os

# The node-agent client and header helpers (``_get_node_client``,
# ``_close_node_client``, ``_node_agent_headers``) were deleted for followup
# 1264. Nothing called them, and ``_node_agent_headers`` sent the static
# NOO_NODE_AGENT_TOKEN. The gateway's node-agent calls are Rust
# (``node_agent_auth::header_for``), with the controller's leaf.

# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def _local_gateway_url() -> str:
    """Build the base URL for gateway self-calls (protocol-aware).

    ``NOO_GATEWAY_URL`` wins when set: the standalone worker container
    (noo-trellion, WP-T23) is NOT colocated with the gateway, so its
    compose env points this at ``https://gateway:8080``. Same knob the
    MCP tool proxy (mcp/tool_models.py) already honors — one existing
    declaration, no new fact.

    Otherwise https://127.0.0.1:<port>, unconditionally: the gateway has
    one listener, the TLS acceptor, and refuses to start without its
    material (gateway-rust/src/main.rs), so there is no plain form to
    fall back to. ``NOO_TLS_CERT`` used to pick the scheme here.
    """
    override = os.getenv("NOO_GATEWAY_URL", "").strip()
    if override:
        return override.rstrip("/")
    port = os.getenv("GATEWAY_PORT", "8080")
    return f"https://127.0.0.1:{port}"


def _default_url(service: str) -> str:
    """Return the default internal URL of a controller-local backend: https.

    Ollama, TEI and llama.cpp have no TLS listener of their own, so their
    doors are the stunnel sidecars (client certificate required, #538);
    vLLM serves HTTPS natively and requires a client certificate too. The
    plain ``http://noo-<svc>`` forms that ``NOO_TLS_CA`` used to select are
    gone: no such door is reachable and the gateway cannot run without the
    CA.
    """
    from .constants import BACKEND_PORTS
    _p = BACKEND_PORTS  # shorthand
    urls = {
        "ollama":   f"https://stunnel-ollama:{_p['ollama']}",
        "tei":      "https://stunnel-tei:443",
        "vllm":     f"https://noo-vllm:{_p['vllm']}",
        # llama-server has no TLS listener: the door is its stunnel sidecar
        # (client certificate required), same port.
        "llamacpp": f"https://noo-stunnel-llamacpp:{_p['llamacpp']}",
    }
    return urls.get(service, "")


def get_node_agent_url(node) -> str:
    """Get the URL to reach a node's agent (computed at registration time)."""
    if node.agent_url:
        return node.agent_url
    # :8081 is mTLS-only (the agent has no plaintext listener) — https always.
    return f"https://{node.ip_address}:8081"


def get_backend_url(node, backend: str, port: int) -> str:
    """Get the URL to reach a backend on a node.

    For local nodes, Docker-managed backends (vLLM, llamacpp, tei, embedding)
    are reached via their Docker service/container name on the shared
    ``noo-cluster`` network.  Host-native backends (Ollama) are reached via
    ``host.docker.internal`` so the gateway container can traverse the Docker
    bridge.  Remote nodes always use their IP address.

    Always https. vLLM serves TLS natively (client certificate required);
    the backends that cannot (Ollama, TEI, llama.cpp) are routed to their
    stunnel sidecar's name. The plain ``noo-<svc>`` forms that ``NOO_TLS_CA``
    used to select are gone with the gateway's plaintext listener:
    no such door answers, and the gateway cannot run
    without the CA.
    """
    # Docker service names, stunnel sidecars where the backend has no TLS
    _DOCKER_SERVICE_NAMES = {
        "vllm": "noo-vllm",
        "llamacpp": "noo-stunnel-llamacpp",
        "ollama": "stunnel-ollama",
        "embedding": "stunnel-tei",
        "tei": "stunnel-tei",
    }

    is_local = node.agent_url and "node-agent" in node.agent_url
    if is_local:
        service = _DOCKER_SERVICE_NAMES.get(backend)
        if service:
            # TEI stunnel listens on 443, not the backend's native port
            if backend in ("embedding", "tei"):
                return f"https://{service}:443"
            return f"https://{service}:{port}"
        # Unknown backend — fall back to host bridge
        return f"https://host.docker.internal:{port}"
    return f"https://{node.ip_address}:{port}"
