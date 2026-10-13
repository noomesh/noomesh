# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Backend resolver provider — backend URL construction.

Replaces direct imports of:
    from noomesh.gateway.constants import BACKEND_PORTS
    from noomesh.gateway.helpers import get_backend_url

Consumers:
    - agents/parallel_collab.py — node + backend → URL

Why: backend URL construction is MESH knowledge (how the cluster lays
out backends). When HARNESS becomes its own repo it shouldn't need to
know the URL scheme — it asks via this provider.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Protocol, runtime_checkable


# Baseline port map if the gateway constants module isn't importable —
# same source of truth: the BackendProfile registry (noomesh.backends).
def _default_ports() -> Dict[str, int]:
    from ..backends import port_map
    return port_map()


@runtime_checkable
class BackendResolver(Protocol):
    """Provider for resolving cluster backend URLs."""

    def port_for(self, backend_type: str) -> Optional[int]:
        """Return the conventional port for a backend type, or None."""
        ...

    def url_for(self, node: Any, backend_type: str, port: int) -> str:
        """Construct the URL for ``backend_type`` running on ``node`` at
        ``port``. Falls back to ``http://{node.ip_address}:{port}`` if
        the underlying helper isn't available."""
        ...


class GatewayBackendResolver:
    """Default impl that delegates to ``gateway.constants`` + ``helpers``."""

    def port_for(self, backend_type: str) -> Optional[int]:
        try:
            from ..gateway.constants import BACKEND_PORTS
            return BACKEND_PORTS.get(backend_type)
        except Exception:
            return _default_ports().get(backend_type)

    def url_for(self, node: Any, backend_type: str, port: int) -> str:
        try:
            from ..gateway.helpers import get_backend_url
            return get_backend_url(node, backend_type, port)
        except Exception:
            # Every backend listener is mTLS (#538): the last-resort shape
            # is https too, never a plain URL nothing on the mesh answers.
            ip = getattr(node, "ip_address", "localhost")
            return f"https://{ip}:{port}"


def default_backend_resolver() -> BackendResolver:
    return GatewayBackendResolver()
