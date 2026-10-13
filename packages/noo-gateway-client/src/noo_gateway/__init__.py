# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PersonifAI LLC

"""noo_gateway — the one client an add-on uses to talk to the noomesh gateway.

    from noo_gateway import GatewaySettings, AsyncGatewayClient, Counters

    settings = GatewaySettings.from_env(consumer="svc:evolve")
    async with AsyncGatewayClient(settings) as gw:
        await gw.post_json("/api/temporal/adaptations", body)

    counters = Counters(settings)
    counters.inc("rollbacks_total", 1, engine="tuner")
    counters.gauge("backlog", 12)

Or, for a client you build yourself (an OpenAI SDK's `http_client`):

    httpx.AsyncClient(auth=GatewayAuth(settings), verify=settings.verify, cert=settings.cert)

Nothing here returns an `Authorization` header: `GatewayAuth` is the only
interface, which is what lets an add-on's tests hold "no call site builds a
header by hand". Authenticates only with the add-on's own key
(`NOO_GATEWAY_KEY`); there is no shared-secret lane. Depends on httpx and
nothing else; Apache-2.0-licensed on its own so the proprietary add-ons may import it whatever the core's licence.
"""

from __future__ import annotations

from .auth import GatewayAuth
from .client import AsyncGatewayClient, GatewayClient, raise_for_gateway
from .errors import (
    GatewayAuthUnavailable,
    GatewayError,
    GatewayRefused,
    GatewayResponseError,
    GatewayThrottled,
)
from .metrics import Counters
from .settings import (
    ADDON_TOKEN_PATH,
    INFERENCE_SURFACE_PREFIXES,
    METRICS_GAUGE_PATH,
    METRICS_INCREMENT_PATH,
    GatewaySettings,
    is_inference_surface,
)

__version__ = "0.1.0"

__all__ = [
    "ADDON_TOKEN_PATH",
    "INFERENCE_SURFACE_PREFIXES",
    "METRICS_GAUGE_PATH",
    "METRICS_INCREMENT_PATH",
    "AsyncGatewayClient",
    "Counters",
    "GatewayAuth",
    "GatewayAuthUnavailable",
    "GatewayClient",
    "GatewayError",
    "GatewayRefused",
    "GatewayResponseError",
    "GatewaySettings",
    "GatewayThrottled",
    "is_inference_surface",
    "raise_for_gateway",
]
