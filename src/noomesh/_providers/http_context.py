# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""HTTP context provider — TLS verify + client cert for HTTP clients.

Replaces the 20-site pattern of:
    from noomesh.gateway.deps import ssl_verify, client_cert
    httpx.AsyncClient(verify=ssl_verify, cert=client_cert)

With:
    def __init__(self, ..., http_context: HttpContextProvider | None = None):
        self.http = http_context or default_http_context()
    ...
    httpx.AsyncClient(verify=self.http.verify, cert=self.http.cert)

Why: the inline ``from ..gateway.deps import ...`` is the largest single
MESH→HARNESS coupling. Making it injectable
lets HARNESS consumers be tested without the gateway loaded, lets a
non-PAI harness supply its own TLS context, and decouples the harness
from the gateway lifespan order.

Per the Phase 2 rule ("parameterize, don't move"), this is a
backwards-compatible change: existing call sites keep working via
``default_http_context()``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Protocol, Tuple, Union, runtime_checkable


# httpx accepts:
#   verify: bool | str | ssl.SSLContext
#   cert: str | (str, str) | (str, str, str)
HttpVerify = Union[bool, str, Any]  # `Any` covers ssl.SSLContext without importing ssl
HttpCert = Optional[Union[str, Tuple[str, str], Tuple[str, str, str]]]


@runtime_checkable
class HttpContextProvider(Protocol):
    """Provides TLS configuration for harness HTTP clients.

    Consumers accept this as a ctor arg instead of importing
    ``gateway.deps.ssl_verify``/``client_cert`` directly.
    """

    @property
    def verify(self) -> HttpVerify:
        """Value for ``httpx.AsyncClient(verify=...)``."""
        ...

    @property
    def cert(self) -> HttpCert:
        """Value for ``httpx.AsyncClient(cert=...)``."""
        ...


@dataclass(frozen=True)
class StaticHttpContext:
    """Concrete provider with explicit verify+cert values. Useful for tests
    and for harness lifespans that resolve TLS config at startup."""
    _verify: HttpVerify = True
    _cert: HttpCert = None

    @property
    def verify(self) -> HttpVerify:
        return self._verify

    @property
    def cert(self) -> HttpCert:
        return self._cert


class GatewayHttpContext:
    """Provider that re-resolves verify/cert from ``gateway.deps`` on each
    access. Preserves the dynamic behavior of the original module-level
    ``ssl_verify()`` / ``client_cert()`` callables (they read env vars on
    each call), so feature flags + cert rotation continue to work without
    forcing consumers to re-construct."""

    @property
    def verify(self) -> HttpVerify:
        try:
            from ..gateway.deps import ssl_verify  # type: ignore[attr-defined]
            return ssl_verify()
        except Exception:
            return True

    @property
    def cert(self) -> HttpCert:
        try:
            from ..gateway.deps import client_cert  # type: ignore[attr-defined]
            return client_cert()
        except Exception:
            return None


def default_http_context() -> HttpContextProvider:
    """Back-compat bridge: returns a provider that delegates to the
    existing ``gateway.deps`` callables on each access. Keeps consumer
    migration non-breaking — once HARNESS supplies its own provider via
    ctor injection, this default isn't used.
    """
    return GatewayHttpContext()
