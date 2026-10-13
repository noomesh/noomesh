# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 PersonifAI LLC

"""Where the gateway is, which credential the add-on holds, and how TLS is verified.

Read ONCE from the environment by `GatewaySettings.from_env` and then frozen:
a client that re-reads `os.environ` per request is a client whose behaviour a
test cannot pin.

TLS is verified against the cluster CA when the container has one, else the
system trust store — ALWAYS, hostname included. There is no switch: the
`NOO_GATEWAY_TLS_VERIFY=0` and `NOO_GATEWAY_TLS_CHECK_HOSTNAME=0` toggles and
the `NOO_GATEWAY_SHARED_SECRET_FALLBACK` ladder rung were retired unused, and
`from_env` REFUSES (raises `ValueError` naming the variable) when one is still
set to its old off value, rather than silently verifying anyway.
"""

from __future__ import annotations

import hashlib
import logging
import os
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any

import httpx

log = logging.getLogger("noo_gateway")

DEFAULT_URL = "https://gateway:8080"
#: CA files a stack container has when the operator did not set `NOO_TLS_CA`:
#: the cluster CA mounted at `/tls` (compose) or the PKI tree at `/app/pki`.
DEFAULT_CA_PATHS: tuple[str, ...] = ("/tls/ca.crt", "/app/pki/ca.crt")
#: Route prefixes on which the gateway accepts an add-on's RAW key as the
#: bearer. Everywhere else only an exchanged token opens
#: a route (`auth.rs`, `is_inference_surface`). The monorepo's
#: tests/test_gateway_client_contract.py holds this to the gateway.
INFERENCE_SURFACE_PREFIXES: tuple[str, ...] = ("/v1/", "/api/external/")
#: The exchange door (`auth::ADDON_TOKEN_PATH`).
ADDON_TOKEN_PATH = "/api/addon/token"
#: The add-on metrics doors (`auth::CONTROL_SCOPE_ROUTES`, scope `metrics`).
METRICS_INCREMENT_PATH = "/api/metrics/increment"
METRICS_GAUGE_PATH = "/api/metrics/gauge"

_FALSE = frozenset({"0", "false", "no", "off"})

#: Retired toggles, each with what replaced it. Set to an OFF value they are a
#: refusal: an add-on that believes it turned verification off (or kept a
#: shared-secret fallback) must hear that it did not.
RETIRED_ENV: dict[str, str] = {
    "NOO_GATEWAY_TLS_VERIFY": "TLS verification is always on (cluster CA, else the system store)",
    "NOO_GATEWAY_TLS_CHECK_HOSTNAME": "hostname verification is always on",
    "NOO_GATEWAY_SHARED_SECRET_FALLBACK": (
        "the client has no shared-secret lane; it authenticates only with the add-on's own key"
    ),
}


def retired_env_refusal(env: Mapping[str, str]) -> str | None:
    """A message naming every retired toggle still set OFF in `env`, else None."""
    found = [
        f"{name}={env[name].strip()} ({now})"
        for name, now in RETIRED_ENV.items()
        if (_clean(env.get(name)) or "").lower() in _FALSE
    ]
    if not found:
        return None
    return (
        "retired noo_gateway toggle(s) still set — remove them from this add-on's "
        "environment: " + "; ".join(found)
    )


def is_inference_surface(path: str) -> bool:
    return path.startswith(INFERENCE_SURFACE_PREFIXES)


def _clean(value: str | None) -> str | None:
    """A stripped, non-empty string, else None: a blank env var is absent."""
    if value is None:
        return None
    value = value.strip()
    return value or None


def resolve_verify(
    env: Mapping[str, str],
    *,
    consumer: str,
    default_ca_paths: tuple[str, ...] = DEFAULT_CA_PATHS,
) -> ssl.SSLContext | bool:
    """What `httpx.Client(verify=...)` gets: never `False`.

    - `NOO_TLS_CA=<file>` (else the first of `default_ca_paths` that exists):
      a context trusting that CA, hostname checked.
    - otherwise `True`: the system trust store.
    """
    del consumer  # kept in the signature for callers; nothing to log any more
    ca = _clean(env.get("NOO_TLS_CA"))
    if ca is None:
        ca = next((p for p in default_ca_paths if os.path.isfile(p)), None)
    if ca is None:
        return True
    return ssl.create_default_context(cafile=ca)


def resolve_cert(env: Mapping[str, str]) -> tuple[str, str] | None:
    """The mTLS client cert, only when BOTH files exist."""
    cert = _clean(env.get("NOO_TLS_CERT"))
    key = _clean(env.get("NOO_TLS_KEY"))
    if cert and key and os.path.isfile(cert) and os.path.isfile(key):
        return (cert, key)
    return None


@dataclass(frozen=True)
class GatewaySettings:
    """Everything a `GatewayAuth` or a client needs. Frozen; build with `from_env`."""

    #: Who this process is, for logs and for the `consumer` claim the exchange
    #: confirms: `svc:trellion`, `svc:evolve`, …
    consumer: str
    #: Base URL, no trailing slash.
    url: str = DEFAULT_URL
    #: The add-on's own service key (`NOO_GATEWAY_KEY`). None = absent.
    key: str | None = None
    #: `httpx` `verify`. `True` (system store), a CA path, or an `SSLContext`.
    #: Never `False` — `__post_init__` refuses it.
    verify: ssl.SSLContext | str | bool = True
    #: `httpx` `cert`: `(cert_path, key_path)` for mTLS, else None.
    cert: tuple[str, str] | None = None
    #: Default timeout for the pre-wired clients, seconds.
    timeout: float = 30.0
    #: Timeout for the exchange itself, seconds.
    exchange_timeout: float = 10.0
    #: Test seam: an `httpx.MockTransport` here is used by the internal
    #: exchange clients AND the pre-wired clients, so a test drives the real
    #: `httpx.Client`/`AsyncClient` code paths. Never patch `httpx.post`.
    transport: httpx.BaseTransport | httpx.AsyncBaseTransport | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "url", self.url.rstrip("/"))
        object.__setattr__(self, "key", _clean(self.key))
        if not self.consumer:
            raise ValueError("GatewaySettings needs a consumer name (e.g. 'svc:evolve')")
        if self.verify is False:
            raise ValueError("GatewaySettings.verify=False: TLS verification cannot be turned off")

    @classmethod
    def from_env(
        cls,
        consumer: str,
        *,
        env: Mapping[str, str] | None = None,
        **overrides: Any,
    ) -> GatewaySettings:
        """Build from the environment (`os.environ` unless `env` is given).

        Variables: `NOO_GATEWAY_URL`, `NOO_GATEWAY_KEY`, `NOO_TLS_CA`,
        `NOO_TLS_CERT` + `NOO_TLS_KEY`. No shared secret is ever read: the
        client authenticates only with the add-on's own key. `overrides`
        win over all of them, which is how an add-on maps its own aliases
        (evolve's `NOO_EVOLVE_GATEWAY_URL`). Raises `ValueError` when a
        retired toggle (`RETIRED_ENV`) is still set off.
        """
        e: Mapping[str, str] = os.environ if env is None else env
        refusal = retired_env_refusal(e)
        if refusal:
            log.error("gateway_settings_refused consumer=%s: %s", consumer, refusal,
                      extra={"event": "gateway_settings_refused", "consumer": consumer})
            raise ValueError(refusal)
        values: dict[str, Any] = {
            "consumer": consumer,
            "url": _clean(e.get("NOO_GATEWAY_URL")) or DEFAULT_URL,
            "key": _clean(e.get("NOO_GATEWAY_KEY")),
            "verify": resolve_verify(e, consumer=consumer),
            "cert": resolve_cert(e),
        }
        values.update(overrides)
        return cls(**values)

    def with_(self, **changes: Any) -> GatewaySettings:
        """A copy with `changes` applied (a frozen dataclass has no setters)."""
        return replace(self, **changes)

    @property
    def key_fingerprint(self) -> str | None:
        """A short, non-reversible id of the key: what token state is keyed
        on, and the only form of the key that may ever appear in a log."""
        if not self.key:
            return None
        return hashlib.sha256(self.key.encode()).hexdigest()[:16]

    def describe(self) -> dict[str, Any]:
        """The settings without any secret, for a startup log line."""
        return {
            "consumer": self.consumer,
            "url": self.url,
            "key": "set" if self.key else "absent",
            "verify": "system" if self.verify is True else "ca",
            "cert": bool(self.cert),
        }
