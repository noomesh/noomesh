# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Resolve the cluster CA a gateway-bound client must verify against.

There is no "verification off" and no silent "whatever the system store
holds": a client of the gateway talks to a leaf the cluster CA issued, so a
process that cannot find that CA is misconfigured and says so, naming the
setting (``NOO_TLS_CA``), instead of dialling unverified.

Resolution order (the same places the rest of the stack looks, and
``noo_gateway.settings.DEFAULT_CA_PATHS`` for the container paths):

1. ``NOO_TLS_CA`` -- must name an existing file. Set-but-missing is an
   error, never a fall-through to a lesser source.
2. ``/tls/ca.crt``, ``/app/pki/ca.crt`` (container mounts).
3. ``$NOO_PKI_DIR/ca.crt`` or ``~/.config/mesh/pki/ca.crt`` (host install,
   the directory ``noo security pki`` writes).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

CONTAINER_CA_PATHS: tuple[str, ...] = ("/tls/ca.crt", "/app/pki/ca.crt")


class TlsCaMissing(RuntimeError):
    """No cluster CA could be found. The message names the setting."""


def resolve_ca(env: Mapping[str, str] | None = None) -> str | None:
    """The CA file path, or None when none exists. Raises if ``NOO_TLS_CA`` is set but not a file."""
    env = os.environ if env is None else env
    explicit = (env.get("NOO_TLS_CA") or "").strip()
    if explicit:
        if not os.path.isfile(explicit):
            raise TlsCaMissing(f"NOO_TLS_CA={explicit!r} is not a file; point it at the cluster CA certificate (ca.crt)")
        return explicit
    pki_dir = (env.get("NOO_PKI_DIR") or "").strip() or os.path.expanduser("~/.config/mesh/pki")
    for p in (*CONTAINER_CA_PATHS, str(Path(pki_dir) / "ca.crt")):
        if os.path.isfile(p):
            return p
    return None


def require_ca(env: Mapping[str, str] | None = None) -> str:
    """The CA file path, or :class:`TlsCaMissing` naming ``NOO_TLS_CA``."""
    ca = resolve_ca(env)
    if ca is None:
        raise TlsCaMissing(
            "no cluster CA found: set NOO_TLS_CA to the path of the cluster CA certificate (ca.crt). "
            "Looked in " + ", ".join((*CONTAINER_CA_PATHS, "$NOO_PKI_DIR/ca.crt")) + ". "
            "TLS verification cannot be turned off."
        )
    return ca
