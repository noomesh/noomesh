# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The ``NOO_MULTI_USER`` gate — the ONLY reader of that flag.

It used to be described as the Python peer of a Rust
``crate::auth::multi_user_enabled()``. That accessor had no caller and was
deleted; the pairing was never real, and calling this one half of a pair
invited the assumption that the gateway enforces tenancy too. It does not —
the gateway's scoping (``auth::scoped_user``) is unconditional, and this gate
is what actually decides whether a worker serves an unattributed read.

Single source of truth for whether this deployment runs in multi-tenant
mode. Off (default) = single-user: a missing resolved identity falls back
to the shared/global scope (today's terminal/CLI/heartbeat behaviour). On =
multi-tenant: data reads fail **closed** when no ``user_id`` is present so one
tenant can never be served another's memory/KB.

Read once and cached — the flag is a deploy-time setting, not hot-reloaded.
``noomesh.posture`` clears this cache after applying the DB posture at
worker startup, which is the one point the value may legitimately change.
"""
from __future__ import annotations

import functools
import os

_TRUTHY = {"1", "true", "yes", "on"}


@functools.lru_cache(maxsize=1)
def multi_user_enabled() -> bool:
    """True when ``NOO_MULTI_USER`` is set to a truthy value (1/true/yes/on)."""
    return os.getenv("NOO_MULTI_USER", "").strip().lower() in _TRUTHY
