# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Redis connection-URL helpers (TLS upgrade, mTLS kwargs, password inject).

Shared by every Python module that opens its own Redis connection
(gateway/heartbeat.py, gateway/worker_pool.py, cluster/scheduler.py).

NOTE (2026-08 zombie sweep): this module used to contain a full
``CacheManager`` class claiming to share LLM-response/session cache state
with the Rust gateway. That claim was false — nothing ever instantiated it,
and the Rust-owned ``noo:cache:*`` / ``noo:session:*`` namespaces were never
read or written from Python (the only genuinely shared Redis namespace is
the ``noo:cq:{consumer}`` quota bucket, now written by the Rust MCP doors).
LLM response
caching lives entirely in gateway-rust/src/cache.rs. The dead class was
deleted; only these URL helpers were ever live.
"""
from __future__ import annotations


def _apply_redis_tls(url: str) -> str:
    """Refuse a plaintext Redis URL; pass a TLS one through.

    The Redis service is TLS-only (``docker/redis-entrypoint.sh``:
    ``port 0`` / ``tls-port 6379``), so a ``redis://`` URL can never
    connect — it used to be upgraded to ``rediss://`` only when
    ``NOO_REDIS_TLS`` was set and otherwise sent as-is, which surfaced as a
    connection reset with nothing naming the cause. Fail loud instead, and
    say why. ``NOO_REDIS_TLS`` is no longer read.
    """
    if url.startswith("redis://"):
        raise ValueError(
            f"REDIS_URL {url!r} is plaintext (redis://), and the Redis service "
            "serves TLS only (port 0 / tls-port 6379) — use rediss://"
        )
    return url


def _redis_ssl_kwargs() -> dict:
    """SSL kwargs for redis.from_url(): the cluster CA and the client leaf.

    Always — there is no plaintext Redis to skip them for. A missing file
    is simply not passed (redis-py then verifies against the system store
    and presents no leaf, and the mTLS server refuses it loudly).
    """
    import os

    kwargs: dict = {}
    ca = os.getenv("NOO_TLS_CA", "")
    if ca and os.path.exists(ca):
        kwargs["ssl_ca_certs"] = ca
    # mTLS: present client cert to Redis
    cert = os.getenv("NOO_TLS_CERT", "")
    key = os.getenv("NOO_TLS_KEY", "")
    if cert and os.path.exists(cert) and key and os.path.exists(key):
        kwargs["ssl_certfile"] = cert
        kwargs["ssl_keyfile"] = key
    return kwargs


def _inject_redis_password(url: str) -> str:
    """Inject REDIS_PASSWORD into the URL if set and not already present."""
    from .secret_env import secret_or_empty

    password = secret_or_empty("REDIS_PASSWORD")
    if not password:
        return url
    # Already has credentials — don't overwrite
    if "://:@" in url or "://" not in url:
        return url
    parts = url.split("://", 1)
    if len(parts) != 2:
        return url
    scheme, rest = parts
    # Check if credentials already present (contains @ before first /)
    slash_pos = rest.find("/")
    host_part = rest[:slash_pos] if slash_pos != -1 else rest
    if "@" in host_part:
        return url
    return f"{scheme}://:{password}@{rest}"

