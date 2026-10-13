# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Scrubbing what is about to be LOGGED.

The Rust gateway has `redact.rs`; this is the Python side's counterpart
for the one shape the cluster client logs on every connect: a service URL.
`NATS_URL` (and `REDIS_URL`) accept `scheme://user:password@host:port`, and
`cluster/messaging.py` wrote the URL raw into six log events (connected,
timeout, error, disconnected, closed, reconnected) — so an operator who put
the password in the URL had it in the journal at every reconnect
(2026-09-29). Structural, mirroring `redact::scrub_url_userinfo`: the
authority is cut at its LAST `@`; a URL with no userinfo, or no scheme,
comes back unchanged so a bare `host:port` stays readable.
"""

from __future__ import annotations


def scrub_url_userinfo(url: str) -> str:
    """`rediss://:hunter2@redis:6379/0` -> `rediss://redis:6379/0`."""
    if not isinstance(url, str):
        return url
    scheme_end = url.find("://")
    if scheme_end < 0:
        return url
    auth_start = scheme_end + 3
    rest = url[auth_start:]
    auth_len = len(rest)
    for stop in ("/", "?", "#"):
        i = rest.find(stop)
        if i >= 0 and i < auth_len:
            auth_len = i
    authority = rest[:auth_len]
    at = authority.rfind("@")
    if at < 0:
        return url
    return url[:auth_start] + authority[at + 1 :] + rest[auth_len:]
