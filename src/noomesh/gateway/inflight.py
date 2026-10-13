# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""In-flight work counter shared by the worker pool and its co-resident loops.

Exists for exactly one consumer: the RSS self-watchdog in ``worker_pool``.
On 2026-08-08 the watchdog's unconditional ``os._exit(0)`` met a working set
that sat just under the ceiling, and the container entered a permanent
~8-minute exit/respawn loop — 82 restarts, every ``structured_research``
heartbeat task killed mid-flight with no run record. The watchdog now defers
its exit while work is in flight (bounded — see ``_rss_watchdog``), which
requires knowing whether work IS in flight.

A separate module rather than a ``worker_pool`` attribute because
``heartbeat`` also increments it and ``worker_pool`` imports ``heartbeat``'s
machinery — the counter must not create an import cycle.

Single-threaded asyncio: a bare int is safe, no lock.
"""

from contextlib import contextmanager

_count = 0


def count() -> int:
    """Number of currently executing units of work (NATS handler bodies
    and heartbeat task executions)."""
    return _count


@contextmanager
def tracked():
    """Wrap one unit of work. Exception-safe; never suppresses."""
    global _count
    _count += 1
    try:
        yield
    finally:
        _count -= 1
