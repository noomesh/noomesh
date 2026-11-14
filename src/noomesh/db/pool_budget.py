# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every Postgres pool noomesh's Python code opens, and how big it may get (i815).

The pools that open in production are fixed in code, not scaled by cores
(``noomesh.db.engine.init_db`` is never called by a running service). Their
ceilings (``pool_size + max_overflow``) add up per process, and the processes
add up against Postgres ``max_connections``. Until 2026-11 nobody had added
them: a default install could ask for ~109 connections of the 97 usable.

So each pool's size lives HERE, beside the peak it was measured at, and every
engine noomesh builds takes its size from ``POOL_BUDGET`` through
``budgeted_engine`` / ``budgeted_async_engine``. ``tests/test_pg_pool_budget.py``
fails when a production ``create_engine`` call sizes itself, and when the sum
of every process's ceilings crosses ``max_connections`` minus the reserved
slots and headroom.

Measured (i815, rc.1, one user, 4-core hosted runner, noomesh#1209 matrix
run 43646919386): peak 18 connections in all — trellion 9, gateway 7,
worker 2. The per-pool peaks below are that run's per-process numbers; no
pool came near its ceiling.

A smaller pool trades an outage (``too many clients``) for waiting under
load. The wait is made visible: a checkout that waits longer than
``SLOW_CHECKOUT_SECONDS`` logs ``db.pool_checkout_slow`` at WARN, naming the
pool and its ceiling, and is counted in ``slow_checkout_counts()`` (the
connections gauge reads it; Python exports no Prometheus registry today).
"""

from __future__ import annotations

import threading
import time
from collections import Counter
from typing import Any, Dict, Tuple

# name -> (pool_size, max_overflow). Ceiling = the sum.
POOL_BUDGET: Dict[str, Tuple[int, int]] = {
    # Security-audit DB sink, app role, one row per event. In noo-worker AND
    # noo-trellion. Measured peak: 1 (worker's 2 total = audit + heartbeat).
    # Unchanged: 2 + 2.
    "worker.audit": (2, 2),
    # HeartbeatStore (sync), heartbeat task CRUD + run records. In noo-worker
    # AND noo-trellion. Measured peak: 1. Was 5 + 10 (SQLAlchemy default).
    "heartbeat_store": (5, 5),
    # trellion ConversationStore, built here and handed to trellion as its
    # engine. noo-trellion only (ml pack). Measured peak: within trellion's 9.
    # Was 5 + 10 (SQLAlchemy default, trellion-built from the DSN).
    "conversation_store": (5, 3),
    # trellion PageIndexStore. noo-trellion only. NOT YET APPLIED: trellion's
    # PageIndexRAG.startup builds the store from the DSN itself, so noomesh
    # cannot hand it an engine; the trellion PR reads this size. Today it is
    # still 5 + 10. Measured peak: within trellion's 9.
    "pageindex_store": (5, 3),
    # noomesh.db.engine.init_db: no production caller (tests and legacy
    # FastAPI lifespan only), so it is in no process's sum. Was
    # max(10, 2 x cores) + 20; fixed now so nothing here scales with cores.
    "db.init_db": (10, 20),
}

# Which noomesh-built pools open in which process. pageindex_store is listed
# under trellion's own pools (tests/test_pg_pool_budget.py) until the trellion
# PR makes it noomesh-sized.
PROCESS_POOLS: Dict[str, Tuple[str, ...]] = {
    "noo-worker": ("worker.audit", "heartbeat_store"),
    "noo-trellion": ("worker.audit", "heartbeat_store", "conversation_store"),
}

# A checkout waiting longer than this is logged and counted.
SLOW_CHECKOUT_SECONDS = 2.0
# At most one WARN per pool per this many seconds; the count keeps them all.
_WARN_EVERY_SECONDS = 10.0

_lock = threading.Lock()
_slow: Counter = Counter()
_timeouts: Counter = Counter()
_last_warn: Dict[str, float] = {}
_unwarned: Counter = Counter()


def ceiling(name: str) -> int:
    size, overflow = POOL_BUDGET[name]
    return size + overflow


def process_ceiling(process: str) -> int:
    return sum(ceiling(n) for n in PROCESS_POOLS[process])


def slow_checkout_counts() -> Dict[str, Dict[str, int]]:
    """``{pool: {"slow": n, "timeouts": n}}`` since process start."""
    with _lock:
        names = set(_slow) | set(_timeouts)
        return {n: {"slow": _slow[n], "timeouts": _timeouts[n]} for n in sorted(names)}


def _record_wait(name: str, ceiling_: int, waited: float, timed_out: bool) -> None:
    now = time.monotonic()
    with _lock:
        _slow[name] += 1
        if timed_out:
            _timeouts[name] += 1
        last = _last_warn.get(name)
        if last is not None and now - last < _WARN_EVERY_SECONDS and not timed_out:
            _unwarned[name] += 1
            return
        _last_warn[name] = now
        folded = _unwarned.pop(name, 0)
    try:
        import structlog

        structlog.get_logger(__name__).warning(
            "db.pool_checkout_slow",
            pool=name,
            ceiling=ceiling_,
            waited_s=round(waited, 3),
            timed_out=timed_out,
            slow_since_last_warn=folded,
        )
    except Exception:  # logging must never fail a checkout
        pass


class _WaitTimed:
    """Mixin over a SQLAlchemy QueuePool: time ``_do_get``.

    ``_do_get`` is where a checkout blocks — on the pool's queue when every
    connection is out and the overflow is spent, until one comes back or
    ``pool_timeout`` passes — and where a new connection is opened while the
    pool is still growing. Pool events cannot see this: ``checkout`` fires
    only after a connection has been handed over. So the measured wait is
    queue wait plus, for a growing pool, the connect itself (milliseconds on
    a healthy server; a slow connect is worth the same warning).
    """

    _noo_pool_name = "?"
    _noo_ceiling = 0

    def _do_get(self):  # type: ignore[override]
        t0 = time.monotonic()
        timed_out = False
        try:
            return super()._do_get()  # type: ignore[misc]
        except Exception as exc:
            from sqlalchemy.exc import TimeoutError as _PoolTimeout

            timed_out = isinstance(exc, _PoolTimeout)
            raise
        finally:
            waited = time.monotonic() - t0
            if waited >= SLOW_CHECKOUT_SECONDS:
                _record_wait(self._noo_pool_name, self._noo_ceiling, waited, timed_out)


def _poolclass(name: str, base: type) -> type:
    # A subclass per pool, not an attribute on the instance: dispose()
    # rebuilds the pool from its class, and the name must survive that.
    return type(
        f"Budgeted{base.__name__}",
        (_WaitTimed, base),
        {"_noo_pool_name": name, "_noo_ceiling": ceiling(name)},
    )


def _sized(name: str, kw: Dict[str, Any]) -> Dict[str, Any]:
    for k in ("pool_size", "max_overflow", "poolclass"):
        if k in kw:
            raise TypeError(f"{k} for pool {name!r} comes from POOL_BUDGET, not the caller")
    size, overflow = POOL_BUDGET[name]
    out = dict(kw)
    out["pool_size"] = size
    out["max_overflow"] = overflow
    return out


def budgeted_engine(name: str, url: Any, **kw: Any):
    """A sync Engine sized by ``POOL_BUDGET[name]``, with checkout waits timed."""
    from sqlalchemy import create_engine
    from sqlalchemy.pool import QueuePool

    args = _sized(name, kw)
    args["poolclass"] = _poolclass(name, QueuePool)
    return create_engine(url, **args)


def budgeted_async_engine(name: str, url: Any, **kw: Any):
    """An AsyncEngine sized by ``POOL_BUDGET[name]``, with checkout waits timed."""
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import AsyncAdaptedQueuePool

    args = _sized(name, kw)
    args["poolclass"] = _poolclass(name, AsyncAdaptedQueuePool)
    return create_async_engine(url, **args)
