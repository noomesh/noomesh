# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Centralized database layer for noomesh.

Single source of truth for PostgreSQL schema (SQLAlchemy models) and
versioned migrations (Alembic).  Replaces scattered ``_ensure_schema()``
methods across 7+ store modules with one ``init_db()`` call.

Usage in gateway lifespan::

    from noomesh.db import init_db, get_engine, get_async_engine, close_engines

    await init_db(dsn)                     # creates engines, runs Alembic upgrade
    engine = get_engine()                  # sync Engine for store constructors
    async_engine = get_async_engine()      # AsyncEngine for async stores
    ...
    await close_engines()                  # shutdown
"""

from __future__ import annotations

from importlib.util import find_spec
from typing import Any

# Availability probe without importing — sqlalchemy+alembic cost ~250ms and
# importers pay for it on every import, so it is a probe, not an import.
DB_AVAILABLE = (
    find_spec("sqlalchemy") is not None and find_spec("alembic") is not None
)

_LAZY_EXPORTS = {
    "close_engines": ("engine", "close_engines"),
    "get_async_engine": ("engine", "get_async_engine"),
    "get_engine": ("engine", "get_engine"),
    "init_db": ("engine", "init_db"),
    "Base": ("models", "Base"),
}

if DB_AVAILABLE:
    __all__ = ["DB_AVAILABLE", *_LAZY_EXPORTS]
else:
    __all__ = ["DB_AVAILABLE"]


def __getattr__(name: str) -> Any:
    if not DB_AVAILABLE or name not in _LAZY_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    submodule, attr = _LAZY_EXPORTS[name]
    value = getattr(import_module(f".{submodule}", __name__), attr)
    globals()[name] = value
    return value
