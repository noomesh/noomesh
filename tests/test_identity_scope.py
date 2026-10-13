# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""``identity.scope.resolve_scope_user`` — resolve, then fail closed.

This is the code that replaced the ``NOO_MULTI_USER`` flag. The flag's
default said "no user_id ⇒ global scope", which is how an unattributed
memory search could return every user's entries. These tests pin the three
answers that replaced it, plus the one thing resolution must never do:
override an identity the caller already supplied.
"""
from __future__ import annotations

import asyncio

import pytest

from src.noomesh.identity import scope


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return self._rows


class _Conn:
    def __init__(self, rows, sql_seen):
        self._rows = rows
        self._sql_seen = sql_seen

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, stmt, params=None):
        self._sql_seen.append(str(stmt))
        return _Result(self._rows)


class _Engine:
    def __init__(self, rows, sql_seen):
        self._rows = rows
        self._sql_seen = sql_seen

    def connect(self):
        return _Conn(self._rows, self._sql_seen)


class _Store:
    def __init__(self, rows, sql_seen):
        self._engine = _Engine(rows, sql_seen)


@pytest.fixture(autouse=True)
def _clean_cache():
    scope.reset_scope_cache()
    yield
    scope.reset_scope_cache()


def _with_accounts(monkeypatch, usernames):
    """Point the resolver's DB lookup at a fake account table."""
    sql_seen: list[str] = []
    store = _Store([(u,) for u in usernames], sql_seen)
    import src.noomesh.workers.common as common

    monkeypatch.setattr(common, "_get_conversation_store", lambda: store)
    return sql_seen


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_one_account_resolves_to_that_account(monkeypatch):
    sql = _with_accounts(monkeypatch, ["solo"])
    assert _run(scope.resolve_scope_user(None)) == "solo"
    # LIMIT 2 answers "exactly one?" without counting the whole table, and
    # disabled accounts are not tenants.
    assert "noo_users" in sql[0] and "LIMIT 2" in sql[0]
    assert "disabled = false" in sql[0]


def test_zero_accounts_fails_closed(monkeypatch):
    _with_accounts(monkeypatch, [])
    assert _run(scope.resolve_scope_user(None)) is None


def test_two_accounts_fail_closed(monkeypatch):
    _with_accounts(monkeypatch, ["alice", "bob"])
    assert _run(scope.resolve_scope_user(None)) is None


def test_explicit_user_id_is_never_overridden(monkeypatch):
    # Even where a sole account exists, the caller's identity wins — and the
    # DB is not consulted at all.
    sql = _with_accounts(monkeypatch, ["solo"])
    assert _run(scope.resolve_scope_user("alice")) == "alice"
    assert sql == []


def test_no_store_fails_closed_and_is_not_cached(monkeypatch):
    import src.noomesh.workers.common as common

    monkeypatch.setattr(common, "_get_conversation_store", lambda: None)
    assert _run(scope.resolve_scope_user(None)) is None
    # The store is wired up asynchronously at worker start; "not ready yet"
    # must not stick for the TTL.
    sql = _with_accounts(monkeypatch, ["solo"])
    assert _run(scope.resolve_scope_user(None)) == "solo"
    assert sql


def test_lookup_failure_fails_closed_and_is_not_cached(monkeypatch):
    class _Boom:
        @property
        def _engine(self):
            raise RuntimeError("db down")

    import src.noomesh.workers.common as common

    monkeypatch.setattr(common, "_get_conversation_store", lambda: _Boom())
    assert _run(scope.resolve_scope_user(None)) is None
    _with_accounts(monkeypatch, ["solo"])
    assert _run(scope.resolve_scope_user(None)) == "solo"


def test_answer_is_cached_within_the_ttl(monkeypatch):
    sql = _with_accounts(monkeypatch, ["solo"])
    assert _run(scope.resolve_scope_user(None)) == "solo"
    assert _run(scope.resolve_scope_user(None)) == "solo"
    assert len(sql) == 1, "resolution runs per prompt — it must not re-query each time"


def test_cache_expires_so_a_second_account_stops_resolving(monkeypatch):
    """The TTL is the whole reason the cache is safe.

    An install that gains a second account must stop resolving unattributed
    reads to the first one — without a restart. A permanently cached answer
    would keep serving user one's data to whoever asks next.
    """
    now = [1000.0]
    monkeypatch.setattr(scope.time, "monotonic", lambda: now[0])

    _with_accounts(monkeypatch, ["solo"])
    assert _run(scope.resolve_scope_user(None)) == "solo"

    # A second account appears. Still inside the TTL: the stale answer stands.
    _with_accounts(monkeypatch, ["solo", "newcomer"])
    assert _run(scope.resolve_scope_user(None)) == "solo"

    # Past the TTL: re-queried, ambiguous, fail closed.
    now[0] += scope._SOLE_ACCOUNT_TTL_SECONDS + 1
    assert _run(scope.resolve_scope_user(None)) is None
