# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every Postgres pool's ceiling, summed against max_connections (i815).

The pools that open in production are fixed in code. Nobody had added them
until 2026-11, and a default install's ceilings (~109) were above Postgres's
stock 100 (97 usable). This file is the addition, and it fails when anyone
raises a pool or lowers max_connections past the line:

  line = max_connections (the compose default) - superuser_reserved (3)
         - HEADROOM (psql, an alembic NullPool run, a stray client)

noomesh's numbers are read from source: POOL_BUDGET for the Python pools,
GATEWAY_PG_MAX_CONNECTIONS in gateway-rust/src/state.rs for the gateway. The
siblings' numbers are pinned below with the sha they were read at. While a
sibling has not yet declared its own budget (``expects_declaration`` False),
the forward sums count its approved budget and a separate test checks the
install as it is TODAY. A sibling that declares ships a ``POOL_CEILINGS``
literal in its own pool_budget.py; the table pins a copy at the sibling's
sha, the flag is on, and the declared figure is what counts and must fit.
The copy is re-read with ``git show <sha>:<path>`` from a sibling checkout
when one is present (NOO_SIBLINGS_DIR), and noomesh-internal's release-align
reads the same file at the revs a release pins.

A second guard keeps the budget the only place a size can come from: a
production create_engine / create_async_engine / pool constructor outside
noomesh/db/pool_budget.py fails, unless it is a NullPool.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from noomesh.db import pool_budget as pb
from tests import _rust_src as rs

ROOT = Path(__file__).resolve().parents[1]
SUPERUSER_RESERVED = 3  # Postgres default; the compose does not change it.
HEADROOM = 10


def _compose_max_connections() -> int:
    text = (ROOT / "docker-compose.cluster.yml").read_text()
    m = re.findall(r"-c max_connections=\$\{NOO_PG_MAX_CONNECTIONS:-(\d+)\}", text)
    assert len(m) == 1, "postgres command must set max_connections from NOO_PG_MAX_CONNECTIONS exactly once"
    return int(m[0])


def _gateway_ceiling() -> int:
    code = rs.own_code((ROOT / "gateway-rust/src/state.rs").read_text())
    m = re.findall(r"pub const GATEWAY_PG_MAX_CONNECTIONS: u32 = (\d+);", code)
    assert len(m) == 1, "GATEWAY_PG_MAX_CONNECTIONS is gone from state.rs; this guard is stale"
    body = rs.fn_body(code, "pub async fn new(config: &AppConfig)")
    assert ".max_connections(GATEWAY_PG_MAX_CONNECTIONS)" in body, (
        "AppState::new must size its pool from GATEWAY_PG_MAX_CONNECTIONS"
    )
    assert "PgPool::connect" not in body, "an unsized PgPool::connect* takes sqlx's default 10"
    return int(m[0])


@dataclass(frozen=True)
class Sibling:
    """A sibling repo's own pools, per process, read at ``sha``.

    Before a sibling declares (``expects_declaration`` False), ``current``
    is its ceiling as read from its code by hand. After, ``declared`` is a
    copy of the ``POOL_CEILINGS`` literal in ``repo``'s ``path`` at ``sha``
    (``test_the_pinned_declarations_match_the_sibling_at_its_sha`` re-reads
    it there), and the process's ceiling is computed from it plus every
    declaration in ``shares`` ("noomesh:<process>" = POOL_BUDGET's pools for
    that process, "<sibling>:POOL_CEILINGS" = that sibling's declaration).
    """

    process: str
    current: int  # ceiling in its code before it declared
    budget: int  # approved (i815)
    expects_declaration: bool
    sha: str
    what: str
    repo: str = ""
    path: str = ""
    declared: dict = field(default_factory=dict)
    shares: tuple = ()


SIBLINGS = {
    # trellion's OWN pools inside noo-trellion; noomesh's pools in that
    # process (audit, heartbeat, conversation store) come from POOL_BUDGET.
    # Budget (general 11-14: never starve trellion's engine to fit): async
    # engine 5+10, lazy sync engine trimmed to 2+3, PageIndexStore 5+3,
    # LISTEN 1.
    "trellion": Sibling(
        process="noo-trellion",
        current=30 + 30 + 15 + 1,
        budget=15 + 5 + 8 + 1,
        expects_declaration=True,
        # trellion main ae9134cf (promoted 2026-11-15; rc.3 built from staging
        # dddf1827, whose declaration is byte-identical).
        sha="ae9134cf1dc6fed3d61beca6bc55672246939f3b",
        what="async init_engine, sync init_engine (opens on first sync use), "
        "PageIndexStore (built in PageIndexRAG.startup), doc_wake LISTEN",
        repo="trellion",
        path="src/trellion/db/pool_budget.py",
        declared={
            "async_engine": (5, 10),
            "sync_engine": (2, 3),
            "pageindex_store": (5, 3),
            "doc_wake_listen": (1, 0),
        },
    ),
    # noo-trellion-intel is the trellion image running noomesh's worker on
    # the ml-intel surface (an ML pack): it opens noomesh's noo-trellion
    # pools AND trellion's, and none of its own: declared 22 + 29 + 0 = 51,
    # the approved budget (general 11-15; +intel+evolve with 2 worker-extras
    # is 181 of 187).
    "trellion-intel": Sibling(
        process="noo-trellion-intel",
        current=79,
        # The trellion image running noomesh's worker on ml-intel: noomesh's
        # 22 + trellion's own 29, none of intel's own (general 11-15: the
        # true number). A trim on ml-intel, if it does not need the
        # conversation store or heartbeat, is recorded in i815.
        budget=51,
        expects_declaration=True,
        # trellion-intel tag v0.1.9 (signed for v0.6.25-rc.3).
        sha="556a892ef95ed7347150c37ddabd0dac9c1d7b06",
        what="none of its own; shares noomesh's noo-trellion pools and trellion's",
        repo="trellion-intel",
        path="src/trellion_intel/pool_budget.py",
        declared={},
        shares=("noomesh:noo-trellion", "trellion:POOL_CEILINGS"),
    ),
    "evolve": Sibling(
        process="noo-evolve",
        current=55,
        budget=25,
        expects_declaration=True,
        # trellion-evolve tag v0.1.11 (signed for v0.6.25-rc.3).
        sha="84014fc57c710ad2b6b3aeb77b769f069f581073",
        what="db.get_engine 4+3, GAStore 3+3, RLPolicyStore 3+3, HofstadterLoopStore 3+3",
        repo="trellion-evolve",
        path="src/noo_evolve/pool_budget.py",
        declared={
            "db_engine": (4, 3),
            "ga_store": (3, 3),
            "rl_policy_store": (3, 3),
            "hofstadter_store": (3, 3),
        },
    ),
}


def _declared_ceiling(name: str) -> int:
    """The process ceiling a sibling's declaration (and what it shares) adds to."""
    s = SIBLINGS[name]
    total = sum(size + overflow for size, overflow in s.declared.values())
    for ref in s.shares:
        repo, _, what = ref.partition(":")
        if repo == "noomesh":
            total += pb.process_ceiling(what)
        else:
            assert what == "POOL_CEILINGS", ref
            total += sum(a + b for a, b in SIBLINGS[repo].declared.values())
    return total


INSTALLS = {
    "default": (),
    "+intel": ("trellion-intel",),
    "+intel+evolve": ("trellion-intel", "evolve"),
}
# How many worker-extra processes each install keeps under the line: two,
# with both first-party add-ons too (181 of 187 at max_connections 200).
MAX_WORKER_EXTRA = {"default": 2, "+intel": 2, "+intel+evolve": 2}


def _sibling(name: str, today: bool) -> int:
    s = SIBLINGS[name]
    if s.expects_declaration:
        return _declared_ceiling(name)
    return s.current if today else s.budget


def _sum(install: str, extras: int, today: bool = False) -> dict[str, int]:
    worker = pb.process_ceiling("noo-worker")
    parts = {
        "gateway": _gateway_ceiling(),
        "noo-worker": worker,
        "noo-trellion": pb.process_ceiling("noo-trellion") + _sibling("trellion", today),
    }
    for name in INSTALLS[install]:
        parts[SIBLINGS[name].process] = _sibling(name, today)
    for i in range(extras):
        parts[f"worker-extra-{i + 1}"] = worker
    return parts


def _line() -> int:
    return _compose_max_connections() - SUPERUSER_RESERVED - HEADROOM


CELLS = [(inst, n) for inst in INSTALLS for n in range(MAX_WORKER_EXTRA[inst] + 1)]


@pytest.mark.parametrize("install,extras", CELLS, ids=[f"{i}+{n}xworker" for i, n in CELLS])
def test_every_pool_ceiling_fits_under_max_connections(install, extras):
    parts = _sum(install, extras)
    total = sum(parts.values())
    assert total < _line(), (
        f"{install} with {extras} worker-extra: pools may open {total} connections "
        f"({parts}), line is {_line()} (max_connections {_compose_max_connections()} "
        f"- {SUPERUSER_RESERVED} reserved - {HEADROOM} headroom). Shrink a pool in "
        "POOL_BUDGET / GATEWAY_PG_MAX_CONNECTIONS or raise NOO_PG_MAX_CONNECTIONS."
    )


def test_todays_default_install_fits_with_the_siblings_as_they_are():
    parts = _sum("default", 0, today=True)
    assert sum(parts.values()) < _line(), parts


def test_a_declared_sibling_is_within_its_budget():
    for name, s in SIBLINGS.items():
        if s.expects_declaration:
            got = _declared_ceiling(name)
            assert got <= s.budget, f"{name} declares {got}, over its budget {s.budget}"


def test_the_declared_ceilings_are_the_reviewed_numbers():
    # Computed from the pinned declarations: each at its approved budget.
    assert {n: _declared_ceiling(n) for n in SIBLINGS} == {
        "trellion": 29,
        "trellion-intel": 51,
        "evolve": 25,
    }


def _sibling_checkout(repo: str) -> Path | None:
    """A git checkout of ``repo``: NOO_SIBLINGS_DIR, beside this repo, or
    beside the main clone this worktree belongs to."""
    import os

    candidates = []
    if os.environ.get("NOO_SIBLINGS_DIR"):
        candidates.append(Path(os.environ["NOO_SIBLINGS_DIR"]) / repo)
    candidates.append(ROOT.parent / repo)
    if ROOT.parent.name == ".worktrees":
        candidates.append(ROOT.parents[2] / repo)
    return next((c for c in candidates if (c / ".git").exists()), None)


def _ceilings_literal(src: str) -> dict:
    """``POOL_CEILINGS`` from a sibling's pool_budget.py, without importing it."""
    for node in ast.parse(src).body:
        target = node.target if isinstance(node, ast.AnnAssign) else (
            node.targets[0] if isinstance(node, ast.Assign) and len(node.targets) == 1 else None
        )
        if isinstance(target, ast.Name) and target.id == "POOL_CEILINGS":
            got = ast.literal_eval(node.value)
            assert isinstance(got, dict), "POOL_CEILINGS is not a dict literal"
            return {k: tuple(v) for k, v in got.items()}
    raise AssertionError("no module-level POOL_CEILINGS literal: the sibling's declaration moved")


@pytest.mark.parametrize("name", [n for n, s in SIBLINGS.items() if s.path])
def test_the_pinned_declarations_match_the_sibling_at_its_sha(name):
    """The pin above against the sibling's own declaration, read with
    ``git show <sha>:<path>`` from a checkout of it (NOO_SIBLINGS_DIR, or
    beside this repo). CI's single-repo workspace has none: skipped there
    (tests/ci_skip_allowlist.txt); the release-align check in
    noomesh-internal reads the same file at the sha the release pins."""
    import os
    import subprocess

    s = SIBLINGS[name]
    base = _sibling_checkout(s.repo)
    shown = None
    if base is not None:
        r = subprocess.run(["git", "-C", str(base), "show", f"{s.sha}:{s.path}"], capture_output=True, text=True)
        shown = r.stdout if r.returncode == 0 else None
    if shown is None:
        if os.environ.get("NOO_REQUIRE_SIBLINGS") == "1":
            pytest.fail(f"NOO_REQUIRE_SIBLINGS=1 and no {s.repo} checkout has {s.sha[:8]}:{s.path}")
        pytest.skip(f"no {s.repo} checkout with {s.sha[:8]}:{s.path} (set NOO_SIBLINGS_DIR, fetch the sibling)")
    assert _ceilings_literal(shown) == s.declared, (
        f"{s.repo}@{s.sha[:8]} {s.path} declares {_ceilings_literal(shown)}; this table pins {s.declared}"
    )


def test_the_declaration_parser_catches_what_it_is_for():
    src = 'from typing import Dict\nPOOL_CEILINGS: Dict[str, tuple] = {"a": (5, 10), "b": (1, 0)}\n'
    assert _ceilings_literal(src) == {"a": (5, 10), "b": (1, 0)}
    with pytest.raises(AssertionError):
        _ceilings_literal("POOL_SIZES = {}\n")
    with pytest.raises(ValueError):
        _ceilings_literal("POOL_CEILINGS = {'a': size()}\n")


def test_every_budget_entry_is_positive_and_bounded():
    for name, (size, overflow) in pb.POOL_BUDGET.items():
        assert size >= 1 and overflow >= 0, name
    for proc, names in pb.PROCESS_POOLS.items():
        for n in names:
            assert n in pb.POOL_BUDGET, f"{proc} lists {n}, which has no budget"


def test_the_process_ceilings_are_the_reviewed_numbers():
    # The table the roll notes quote. A change here is a budget change.
    assert {n: sum(v) for n, v in pb.POOL_BUDGET.items()} == {
        "worker.audit": 4,
        "heartbeat_store": 10,
        "conversation_store": 8,
        "pageindex_store": 8,
        "db.init_db": 30,
    }
    assert pb.process_ceiling("noo-worker") == 14
    assert pb.process_ceiling("noo-trellion") == 22
    assert _gateway_ceiling() == 12
    # trellion's own engine keeps a working pool (general 11-14): 15+5+8+1.
    assert SIBLINGS["trellion"].budget == 29
    assert (SIBLINGS["trellion-intel"].budget, SIBLINGS["evolve"].budget) == (51, 25)


# --------------------------------------------------------------------------
# The guard: no size comes from anywhere but POOL_BUDGET.
# --------------------------------------------------------------------------

_POOL_CALLS = {"create_engine", "create_async_engine", "create_pool", "ConnectionPool", "AsyncConnectionPool"}
# A trellion store handed only a DSN opens its own default-sized pool.
_DSN_STORES = {"ConversationStore", "PageIndexStore"}


def _name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _is_nullpool(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "poolclass" and _name(kw.value) == "NullPool":
            return True
    return False


def _offences(src: str, rel: str) -> list[str]:
    out = []
    budget_module = rel == "noomesh/db/pool_budget.py"
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Call):
            continue
        name = _name(node.func)
        if name in _POOL_CALLS:
            if budget_module:
                for kw in node.keywords:
                    if kw.arg in ("pool_size", "max_overflow", "max_size") and isinstance(kw.value, ast.Constant):
                        out.append(f"{rel}:{node.lineno} {name} with a literal {kw.arg}")
            elif not _is_nullpool(node):
                out.append(f"{rel}:{node.lineno} {name}() outside pool_budget (use budgeted_engine / budgeted_async_engine)")
        elif name in _DSN_STORES and any(kw.arg == "dsn" for kw in node.keywords):
            out.append(f"{rel}:{node.lineno} {name}(dsn=...) opens an unbudgeted pool; pass async_engine=budgeted_async_engine(...)")
    return out


def _production_offences() -> list[str]:
    base = ROOT / "src"
    out = []
    for path in sorted((base / "noomesh").rglob("*.py")):
        rel = path.relative_to(base).as_posix()
        if "/tests/" in rel:
            continue
        out += _offences(path.read_text(encoding="utf-8-sig"), rel)
    return out


def test_no_production_pool_sizes_itself():
    assert _production_offences() == []


def test_the_guard_sees_a_literal_pool():
    bad = "from sqlalchemy import create_engine\ne = create_engine(url, pool_size=7)\n"
    assert _offences(bad, "noomesh/gateway/x.py")
    assert _offences("ConversationStore(dsn=d)\n", "noomesh/gateway/x.py")
    assert not _offences("create_engine(url, poolclass=NullPool)\n", "noomesh/db/x.py")
    assert _offences("create_engine(url, pool_size=3)\n", "noomesh/db/pool_budget.py")


def test_the_gateway_has_one_production_pool():
    """AppState's pool is the gateway's only long-lived one. A one-connection
    pool (mesh_migrate::run, before AppState exists, then dropped) is the
    migration slot HEADROOM covers. Test modules (`tests.rs`, `#[cfg(test)]`)
    are not production."""
    hits = []
    for path in sorted((ROOT / "gateway-rust/src").rglob("*.rs")):
        rel = path.relative_to(ROOT).as_posix()
        if path.name.endswith("tests.rs") or path.name.startswith("test_") or "/tests/" in rel:
            continue
        code = rs.own_code(path.read_text())
        for m in re.finditer(r"PgPoolOptions::new\(\)|PgPool::connect\w*", code):
            chain = code[m.end(): m.end() + 120]
            if m.group(0).startswith("PgPoolOptions") and re.match(r"\s*\.max_connections\(1\)", chain):
                continue
            hits.append(f"{rel}:{code.count(chr(10), 0, m.start()) + 1}")
    assert len(hits) == 1 and hits[0].startswith("gateway-rust/src/state.rs:"), hits


# --------------------------------------------------------------------------
# The wait is seen: a slow checkout is logged and counted.
# --------------------------------------------------------------------------

def _reset_counts():
    with pb._lock:
        pb._slow.clear()
        pb._timeouts.clear()
        pb._last_warn.clear()
        pb._unwarned.clear()


def _pool(name: str, timeout: float):
    from sqlalchemy.pool import QueuePool

    class _Conn:
        def close(self):
            pass

        def rollback(self):
            pass

    cls = pb._poolclass(name, QueuePool)
    return cls(_Conn, pool_size=1, max_overflow=0, timeout=timeout)


def test_a_checkout_that_waits_is_counted_and_named(monkeypatch):
    import threading

    _reset_counts()
    monkeypatch.setattr(pb, "SLOW_CHECKOUT_SECONDS", 0.2)
    warned = []
    monkeypatch.setattr(pb, "_record_wait", lambda *a: (warned.append(a), pb._slow.update([a[0]])))
    pool = _pool("heartbeat_store", timeout=5)
    held = pool.connect()
    threading.Timer(0.4, held.close).start()
    second = pool.connect()  # waits for `held`
    second.close()
    assert warned and warned[0][0] == "heartbeat_store" and warned[0][1] == 10
    assert warned[0][2] >= 0.2 and warned[0][3] is False


def test_a_checkout_that_times_out_is_counted_as_a_timeout(monkeypatch):
    from sqlalchemy.exc import TimeoutError as PoolTimeout

    _reset_counts()
    monkeypatch.setattr(pb, "SLOW_CHECKOUT_SECONDS", 0.1)
    pool = _pool("worker.audit", timeout=0.3)
    held = pool.connect()
    with pytest.raises(PoolTimeout):
        pool.connect()
    held.close()
    assert pb.slow_checkout_counts() == {"worker.audit": {"slow": 1, "timeouts": 1}}


def test_a_fast_checkout_is_not_counted():
    _reset_counts()
    pool = _pool("worker.audit", timeout=1)
    pool.connect().close()
    assert pb.slow_checkout_counts() == {}


def test_the_pool_name_survives_dispose():
    eng = pb.budgeted_engine("heartbeat_store", "postgresql+psycopg://u:p@h/db")
    eng.dispose()
    assert eng.pool._noo_pool_name == "heartbeat_store" and eng.pool.size() == 5


def test_a_caller_cannot_size_a_budgeted_pool():
    with pytest.raises(TypeError):
        pb.budgeted_engine("heartbeat_store", "postgresql+psycopg://u:p@h/db", pool_size=50)


def test_an_async_checkout_wait_is_timed_too(monkeypatch):
    """AsyncAdaptedQueuePool waits inside a greenlet on an asyncio queue;
    the wall-clock timing around _do_get must still see it."""
    import asyncio

    from sqlalchemy.pool import AsyncAdaptedQueuePool
    from sqlalchemy.util import greenlet_spawn

    _reset_counts()
    monkeypatch.setattr(pb, "SLOW_CHECKOUT_SECONDS", 0.2)

    class _Conn:
        def close(self):
            pass

        def rollback(self):
            pass

    pool = pb._poolclass("conversation_store", AsyncAdaptedQueuePool)(
        _Conn, pool_size=1, max_overflow=0, timeout=5
    )

    async def run():
        held = await greenlet_spawn(pool.connect)
        asyncio.get_running_loop().call_later(0.4, held.close)
        second = await greenlet_spawn(pool.connect)
        await greenlet_spawn(second.close)

    asyncio.run(run())
    assert pb.slow_checkout_counts() == {"conversation_store": {"slow": 1, "timeouts": 0}}
