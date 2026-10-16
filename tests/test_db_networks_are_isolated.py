# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Postgres and Redis answer on `noo-db` only, and `noo-db` holds exactly
their clients.

SECURITY.md promises network isolation. Until this guard postgres and redis
were on `noo-cluster` AS WELL as `noo-db`, so every container on the cluster
network (inference backends that parse untrusted model files, nginx, the
monitoring images, the worker's tool code) had a TCP path to postgres:5432
and redis:6379, and the "internal DB network" isolated nothing.

What holds now, read from the composed projection (base + every add-on
overlay in this tree):

  1. redis' networks are exactly {noo-db};
  2. postgres' networks are exactly {noo-db, noo-pg-host}, where `noo-pg-host`
     is the one non-internal bridge that lets Docker publish the host port
     (an internal-only container publishes nothing), and NO other service is
     on it;
  3. `noo-db` is `internal: true` and its member set is an explicit
     allow-list (below). A new member is a reviewed change to this file;
  4. every service that dials `postgres` or `redis` by name is a `noo-db`
     member, so removing `noo-cluster` from the databases cannot strand a
     client (the failure would be a connect timeout on the next upgrade).

The evolve and trellion-intel add-ons ship their overlays in their own signed
bundles; they are on the allow-list so their overlays may join, and the
overlay repositories guard that they do.
"""

from __future__ import annotations

import copy
import re

import pytest

from tests._compose_projection import env_of, full_projection

# Postgres/Redis themselves, then every client. `evolve` and `trellion-intel`
# are add-on services whose overlays are not in this tree.
DB_NET_ALLOW = {
    "postgres", "redis",
    "gateway", "worker", "worker-extra", "trellion",
    "trellion-intel", "evolve",
}
# The members the in-tree files must actually carry (a guard that passes on an
# empty network is not guarding).
DB_NET_REQUIRED = {"postgres", "redis", "gateway", "worker", "worker-extra", "trellion"}

DIALS_DB = re.compile(r"@postgres:5432|rediss?://(?:[^@/]*@)?redis:6379")


def _nets(svc: dict) -> set[str]:
    n = svc.get("networks")
    if isinstance(n, dict):
        return set(n)
    return set(n or [])


def violations(proj: dict) -> list[str]:
    """Pure over a projection, so the planted negatives below can bite it."""
    out: list[str] = []
    svcs = proj["services"]
    nets = proj.get("networks") or {}

    if _nets(svcs["redis"]) != {"noo-db"}:
        out.append(f"redis networks are {sorted(_nets(svcs['redis']))}, want ['noo-db']")
    if _nets(svcs["postgres"]) != {"noo-db", "noo-pg-host"}:
        out.append(f"postgres networks are {sorted(_nets(svcs['postgres']))}, want ['noo-db', 'noo-pg-host']")

    if not nets.get("noo-db", {}).get("internal"):
        out.append("noo-db is not `internal: true`")
    if nets.get("noo-pg-host", {}).get("internal"):
        out.append("noo-pg-host is internal: it could not publish postgres' host port")

    pg_host = {n for n, s in svcs.items() if "noo-pg-host" in _nets(s)}
    if pg_host != {"postgres"}:
        out.append(f"noo-pg-host members are {sorted(pg_host)}, want ['postgres']")

    members = {n for n, s in svcs.items() if "noo-db" in _nets(s)}
    if members - DB_NET_ALLOW:
        out.append(f"noo-db has members outside the allow-list: {sorted(members - DB_NET_ALLOW)}")
    if DB_NET_REQUIRED - members:
        out.append(f"noo-db is missing required members: {sorted(DB_NET_REQUIRED - members)}")

    for name, svc in svcs.items():
        if name in ("postgres", "redis"):
            continue
        env = env_of(svc)
        if any(DIALS_DB.search(v) for v in env.values()) and "noo-db" not in _nets(svc):
            out.append(f"{name} dials postgres/redis by name but is not on noo-db")
    return out


@pytest.fixture(scope="module")
def proj() -> dict:
    return full_projection()


def test_databases_answer_on_noo_db_only(proj):
    assert violations(proj) == []


def test_the_clients_are_found(proj):
    """The client scan is not vacuous: it sees the gateway, the worker and
    trellion dialling the databases."""
    dialers = {
        n for n, s in proj["services"].items()
        if any(DIALS_DB.search(v) for v in env_of(s).values())
    }
    assert {"gateway", "worker", "trellion"} <= dialers, sorted(dialers)


def test_cluster_network_is_not_on_either_database(proj):
    for name in ("postgres", "redis"):
        assert "noo-cluster" not in _nets(proj["services"][name]), name
        assert "default" not in _nets(proj["services"][name]), name


# ── planted negatives: the checker must fail on the pre-fix shape ──────────

def _mut(proj, fn):
    p = copy.deepcopy(proj)
    fn(p)
    return violations(p)


def test_redis_back_on_noo_cluster_is_caught(proj):
    v = _mut(proj, lambda p: p["services"]["redis"]["networks"].update({"noo-cluster": None}))
    assert any(s.startswith("redis networks") for s in v), v


def test_postgres_back_on_noo_cluster_is_caught(proj):
    v = _mut(proj, lambda p: p["services"]["postgres"]["networks"].update({"noo-cluster": None}))
    assert any(s.startswith("postgres networks") for s in v), v


def test_a_stranger_on_noo_db_is_caught(proj):
    v = _mut(proj, lambda p: p["services"]["model-cache"].update({"networks": {"noo-cluster": None, "noo-db": None}}))
    assert any("outside the allow-list" in s and "model-cache" in s for s in v), v


def test_a_client_off_noo_db_is_caught(proj):
    v = _mut(proj, lambda p: p["services"]["worker"].update({"networks": {"noo-cluster": None}}))
    assert any("worker dials postgres/redis by name but is not on noo-db" in s for s in v), v


def test_a_second_member_of_the_publish_network_is_caught(proj):
    v = _mut(proj, lambda p: p["services"]["gateway"]["networks"].update({"noo-pg-host": None}))
    assert any("noo-pg-host members" in s for s in v), v
