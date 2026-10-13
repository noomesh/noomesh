# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The role set the gateway filters the listing and graph with.

`worker.rag.audience` is how the Rust gateway learns who may read what. It must
be the SAME answer retrieval uses, because there is no second copy of the
rules: this pins `_resolve_kb_roles` (via `_kb_roles_for`) to the fixture table
`tests/fixtures/kb_audience_isolation.json`, which the DB-backed Rust test
(`gateway-rust/src/memory/scope.rs`) feeds to the scoped SQL.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from noomesh.gateway import bus_principal as bp
from noomesh.workers import kb as kb_worker
from noomesh.workers import rag as rag_worker

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "kb_audience_isolation.json"
FIXTURE = json.loads(FIXTURE_PATH.read_text())
CALLERS = FIXTURE["callers"]

#: sha256 of the fixture. the trellion-intel add-on keeps a VENDORED COPY
#: (tests/fixtures/kb_audience_isolation.json) that its audience tests are run
#: against, and pins the same digest in tests/test_audience_scoping.py
#: (FIXTURE_SHA256). Change the fixture here and this fails; update the digest
#: in BOTH repos and copy the file across, or the two suites stop describing the
#: same corpus.
FIXTURE_SHA256 = "f206effaac779a5ce39d1c9ce38a3574209c2fa62d0c7c20ad89718f546e6216"


def test_the_fixture_is_pinned_so_the_intel_copy_cannot_drift():
    import hashlib

    assert hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest() == FIXTURE_SHA256, (
        "kb_audience_isolation.json changed: copy it to the trellion-intel add-on's "
        "tests/fixtures/ and update FIXTURE_SHA256 in both repos"
    )


def _params(spec: dict) -> dict:
    p = bp.Principal(sub=spec["sub"], kind="user", role="user", scopes=list(spec["scopes"]))
    return {bp.PRINCIPAL_KEY: p}


@pytest.fixture
def grants(monkeypatch):
    table: dict = {}

    async def _map():
        return table

    monkeypatch.setattr(kb_worker, "_kb_grants_map", _map)
    return table


@pytest.mark.parametrize("who", sorted(CALLERS))
async def test_the_resolver_matches_the_fixture_table(who, grants):
    spec = CALLERS[who]
    grants[spec["sub"].split("/")[0]] = list(spec["grants"])
    assert await kb_worker._kb_roles_for(_params(spec)) == spec["roles"]


@pytest.mark.parametrize("who", sorted(CALLERS))
async def test_the_audience_handler_answers_with_the_same_set(who, grants):
    spec = CALLERS[who]
    grants[spec["sub"].split("/")[0]] = list(spec["grants"])
    reply = await rag_worker._rag_audience({"params": _params(spec)})
    assert reply == {"roles": spec["roles"]}


async def test_a_grant_cannot_put_admin_or_system_or_the_legacy_tier_in_a_readers_set(grants):
    spec = CALLERS["b_op"]
    grants["b"] = list(spec["grants"])
    roles = await kb_worker._kb_roles_for(_params(spec))
    assert "admin" not in roles and "user" not in roles
    # `system` is world-readable, so it is present regardless of the grant.
    assert roles == ["company", "system", "user:b"]


async def test_generated_is_opt_in_not_in_the_default_set(grants):
    roles = await kb_worker._kb_roles_for(_params(CALLERS["a"]))
    assert "generated" not in roles


async def test_a_connection_is_the_same_person_as_its_account(grants):
    grants["a"] = ["team:x"]
    conn = {"sub": "a/laptop", "scopes": ["read"]}
    assert await kb_worker._kb_roles_for(_params(conn)) == await kb_worker._kb_roles_for(
        _params({"sub": "a", "scopes": ["read"]})
    )


async def test_no_verified_principal_is_refused_not_unrestricted(grants):
    with pytest.raises(PermissionError):
        await rag_worker._rag_audience({"params": {"_requester": {"sub": "a", "scopes": ["admin"]}}})


async def test_a_body_claiming_admin_does_not_make_a_user_unrestricted(grants):
    params = _params(CALLERS["a"])
    params["_requester"] = {"sub": "a", "scopes": ["admin"]}
    assert (await rag_worker._rag_audience({"params": params}))["roles"] == CALLERS["a"]["roles"]
