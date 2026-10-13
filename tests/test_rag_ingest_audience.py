# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every knowledge-base document is stored with an audience.

An absent audience used to mean "admin only" by accident of the read filter.
It is now an explicit tag, and the default for a known uploader is the
uploader. These tests drive the real `_rag_ingest` and assert the metadata
that actually reaches the storage boundary (`rag.ingest`), not that something
was called.
"""
from __future__ import annotations

import pytest

from noomesh.gateway import bus_principal as bp
from noomesh.gateway import kb_roles
from noomesh.workers import rag as rag_worker
from noomesh.workers.kb import _resolve_kb_roles, _writable_kb_roles

ADMIN = {"sub": "alice", "scopes": ["admin", "write", "read"]}
PERSON = {"sub": "bob", "scopes": ["read", "write"]}


class _Store:
    def __init__(self):
        self.calls: list[dict] = []

    async def ingest(self, content, title=None, source_uri=None, metadata=None):
        self.calls.append({"content": content, "source_uri": source_uri, "metadata": metadata})
        return "doc-1"


@pytest.fixture
def harness(monkeypatch):
    store = _Store()
    state = {"default": [], "rules": [], "grants": {}}
    monkeypatch.setattr(rag_worker, "_get_rag", lambda: store)

    async def _rules():
        return state["rules"]

    async def _grants():
        return state["grants"]

    monkeypatch.setattr(rag_worker, "_kb_source_rules", _rules)
    monkeypatch.setattr(rag_worker, "_kb_grants_map", _grants)
    monkeypatch.setattr(kb_roles, "_load_kb_config", lambda: None)
    monkeypatch.setitem(kb_roles._cache, "rules", [])
    monkeypatch.setitem(kb_roles._cache, "default_roles", state["default"])

    async def run(requester=None, **params):
        req = {"text": "hello", "title": "t", **params}
        if requester is not None:
            req["_requester"] = requester
        store.calls.clear()
        await rag_worker._rag_ingest(req)
        assert len(store.calls) == 1
        return store.calls[0]["metadata"]["roles"]

    run.state = state
    run.store = store
    run.set_default = lambda roles: kb_roles._cache.__setitem__("default_roles", list(roles))
    return run


async def test_person_with_no_roles_gets_their_own_tier(harness):
    assert await harness(PERSON) == ["user:bob"]


async def test_admin_with_no_roles_gets_their_own_tier_not_admin(harness):
    assert await harness(ADMIN) == ["user:alice"]


async def test_default_roles_never_widen_a_known_uploader(harness):
    harness.set_default(["company"])
    assert await harness(PERSON) == ["user:bob"]
    assert await harness(ADMIN) == ["user:alice"]


async def test_no_uploader_and_empty_default_is_an_explicit_admin_tag(harness):
    assert await harness(None) == ["admin"]


async def test_no_uploader_uses_default_roles(harness):
    harness.set_default(["company"])
    assert await harness(None) == ["company"]


async def test_a_source_rule_never_widens_an_uploaders_own_document(harness):
    # The operator's rule: an upload is the uploader's until they choose a
    # team or the org. A provenance rule is for ingests with nobody behind
    # them, not a way to publish a person's upload for them.
    harness.state["rules"].append(("gdrive://*", ["company"]))
    assert await harness(PERSON, source_uri="gdrive://abc") == ["user:bob"]
    assert await harness(ADMIN, source_uri="gdrive://abc") == [f"user:{ADMIN['sub']}"]


async def test_a_source_rule_tags_an_ingest_with_no_uploader(harness):
    harness.state["rules"].append(("gdrive://*", ["company"]))
    harness.set_default(["team:ops"])
    assert await harness(None, source_uri="gdrive://abc") == ["company"]
    assert await harness(None, source_uri="file:///x") == ["team:ops"]


async def test_explicit_roles_are_honoured_within_the_clamp(harness):
    assert await harness(PERSON, roles=["company"]) == ["company"]
    assert await harness(ADMIN, roles=["system"]) == ["system"]


@pytest.mark.parametrize("asked", [["admin"], ["system"], ["user:alice"], ["admin", "system"]])
async def test_a_non_admin_cannot_tag_admin_or_system_and_falls_back_to_self(harness, asked):
    assert await harness(PERSON, roles=asked) == ["user:bob"]


async def test_a_granted_team_is_taggable(harness):
    harness.state["grants"]["bob"] = ["team:eng"]
    assert await harness(PERSON, roles=["team:eng"]) == ["team:eng"]


async def test_a_clamp_that_empties_roles_with_no_uploader_is_refused(harness):
    # A requester dict with no sub: nothing to fall back to. Must raise,
    # never store an untagged document.
    with pytest.raises(ValueError, match="no audience"):
        await harness({"sub": "", "scopes": ["read"]}, roles=["admin"])
    assert harness.store.calls == []


async def test_stored_metadata_always_has_non_empty_roles(harness):
    for requester in (None, ADMIN, PERSON):
        harness.store.calls.clear()
        req = {"text": "x", "title": "t", "metadata": {"k": "v"}}
        if requester:
            req["_requester"] = requester
        await rag_worker._rag_ingest(req)
        md = harness.store.calls[0]["metadata"]
        assert md["roles"] and all(isinstance(r, str) and r for r in md["roles"])
        assert md["k"] == "v"


# ── the `admin` audience at the role-resolution level ──────────────────

def _principal(req):
    return {
        bp.PRINCIPAL_KEY: bp.Principal(
            sub=req["sub"], kind="user", role="user", scopes=list(req["scopes"])
        )
    }


def test_admin_reads_everything_so_admin_tagged_docs_are_visible():
    # None == unrestricted: no role filter is applied for an admin.
    assert _resolve_kb_roles(_principal(ADMIN)) is None


def test_non_admin_read_set_never_contains_admin_even_when_asked_or_granted():
    got = _resolve_kb_roles(_principal(PERSON), grants=["admin", "team:eng"])
    assert "admin" not in got and "team:eng" in got
    asked = _resolve_kb_roles({**_principal(PERSON), "roles": ["admin"]}, grants=["admin"])
    assert "admin" not in asked


def test_non_admin_can_never_write_admin_even_when_granted():
    allowed = _writable_kb_roles(PERSON, ["admin", "team:eng"])
    assert "admin" not in allowed and "team:eng" in allowed
    assert _writable_kb_roles(ADMIN) is None  # admin is unclamped, may tag admin


def test_a_user_doc_is_readable_by_its_owner_admin():
    # The owner is an admin: unrestricted read covers their own user:<sub>.
    assert _resolve_kb_roles(_principal(ADMIN)) is None
    # And a non-admin owner reads their own tier.
    assert "user:bob" in _resolve_kb_roles(_principal(PERSON))
