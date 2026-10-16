# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""H-D1 cross-user scoping regression tests.

Verifies the NATS memory handlers thread the requesting user's identity into
the conversation store so one tenant can never read another tenant's data.
The store itself applies ``(c.user_id = :user_id OR c.user_id IS NULL)``; these
tests assert the handlers actually *supply* the identity (the historical gap).
"""
import asyncio

import pytest

from src.noomesh.workers import memory as wp


class FakeStore:
    def __init__(self):
        self.search_text_calls = []
        self.list_calls = []

    async def search_text(self, query, top_k=5, user_id=None, persona_id=None,
                          org=None, teams=None):
        self.search_text_calls.append(
            {"query": query, "top_k": top_k, "user_id": user_id, "persona_id": persona_id}
        )
        self.last_scope = {"org": org, "teams": teams}
        return [({"content": "hello world"}, 0.9)]

    async def list_conversations(self, user_id=None, active_only=False, limit=20,
                                 org=None, teams=None, **kw):
        self.list_calls.append({"user_id": user_id, "limit": limit, "org": org, "teams": teams})
        return {
            "conversations": [
                {"id": "c1", "metadata": {"source_channel": "telegram"}},
                {"id": "c2", "metadata": {"source_channel": "terminal"}},
            ]
        }

    async def get_recent_messages(self, conv_id, limit=10, **kw):
        return [{"type": "user", "content": f"msg-{conv_id}"}]


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _sole(monkeypatch, username):
    """Pretend the install has exactly one enabled account."""
    _accounts(monkeypatch, [username])


def _accounts(monkeypatch, usernames):
    """Stub the account-count lookup `resolve_scope_user` does.

    Patched at the scope module (both workers import the same function), and
    the module cache is cleared so tests cannot see each other's answers.
    """
    from src.noomesh.identity import scope

    scope.reset_scope_cache()

    async def _fake():
        if len(usernames) == 1:
            return usernames[0], "sole_account"
        return None, ("no_accounts" if not usernames else "several_accounts")

    monkeypatch.setattr(scope, "_sole_account", _fake)



def test_memory_search_scopes_by_user(monkeypatch):
    store = FakeStore()
    monkeypatch.setattr(wp, "_get_conversation_store", lambda: store)
    out = _run(
        wp._memory_search(
            {"params": {"query": "q", "top_k": 3, "user_id": "alice", "persona_id": "p1"}}
        )
    )
    # Over-fetched: format_memory_lines drops tool rows and the query itself.
    assert store.search_text_calls == [
        {"query": "q", "top_k": 3 * wp.MEMORY_OVERFETCH, "user_id": "alice", "persona_id": "p1"}
    ]
    assert "hello world" in out


def test_memory_search_single_user_resolves_sole_account(monkeypatch):
    """No identity on a single-account install: scoped to that account.

    This used to run UNSCOPED (the NOO_MULTI_USER default), i.e. the store
    skipped its scope join. Scoping to the only account there is cannot hide
    anything from the only person there is, and it is what stops the same
    call leaking on an install that later grows a second account.
    """
    store = FakeStore()
    monkeypatch.setattr(wp, "_get_conversation_store", lambda: store)
    _sole(monkeypatch, "solo")
    _run(wp._memory_search({"query": "q"}))
    assert store.search_text_calls[0]["user_id"] == "solo"
    assert store.search_text_calls[0]["persona_id"] is None


def test_memory_search_result_shape_is_tuple_safe(monkeypatch):
    # search_text returns List[Tuple[entry, score]]; handler must unpack, not
    # treat rows as dicts (the historical bug that called a non-existent method).
    store = FakeStore()
    monkeypatch.setattr(wp, "_get_conversation_store", lambda: store)
    _sole(monkeypatch, "solo")
    out = _run(wp._memory_search({"params": {"query": "q"}}))
    assert out == "- (earlier, noted) hello world"


def test_cross_channel_scopes_by_user_and_excludes_current(monkeypatch):
    store = FakeStore()
    monkeypatch.setattr(wp, "_get_conversation_store", lambda: store)
    res = _run(
        wp._memory_cross_channel(
            {"params": {"exclude_channel": "terminal", "top_k": 5, "user_id": "bob"}}
        )
    )
    assert store.list_calls[0]["user_id"] == "bob"
    msgs = res["data"]["messages"]
    assert msgs, "expected cross-channel messages"
    assert all(m["channel"] != "terminal" for m in msgs)  # current channel excluded
    assert any(m["channel"] == "telegram" for m in msgs)


def test_cross_channel_single_user_resolves_sole_account(monkeypatch):
    store = FakeStore()
    monkeypatch.setattr(wp, "_get_conversation_store", lambda: store)
    _sole(monkeypatch, "solo")
    _run(wp._memory_cross_channel({"exclude_channel": "terminal", "top_k": 3}))
    assert store.list_calls[0]["user_id"] == "solo"


def test_memory_search_fails_closed_with_no_accounts(monkeypatch):
    # No resolvable identity: the handler must NOT query the store (which
    # would skip the scope join and return every user's entries).
    store = FakeStore()
    monkeypatch.setattr(wp, "_get_conversation_store", lambda: store)
    _accounts(monkeypatch, [])
    out = _run(wp._memory_search({"params": {"query": "q"}}))
    assert out == ""
    assert store.search_text_calls == []  # store never touched


def test_memory_search_fails_closed_with_several_accounts(monkeypatch):
    # Two tenants and no identity is exactly the ambiguity that used to leak.
    store = FakeStore()
    monkeypatch.setattr(wp, "_get_conversation_store", lambda: store)
    _accounts(monkeypatch, ["alice", "bob"])
    out = _run(wp._memory_search({"params": {"query": "q"}}))
    assert out == ""
    assert store.search_text_calls == []


def test_memory_search_explicit_identity_is_never_overridden(monkeypatch):
    # Even on a sole-account install, a supplied user_id wins — resolution
    # fills a gap, it does not reassign.
    store = FakeStore()
    monkeypatch.setattr(wp, "_get_conversation_store", lambda: store)
    _accounts(monkeypatch, ["solo"])
    _run(wp._memory_search({"params": {"query": "q", "user_id": "alice"}}))
    assert store.search_text_calls[0]["user_id"] == "alice"


def test_cross_channel_fails_closed_with_several_accounts(monkeypatch):
    store = FakeStore()
    monkeypatch.setattr(wp, "_get_conversation_store", lambda: store)
    _accounts(monkeypatch, ["alice", "bob"])
    res = _run(wp._memory_cross_channel({"params": {"exclude_channel": "terminal"}}))
    assert res["data"]["messages"] == []
    assert store.list_calls == []  # store never touched


def test_memory_search_threads_org_and_teams(monkeypatch):
    # PR5: the resolved org + team tiers must reach the store filter.
    store = FakeStore()
    monkeypatch.setattr(wp, "_get_conversation_store", lambda: store)

    async def fake_resolve(_store, _uid):
        return "acme", ["team:research"]

    monkeypatch.setattr(wp, "_resolve_org_teams", fake_resolve)
    _run(wp._memory_search({"params": {"query": "q", "user_id": "alice"}}))
    assert store.last_scope == {"org": "acme", "teams": ["team:research"]}


def test_cross_channel_threads_org_and_teams(monkeypatch):
    store = FakeStore()
    monkeypatch.setattr(wp, "_get_conversation_store", lambda: store)

    async def fake_resolve(_store, _uid):
        return "acme", ["team:research"]

    monkeypatch.setattr(wp, "_resolve_org_teams", fake_resolve)
    _run(wp._memory_cross_channel({"params": {"exclude_channel": "x", "user_id": "alice"}}))
    assert store.list_calls[0]["org"] == "acme"
    assert store.list_calls[0]["teams"] == ["team:research"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_memory_lines_are_labelled_and_filtered():
    """mcmini, 2026-10-16: asked about machine learning, gemma answered an
    older "what can you tell me about trading" that arrived in the prompt as a
    bare line, and its own "Tool: noo_rag_query ... trading" records came back
    to steer the next search. Lines now carry date + speaker; tool rows and
    the message being answered are dropped."""
    day = 1792087167.0  # 2026-10-15T17:59:27Z
    results = [
        ({"type": "user", "content": "tell me about machien learning", "created_at": day}, 0.9),
        ({"type": "user", "content": "what can you tell me about trading", "created_at": day}, 0.7),
        ({"type": "tool_call", "content": "Tool: noo_rag_query\nArguments: {}", "created_at": day}, 0.6),
        ({"type": "assistant", "content": "Trading is ...", "created_at": day}, 0.5),
        ({"type": "user", "content": "", "created_at": day}, 0.4),
        ({"type": "user", "content": "one more", "created_at": day}, 0.3),
    ]
    lines = wp.format_memory_lines(results, "Tell me about  MACHIEN learning", 2)
    assert lines == [
        "- (2026-10-15, the user said) what can you tell me about trading",
        "- (2026-10-15, you replied) Trading is ...",
    ]


def test_memory_lines_tolerate_bad_timestamps():
    lines = wp.format_memory_lines([({"type": "user", "content": "x", "created_at": "nope"}, 1.0)], "q", 5)
    assert lines == ["- (earlier, the user said) x"]
