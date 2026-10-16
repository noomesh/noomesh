# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A group chat / space turn reads only what the whole room may see.

The gateway adds ``kb:shared-room`` to the SIGNED principal for every bus
message of a room turn (``channels::scoped_turn``), tool calls included.
The KB resolver clamps every read to the shared tiers when it sees it, and
the personal memory handlers answer nothing. Without the scope, nothing
changes.
"""
from __future__ import annotations

from noomesh.gateway import bus_principal
from noomesh.workers import kb, memory


def _req(scopes, roles=None):
    p = bus_principal.Principal(sub="ada", kind="user", role="operator", scopes=scopes)
    params = {bus_principal.PRINCIPAL_KEY: p}
    if roles is not None:
        params["roles"] = roles
    return params


def test_room_scope_clamps_a_default_read_to_shared_tiers():
    roles = kb._resolve_kb_roles(_req(["read", "write", kb.SHARED_ROOM_SCOPE]), grants=["team:red"])
    assert sorted(roles) == ["company", "system"]


def test_room_scope_clamps_an_explicit_private_tier_away():
    roles = kb._resolve_kb_roles(
        _req(["read", kb.SHARED_ROOM_SCOPE], roles=["user:ada", "team:red", "company"]), grants=["team:red"]
    )
    assert roles == ["company"]


def test_room_scope_wins_over_unrestricted():
    roles = kb._resolve_kb_roles(_req(["read", "kb:unrestricted", kb.SHARED_ROOM_SCOPE]))
    assert sorted(roles) == ["company", "system"]


def test_without_the_scope_the_own_tier_stays():
    roles = kb._resolve_kb_roles(_req(["read"]))
    assert "user:ada" in roles


async def test_memory_search_answers_nothing_in_a_room(monkeypatch):
    called = []
    monkeypatch.setattr(memory, "_get_conversation_store", lambda: called.append(1) or object())
    req = {"query": "what did I say", **_req(["read", kb.SHARED_ROOM_SCOPE])}
    assert await memory._memory_search(req) == ""


async def test_cross_channel_answers_nothing_in_a_room(monkeypatch):
    monkeypatch.setattr(memory, "_get_conversation_store", lambda: object())
    req = {"exclude_channel": "telegram", **_req(["read", kb.SHARED_ROOM_SCOPE])}
    out = await memory._memory_cross_channel(req) if hasattr(memory, "_memory_cross_channel") else None
    if out is None:
        fn = [v for k, v in vars(memory).items() if k.startswith("_memory_cross")][0]
        out = await fn(req)
    assert out == {"success": True, "data": {"messages": []}}
