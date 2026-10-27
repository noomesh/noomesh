# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Listing conversations is scoped, and the total must be scoped with it.

`GET /api/conversations` was documented and never registered — the spec even
carried a NOTE admitting it, and the Python `memory_cli.py` (since deleted) was
fetching it and getting a 404. So the fix is to register it, not to delete
the path: users are meant to see their own conversations, which is what
`scoped_user` already enforces.

The subtler half is the one these tests exist for. `conversations_with_preview`
filtered the LIST by the enforced `scope` and counted the TOTAL by the raw
`params.user_id`. For a User-tier caller who passed no `user_id` those differ:
scope is their own name, the raw parameter is None, and `WHERE (NULL IS NULL
OR …)` counts every conversation on the install. They saw their own rows
beside somebody else's count — not content, but a cross-tenant fact, and a
pagination control that disagreed with the page it described.

Textual, like the other cross-language guards here: the handler is Rust and
the crates share no library with this suite.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MEMORY = ROOT / "gateway-rust/src/routes/memory.rs"
AUTH = ROOT / "gateway-rust/src/auth.rs"


def _handler(name: str, code_only: bool = False) -> str:
    """One handler's body. `code_only` strips `//` comments.

    Three times in one session a guard in this repo has failed on the very
    comment explaining the thing it checks for — the comment below names
    `params.user_id` precisely to say it must not be bound. A check that
    cannot tell code from prose is a check that punishes documenting."""
    src = MEMORY.read_text(encoding="utf-8")
    start = src.index(f"async fn {name}(")
    body = src[start : src.index("\n}\n", start)]
    if code_only:
        body = "\n".join(l.split("//")[0] for l in body.splitlines())
    return body


def test_the_documented_list_path_is_registered():
    """The whole defect: a path in the spec that the router never served."""
    src = MEMORY.read_text(encoding="utf-8")
    assert '.route("/api/conversations", get(conversations_with_preview))' in src
    assert '.route("/api/conversations/with-preview", get(conversations_with_preview))' in src


def test_every_bind_in_the_list_handler_uses_the_enforced_scope():
    """Not "the total is fixed" — that a raw request parameter is never bound
    at all. A second query added later would reintroduce this verbatim."""
    body = _handler("conversations_with_preview", code_only=True)
    assert "params.user_id" not in body.replace(
        "params.user_id.as_deref()", ""
    ), (
        "conversations_with_preview binds the RAW user_id somewhere. The list "
        "filters by `scope`; anything else must too, or the two disagree for "
        "any caller whose scope was forced rather than requested."
    )
    assert body.count(".bind(&scope)") >= 2, "the list and the total both bind the scope"


def test_reading_one_conversation_compares_the_rows_owner():
    """The id says nothing about who owns it, so the row must be fetched and
    compared — and the refusal must be a 404, or ids are enumerable by
    status code."""
    body = _handler("conv_detail")
    assert "conv.1.as_deref() != Some(want.as_str())" in body
    assert "NotFound" in body and "Forbidden" not in body.split("let conv =")[1]


def test_a_user_tier_caller_cannot_name_another_user():
    """`scoped_user` is the one rule all of this rests on."""
    src = AUTH.read_text(encoding="utf-8")
    fn = src[src.index("pub fn scoped_user(") :]
    fn = fn[: fn.index("\n}\n")]
    # Operator and above may name anyone; below that, only themselves.
    assert "r.role >= Role::Operator" in fn
    assert "may only read their own data" in fn
    # A node holding a cluster credential is refused outright.
    assert "may not read user data" in fn
