# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The last-admin refusal names a `noo` verb that exists and does the job.

The gateway refuses to disable, erase or demote the last enabled admin and
tells the operator what to run first. It once named
`noo security user set-role <user> admin` when no such verb existed: the
refusal was a dead end. This guard reads the command from
`LAST_ADMIN_PROMOTE_CMD` in users.rs and holds it to the CLI's dispatch
table (main.rs NATIVE), its usage row and its parser's tiers, and the verb
to the route the refusal guards.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests import _rust_src as rs

ROOT = Path(__file__).resolve().parents[1]
USERS = ROOT / "gateway-rust/src/routes/users.rs"
CLI = ROOT / "noo-cli/src"


def _hint() -> list[str]:
    code = rs.own_code(USERS.read_text())
    m = re.search(r'const LAST_ADMIN_PROMOTE_CMD: &str = "([^"]+)";', code)
    assert m, "LAST_ADMIN_PROMOTE_CMD is gone from users.rs"
    guard = rs.fn_body(code, "async fn require_not_last_admin(")
    assert "{LAST_ADMIN_PROMOTE_CMD}" in guard, "the refusal no longer names the constant"
    return m.group(1).split()


def test_the_last_admin_refusal_names_a_registered_verb() -> None:
    words = _hint()
    assert words[0] == "noo"
    path = [w for w in words[1:] if not w.startswith("<")][:3]
    assert path == ["security", "user", "set-role"], words
    rendered = "(&[" + ", ".join(f'"{w}"' for w in path) + "]"
    main = rs.own_code((CLI / "main.rs").read_text())
    assert re.search(re.escape(rendered) + r", commands::security_user_set_role\)", main), (
        f"main.rs NATIVE has no {path}: the refusal names a verb noo does not have"
    )
    usage = (CLI / "usage.rs").read_text()
    assert re.search(re.escape(rendered) + r', "<username> <user\|operator\|admin>"', usage), "usage row"


def test_the_hint_role_is_a_tier_the_verb_takes_and_the_verb_calls_the_role_route() -> None:
    words = _hint()
    role = words[-1]
    sec = rs.own_code((CLI / "commands/security.rs").read_text())
    tiers = re.search(r"const ROLE_TIERS: \[&str; 3\] = \[([^\]]+)\];", sec)
    assert tiers, "ROLE_TIERS is gone"
    assert role in re.findall(r'"([a-z]+)"', tiers.group(1)), f"{role!r} is not a tier set-role takes"
    verb = rs.fn_body(sec, "pub fn security_user_set_role(")
    assert '"/api/security/users/{}/role"' in verb
    # The route the verb calls is the one whose handler runs the guard.
    users = rs.own_code(USERS.read_text())
    assert '.route("/api/security/users/{username}/role", post(user_set_role))' in users
    assert "require_not_last_admin(" in rs.fn_body(users, "async fn user_set_role(")
