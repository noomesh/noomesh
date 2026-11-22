# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The last-admin refusal names `noo` commands that exist and do the job.

The gateway refuses to disable, erase or demote the last enabled admin and
tells the operator what to run first. It once named
`noo security user set-role <user> admin` when no such verb existed: the
refusal was a dead end. It now names the existing `set-scopes` (which
replaces the scope set, so the hint keeps the account's current scopes and
adds `admin`) and `noo security user list` to read them. This guard reads
the hint from `LAST_ADMIN_PROMOTE_CMD` in users.rs and holds every `noo`
command in it to the CLI's dispatch table (main.rs NATIVE) and usage rows,
and every flag to that command's syntax.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests import _rust_src as rs

ROOT = Path(__file__).resolve().parents[1]
USERS = ROOT / "gateway-rust/src/routes/users.rs"
CLI = ROOT / "noo-cli/src"


def _hint() -> str:
    code = rs.own_code(USERS.read_text())
    m = re.search(r'const LAST_ADMIN_PROMOTE_CMD: &str =\s*"([^"]+)";', code)
    assert m, "LAST_ADMIN_PROMOTE_CMD is gone from users.rs"
    guard = rs.fn_body(code, "async fn require_not_last_admin(")
    assert "{LAST_ADMIN_PROMOTE_CMD}" in guard, "the refusal no longer names the constant"
    return m.group(1)


def _commands(hint: str) -> list[list[str]]:
    """Each `noo …` command in the hint, as its words (up to `;` or a backtick)."""
    return [m.group(1).split() for m in re.finditer(r"\bnoo ([^;`]+)", hint)]


def test_every_command_in_the_last_admin_refusal_is_a_registered_verb() -> None:
    cmds = _commands(_hint())
    assert len(cmds) >= 2, cmds
    main = rs.own_code((CLI / "main.rs").read_text())
    usage = (CLI / "usage.rs").read_text()
    for words in cmds:
        path = [w for w in words if not w.startswith(("<", "-"))][:3]
        rendered = "(&[" + ", ".join(f'"{w}"' for w in path) + "]"
        assert rendered in main, f"main.rs NATIVE has no {path}: the refusal names a verb noo does not have"
        row = re.search(re.escape(rendered) + r', "([^"]*)"', usage)
        assert row, f"no usage row for {path}"
        for flag in (w for w in words if w.startswith("--")):
            assert flag in row.group(1), f"{path}: {flag} is not in its syntax `{row.group(1)}`"


def test_the_hint_promotes_by_adding_admin_and_keeps_the_other_scopes() -> None:
    hint = _hint()
    assert "set-role" not in hint, "set-role does not exist"
    assert "--scope admin" in hint
    # set-scopes REPLACES the set: the hint must say to keep the current ones.
    assert "current scopes" in hint and "security user list" in hint
