# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Python guards read Rust source through tests/_rust_src.py, and only there.

A guard that reads Rust source to show an absence (no plaintext lane, no
vendor call, no swallowed read) used to cut each file at its FIRST
`#[cfg(test)]`, or count braces with no notion of a string or a comment.
Either one hides real code: everything after a test-only item, or
everything after a `}` inside a string. 18 files under tests/ did one or
the other (i460 Finding 0, 2026-11-05).

Here:
- the helper is the third copy of the Rust lexer, pinned to the same rows
  as the two Rust copies (tests/fixtures/test_src_cases.json);
- no file under tests/ strips Rust test code by itself.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests import _rust_src as rs

REPO = Path(__file__).resolve().parents[1]
CASES = REPO / "tests" / "fixtures" / "test_src_cases.json"
HERE = Path(__file__).name

# Shapes of a hand-rolled strip. The attribute is assembled, so this file's
# own patterns do not describe a strip of their own.
_A = re.escape("#[cfg(" + "test)]")
STRIPS = [
    # a cut or split at a literal that names the attribute
    re.compile(r"\.(?:split|rsplit|find|rfind|index|rindex|partition|rpartition)\(\s*(?:r|rb|b)?[\"'][^\"'\n]*" + _A),
    # a line compared with, or starting with, the attribute
    re.compile(r"(?:==|!=|startswith\(|endswith\()\s*(?:r|b)?[\"']\s*" + _A),
    # a strip function of its own
    re.compile(r"def\s+_?strip_(?:rust_)?test"),
]

# Converted by a PR of its own, named here; each entry must still need it.
PENDING = {
    "test_db_read_errors_are_not_absent.py": "the i460 guard PR widens it and moves it to _rust_src in one change",
}


def _hits(text: str) -> list[str]:
    return [m.group(0) for p in STRIPS for m in p.finditer(text)]


def test_every_shared_case_holds():
    rows = json.loads(CASES.read_text())["cases"]
    assert len(rows) >= 6, "the shared table lost rows"
    bodies = stale = 0
    for c in rows:
        code = rs.own_code(c["src"])
        assert code == c["own_code"], f"{c['name']}: own_code"
        lines = rs.own_code_lines(c["src"])
        assert lines.count("\n") == c["src"].count("\n"), f"{c['name']}: own_code_lines keeps every line"
        for b in c["bodies"]:
            of = {"src": c["src"], "own_code": code}[b["of"]]
            assert rs.fn_body(of, b["marker"]) == b["body"], f"{c['name']}: fn_body({b['marker']})"
            bodies += 1
        for m in c["stale_in_own_code"]:
            with pytest.raises(AssertionError, match="this guard is stale"):
                rs.fn_body(code, m)
            stale += 1
    assert bodies >= 13 and stale >= 3, (bodies, stale)


def test_no_guard_strips_rust_test_code_itself():
    seen, bad = 0, []
    for p in sorted((REPO / "tests").rglob("*.py")):
        if p.name in (HERE, "_rust_src.py") or "fixtures" in p.parts:
            continue
        seen += 1
        hits = _hits(p.read_text())
        if p.name in PENDING:
            assert hits, f"{p.name} no longer strips by itself: drop its PENDING entry"
            continue
        if hits:
            bad.append(f"{p.relative_to(REPO)}: {hits}")
    assert seen >= 150, f"read only {seen} files: this guard is looking in the wrong place"
    assert not bad, "read Rust source through tests/_rust_src.py (own_code / own_code_lines / fn_body):\n  " + "\n  ".join(bad)


def test_the_matcher_sees_each_strip_shape():
    a = "#[cfg(" + "test)]"
    bad = [
        f'body = RS[: RS.index("{a}")]',
        f'shipped = src[:src.index("\\n{a}")]',
        f'code = text.split("{a}")[0]',
        f'text = f.read_text().split("{a}", 1)[0]',
        f'i = text.find("{a}")',
        f'kiosk.split("\\n{a}\\nmod tests", 1)[0]',
        f'if ln.strip() == "{a}":',
        f'if raw.lstrip().startswith("{a}"):',
        "def _strip_tests(text):",
        "def _strip_rust_test_modules(src):",
    ]
    good = [
        "code = rs.own_code(src)",
        f'assert swallowing_reads("fn f() {{}}\\n{a}\\nmod t {{ }}") == []',
        "# the first #[cfg" + "(test)] used to hide code",
    ]
    for s in bad:
        assert _hits(s), f"missed: {s}"
    for s in good:
        assert not _hits(s), f"flagged: {s}"
