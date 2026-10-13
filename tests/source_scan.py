# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Read a source file's EXECUTABLE part, with prose removed.

WHY THIS EXISTS

A recurring test shape here is "this file must never contain X" — no
`ALTER ROLE`, no `create_all`, no `rolpassword`, no `GRANT ... CREATE ON
SCHEMA`. The natural implementation reads the file and searches it, and that
implementation is wrong in a specific, repeatable way: **a well-commented file
explains the rule it obeys**, so the scan matches the documentation of the
rule rather than a breach of it.

That failed four times in one day (2026-08-05), in three languages and both
comment styles — Rust `//`, shell `#`, and a Python docstring, which is not a
comment at all and survives `#`-stripping. Each time the fix was re-invented
locally and slightly differently.

`test_gateway_image_is_shell_less.py` had already learned it and says so:

    Instructions, not raw text: the stage's comments legitimately explain why
    PYTHONPATH is gone, and matching those would make the check
    unfixable-by-construction.

That last phrase is the real cost. A check that fails on its own explanation
cannot be satisfied except by deleting the explanation — so it pressures
whoever hits it to remove the comment that made the rule understandable.

USE THIS, don't re-roll it:

    from tests.source_scan import executable_source

    def test_never_alters_a_role():
        assert "ALTER ROLE" not in executable_source(SCRIPT).upper()

WHAT IT DOES NOT DO

It does not parse. Strings survive — deliberately, because the thing being
searched for is usually IN a string (SQL, a shell command, a path). Only
commentary is removed.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

#: Suffixes whose comments start at `#` and run to end of line. Dockerfiles and
#: YAML share the convention, which is why the map is by suffix AND by name.
_HASH_COMMENT = {".sh", ".bash", ".yml", ".yaml", ".toml", ".cfg", ".ini"}
_HASH_COMMENT_NAMES = {"Dockerfile"}

#: Suffixes with C-style comments.
_SLASH_COMMENT = {".rs", ".go", ".js", ".ts", ".c", ".h", ".java"}


def _strip_hash(text: str) -> str:
    """Drop whole-line `#` comments.

    Whole-line only. A trailing `#` inside a quoted string is not a comment,
    and this deliberately does not try to tell the difference — over-stripping
    would silently hide real matches, which is worse than the problem being
    solved.
    """
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def _strip_slash(text: str) -> str:
    """Drop `//` and `///` line comments and `/* ... */` blocks."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("//")
    )


def _strip_python(text: str) -> str:
    """Drop comments AND docstrings.

    Docstrings are the case that catches people: they are not comments, so
    `#`-stripping leaves them, and a module docstring explaining "this must
    never call create_all()" contains the forbidden phrase.

    Falls back to `#`-stripping if the file does not parse — a syntax error is
    the caller's problem to discover from a real test, not something to raise
    from a helper.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return _strip_hash(text)

    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            continue
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            del body[0]
    return ast.unparse(tree)


def executable_source(path: str | Path) -> str:
    """Return *path*'s contents with commentary removed.

    Dispatches on suffix, then on filename. An unrecognised type falls back to
    `#`-stripping, which is right more often than doing nothing and never
    removes code in a language that uses `#` for something else at line start.
    """
    p = Path(path)
    text = p.read_text()
    if p.suffix == ".py":
        return _strip_python(text)
    if p.suffix in _SLASH_COMMENT:
        return _strip_slash(text)
    if p.suffix in _HASH_COMMENT or p.name in _HASH_COMMENT_NAMES:
        return _strip_hash(text)
    return _strip_hash(text)
