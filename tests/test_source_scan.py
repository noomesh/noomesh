# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The prose-stripper must strip prose and keep code.

Every one of these is a real failure that happened, reduced. If this helper
is wrong the tests that depend on it are wrong in the direction that matters
least visibly: they pass.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.source_scan import executable_source


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body)
    return p


# ── the four real failures ───────────────────────────────────────────────


def test_python_docstring_is_stripped(tmp_path: Path):
    """noo-evolve's baseline: the docstring says it must not call create_all."""
    p = _write(
        tmp_path,
        "mig.py",
        '"""FROZEN DDL, NOT create_all(). A baseline that follows the models..."""\n'
        "def upgrade():\n"
        '    op.execute("CREATE TABLE x (id int)")\n',
    )
    code = executable_source(p)
    assert "create_all" not in code, "the module docstring survived"
    assert "CREATE TABLE x" in code, "the DDL string must survive — it is the code"


def test_python_function_docstring_is_stripped(tmp_path: Path):
    p = _write(
        tmp_path,
        "f.py",
        "def f():\n"
        '    """Never issue ALTER ROLE here."""\n'
        '    run("GRANT USAGE")\n',
    )
    code = executable_source(p)
    assert "ALTER ROLE" not in code
    assert "GRANT USAGE" in code


def test_rust_line_and_block_comments_are_stripped(tmp_path: Path):
    """role_provision.rs: the module doc explains the ALTER ROLE rule."""
    p = _write(
        tmp_path,
        "r.rs",
        "//! no chain ever issues ALTER ROLE ... PASSWORD\n"
        "/* also ALTER ROLE in a block */\n"
        "// and ALTER ROLE in a line comment\n"
        'let q = "CREATE ROLE x LOGIN";\n',
    )
    code = executable_source(p)
    assert "ALTER ROLE" not in code
    assert "CREATE ROLE x LOGIN" in code


def test_shell_comments_are_stripped(tmp_path: Path):
    """pg-privilege-dump.sh: the header says it never reads rolpassword."""
    p = _write(
        tmp_path,
        "s.sh",
        "# The password is never read: rolpassword is not selected here.\n"
        "psql -c 'SELECT rolname FROM pg_roles'\n",
    )
    code = executable_source(p)
    assert "rolpassword" not in code
    assert "SELECT rolname" in code


# ── the properties that keep it honest ───────────────────────────────────


def test_strings_survive_because_the_match_is_usually_in_one(tmp_path: Path):
    """This does not parse away string literals, deliberately.

    The forbidden text is nearly always INSIDE a string — SQL, a shell
    command, a path. A stripper that removed them would make every check
    vacuous while still passing.
    """
    p = _write(tmp_path, "q.py", 'sql = "ALTER ROLE noo PASSWORD \'x\'"\n')
    assert "ALTER ROLE" in executable_source(p)


def test_a_python_file_that_does_not_parse_still_returns_something(tmp_path: Path):
    """A syntax error belongs to a real test, not to this helper."""
    p = _write(tmp_path, "broken.py", "# comment\ndef (: oops\n")
    out = executable_source(p)
    assert "comment" not in out
    assert "oops" in out


def test_dockerfile_is_recognised_by_name(tmp_path: Path):
    p = _write(
        tmp_path,
        "Dockerfile",
        "# PYTHONPATH is gone; nothing imports the tree\nENV FOO=1\n",
    )
    code = executable_source(p)
    assert "PYTHONPATH" not in code
    assert "ENV FOO=1" in code


def test_unknown_suffix_falls_back_rather_than_raising(tmp_path: Path):
    p = _write(tmp_path, "notes.txt", "# hidden\nvisible\n")
    assert executable_source(p) == "visible"


@pytest.mark.parametrize("name", ["x.py", "x.rs", "x.sh", "Dockerfile"])
def test_code_is_never_removed(tmp_path: Path, name: str):
    """Over-stripping is the dangerous failure: it hides real matches."""
    p = _write(tmp_path, name, "KEEPME\n")
    assert "KEEPME" in executable_source(p)
