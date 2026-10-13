# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The privilege snapshot must cover the plane the schema gates cannot see.

Both equivalence gates dump `--no-owner --no-privileges` on both sides, so
roles, ownership and grants are invisible to them. That blindness is why the
sqlx cutover shipped with no login roles, none of `noo_app`'s 348 grants and
the ownership of 34 tables missing, while both gates reported IDENTICAL.

`scripts/pg-privilege-dump.sh` is the replacement for the compensating control
that an earlier change deletes (`role_provision.rs`'s reconciliation and
its pinned lists). These tests check the script's SHAPE — that it still asks
about every plane, and that it never asks for a password. They cannot check
its output, which needs a database; that is the gate's job once B′ makes the
two sides comparable.
"""
from __future__ import annotations

import re
from pathlib import Path

from tests.source_scan import executable_source

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "pg-privilege-dump.sh"

# Each plane, and what its absence would let through. Losing one of these is
# how the blind spot reappears somewhere new.
REQUIRED_SECTIONS = {
    "== roles ==": "a missing login role — the 2026-08-04 failure",
    "== schemas ==": "a schema owned by the wrong system",
    "== table owners ==": "ownership drift, invisible to every schema diff",
    "== table grants ==": "a role that cannot read its own tables",
    "== schema privileges ==": "CREATE held by a runtime role",
    "== default privileges ==": "new tables unreachable by the runtime role",
}


def _body() -> str:
    return SCRIPT.read_text()


def _code() -> str:
    """The script with commentary removed.

    Scanning raw text matches the script's own PROSE — its header explains
    that it never reads a password and that comparison is the caller's job,
    so a naive search finds both phrases and fails on the documentation of
    the rule rather than a breach of it. See `tests/source_scan.py`, which
    exists because that mistake landed four times in one day.
    """
    return executable_source(SCRIPT)


def test_the_script_exists_and_is_executable():
    assert SCRIPT.exists(), f"{SCRIPT} is missing"
    assert SCRIPT.stat().st_mode & 0o111, "must be executable to be usable in a gate"


def test_every_plane_is_covered():
    body = _body()
    for section, why in REQUIRED_SECTIONS.items():
        assert section in body, f"{section} missing — that plane goes unseen: {why}"


def test_it_never_reads_a_password():
    """`rolpassword` must not appear, in any form.

    The snapshot is meant to be pasted into an issue, a PR, or a terminal
    someone is sharing. It reports that a role EXISTS with the right
    attributes; a hash in that output would be a credential in a place nobody
    treats as sensitive.
    """
    assert not re.search(r"rolpassword", _code(), re.IGNORECASE), (
        "the privilege snapshot must never select rolpassword — its output is "
        "meant to be shareable"
    )


def test_output_is_ordered_so_a_diff_means_something():
    """Every query sorts. An unordered dump diffs against itself."""
    body = _body()
    selects = [s for s in body.split('q "') if s.strip().upper().startswith("SELECT")]
    assert selects, "no queries found — has the script been restructured?"
    for sel in selects:
        stmt = sel.split('"')[0]
        assert "ORDER BY" in stmt.upper(), (
            f"a query without ORDER BY makes the snapshot undiffable:\n{stmt[:120]}"
        )


def test_it_does_not_compare():
    """Printing and comparing are deliberately separate.

    What SHOULD match differs by context — two databases built the same way
    must match exactly, while a chain-built and a dump-restored one
    legitimately differ on owner until B′ lands. A script that hard-coded one
    answer would be wrong half the time, so the comparison belongs to the
    caller.
    """
    assert "diff " not in _code(), (
        "this script prints a snapshot; comparison is the caller's job"
    )
