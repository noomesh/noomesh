# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The add-on caller credential is spelled the same in four places.

The gateway mints a key under one consumer name, a Postgres view selects the
rows whose consumer starts with a prefix, an add-on reads four header names,
and `docs/development/addons.md` is what an add-on author implements from.
Nothing links them at build time: the Rust compiles, the migration applies,
the doc renders, and a rename on any one side leaves the add-on verifying a
row that will never exist — which reads exactly like "the gateway did not
call me".

Static parse on purpose: no gateway, no DB, no Rust toolchain.

Comments are stripped before anything is located. This file's three
predecessors (`test_graph_recluster_rail`, `test_graph_tool_formatters`,
`test_conversation_scope`) each shipped a guard that passed or failed on the
prose beside the code rather than the code.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTH_RS = ROOT / "gateway-rust/src/addon_auth.rs"
PROXY_RS = ROOT / "gateway-rust/src/addon_proxy.rs"
# The Alembic chain is frozen at 046; schema authored after the cut-over lives
# in the Rust mesh chain as SQL. This view is revision 077 there.
MIGRATION = ROOT / "gateway-rust/src/mesh_migrate.rs"
DOC = ROOT / "docs/development/addons.md"
VIEW = "noo_addon_caller_keys"


def _rust_code(path: Path) -> str:
    """Source with `//` line comments removed."""
    return "\n".join(re.sub(r"//.*", "", line) for line in path.read_text().splitlines())


def _rust_const(path: Path, name: str) -> str:
    m = re.search(rf'const {name}: &str = "([^"]+)"', _rust_code(path))
    assert m, f"{name} not found in {path.name}"
    return m.group(1)


def _view_sql() -> str:
    """The body of the revision that creates the verify view."""
    code = _rust_code(MIGRATION)
    start = code.index('revision: "077_addon_caller_verify_view"')
    end = code.index('"#,', code.index("CREATE OR REPLACE VIEW", start))
    return code[start:end]


def test_the_gateways_consumer_name_matches_the_views_prefix():
    consumer = _rust_const(AUTH_RS, "CALLER_CONSUMER")
    # The literal is doubled inside the revision's dollar-quoted EXECUTE.
    m = re.search(r"starts_with\(consumer, '+([a-z-]+:)'+\)", _view_sql())
    assert m, "the view no longer filters on a consumer prefix"
    prefix = m.group(1)
    assert consumer.startswith(prefix), (
        f"the gateway mints {consumer!r} but the view selects {prefix!r}* — "
        "no add-on would ever find the row"
    )


def test_the_view_the_migration_creates_is_the_one_the_doc_tells_authors_to_read():
    assert VIEW in _view_sql(), f"revision 077 no longer creates {VIEW!r}"
    assert VIEW in DOC.read_text(), (
        f"revision 077 creates {VIEW!r}; the add-on guide names a different view"
    )


def test_the_view_is_not_in_the_frozen_alembic_chain():
    """New schema goes in the Rust mesh chain. An Alembic revision above 046
    fails `baseline_revision_matches_the_generated_dump`, which is how this
    landed in the wrong chain the first time."""
    versions = ROOT / "src/noomesh/db/migrations/versions"
    stray = [p.name for p in versions.glob("0*.py") if p.name[:3] > "046"]
    assert not stray, f"Alembic is frozen at 046; move these to mesh_migrate.rs: {stray}"


def test_every_requester_header_is_documented():
    code = _rust_code(PROXY_RS)
    headers = dict(re.findall(r'const (REQUESTER_\w+): &str = "([^"]+)"', code))
    assert headers, "no requester headers found — did they move?"
    doc = DOC.read_text().lower()
    for name, value in headers.items():
        assert value in doc, (
            f"{name} = {value!r} is sent to every add-on but appears nowhere in "
            "the add-on guide, which is what an author implements from"
        )


def test_the_headers_are_lowercase_so_they_survive_http2():
    code = _rust_code(PROXY_RS)
    for name, value in re.findall(r'const (REQUESTER_\w+): &str = "([^"]+)"', code):
        assert value == value.lower(), f"{name} must be lowercase"


def test_the_caller_key_is_minted_with_no_scopes():
    """It names a caller. A key carrying the four inference scopes would also
    authenticate at `/api/external/*`, which is a different boundary."""
    code = _rust_code(AUTH_RS)
    assert "'[]'::jsonb" in code, (
        "the caller key must be inserted with empty scopes"
    )


def test_the_previous_key_is_retired_before_the_new_one_is_published():
    """Insert-then-deactivate would leave two live tokens across a crash, one
    of which no process holds."""
    code = _rust_code(AUTH_RS)
    update = code.index("UPDATE noo_service_keys")
    insert = code.index("INSERT INTO noo_service_keys")
    assert update < insert, "retire the old row first; that failure mode is closed"


def test_the_view_exposes_no_bound_user_or_quota():
    """The columns are the contract. `user_id` in particular: these keys name a
    program, and who the call acts for rides in the headers, bound to the same
    bearer."""
    sql = _view_sql()
    select = sql[sql.index("CREATE OR REPLACE VIEW") : sql.index("view_ :=")]
    for forbidden in ("user_id", "user_uuid", "rpm_limit", "note", "last_used_at"):
        assert forbidden not in select, f"the verify view must not expose {forbidden}"


def test_the_published_hash_is_of_the_prefixed_token_as_presented():
    """an earlier change: the key carries `noo-ak-` so a scrubber can see it, and
    the row's hash is of the WHOLE string. An add-on hashes what it was
    shown; hashing a stripped value here would make every add-on built before
    the prefix refuse the gateway."""
    code = _rust_code(AUTH_RS)
    assert _rust_const(AUTH_RS, "KEY_PREFIX") == "noo-ak-"
    mint = code.split("fn mint()", 1)[1].split("\n}\n", 1)[0]
    assert "KEY_PREFIX" in mint, "mint() no longer puts the prefix on the key"
    init = code.split("pub async fn init(", 1)[1].split("\n}\n", 1)[0]
    assert re.search(r"let token = mint\(\);\s*let hash = crate::service_keys::sha256_hex\(&token\);", init), (
        "init must hash the token exactly as it will be presented, prefix included"
    )
    assert "strip_prefix" not in init
