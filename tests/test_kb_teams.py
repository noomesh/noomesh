# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Policy tests for the KB team registry handlers (pure paths only —
validation runs before any DB access).

Handler-level create/delete tests removed 2026-07-18 — those handlers
were ported to native Rust (gateway-rust routes/users.rs, PR #206); the
regex itself is still shared via worker_pool."""
from noomesh.gateway.worker_pool import _TEAM_NAME_RE


def test_team_name_pattern():
    assert _TEAM_NAME_RE.match("research")
    assert _TEAM_NAME_RE.match("ml-ops_2")
    assert not _TEAM_NAME_RE.match("Research")      # uppercase
    assert not _TEAM_NAME_RE.match("-lead")         # must start alphanumeric
    assert not _TEAM_NAME_RE.match("a" * 65)        # too long
    assert not _TEAM_NAME_RE.match("")
