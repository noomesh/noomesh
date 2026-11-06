# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A database read's error must not become "absent" on the request path.

The house bug class (i433, i434, i436, i437, and the #650 sweep): a read
whose error was turned into None / false / empty / a default with `.ok()`,
`.unwrap_or(..)` or `.unwrap_or_default()`. An error then reads as "no such
row":

- an ownership check was skipped (temporal facts),
- a hold filter was dropped (held documents came back),
- an operator's cap was lifted (placement fit), or
- a good key was refused as unknown (service keys).

This guard scans every file under `gateway-rust/src/` for a database read,
meaning a `.fetch_optional(` / `.fetch_one(` / `.fetch_all(` call or a
`crate::repo::` function, whose statement swallows the error at the top level
of its method chain. Test code is excluded through `tests/_rust_src.py`
(`own_code_lines`): every `#[cfg(test)]` item is removed whole, so code after
a test-only item is still read (i460 Finding 0). It used to cut each file at
its first `#[cfg(test)]` and scan only `routes/` and `coordinator/`, which hid
two routes sites and every site outside those two directories.

The sites that remain are PINNED per file below, each with its reason. Most
are best-effort or fail closed. The ones marked FINDING are not: they are
known defects, pinned so this guard can hold the line while each is fixed by
its own change. The rule is a ratchet:

- A count may only go DOWN. Lower it in the same change that removes a site.
- A NEW site fails this test. Propagate the error instead (`?`, `map_err` to
  a 503 that names it), or, for genuinely optional enrichment, match on it and
  log it at warn. A `match` that logs is not flagged; a bare default is.
"""
from __future__ import annotations

import re
from pathlib import Path

from tests import _rust_src as rs

ROOT = Path(__file__).resolve().parent.parent / "gateway-rust" / "src"

# file (relative to gateway-rust/src) -> swallowing DB reads still there, and why.
PINNED: dict[str, int] = {
    # annotate_backend_activity: placements and usage for the listing's
    # activity columns, documented best-effort (display only); and
    # node_task_holds, which logs at warn and leaves the field out (seen since
    # the scan reads past the first test-only item).
    "routes/cluster.rs": 3,
    # login: an unreadable disabled flag refuses (fail closed; audited as
    # account_disabled, the wrong cause).
    "routes/core.rs": 1,
    # TaskCheckpoint: the renewal is already refused; an unreadable flag only
    # skips the explicit stop (documented, i143 D).
    "routes/harness.rs": 1,
    # the wording of a pinned-chat refusal only.
    "routes/inference.rs": 1,
    # EXISTS checks answer "not found" on an error (fail closed, wrong cause),
    # plus the autonomy status's DB locations (display only).
    "routes/intelligence.rs": 3,
    # conversation preview, pagination total and avg rating (display), and
    # the DPO export's prompt read (drops the pair: fail closed, silent).
    "routes/memory.rs": 4,
    # api_kb_grants: the config snapshot records "no grants" (#247).
    "routes/users.rs": 1,
    # turn_number: only decides when a summary is regenerated.
    "coordinator/runtime.rs": 1,
    # Seen since the scan reads past the first test-only item (i460 Finding 0):
    # entity_cleanup_run's "is a recluster live" check answers yes on an error,
    # so the cleanup refuses and says "or could not be ruled out" (fail closed).
    "routes/knowledge.rs": 1,
    # Outside routes/ and coordinator/, seen since the scan covers all of src/.
    # wait_for_cluster_warm: an unreadable count keeps the startup wait going.
    "heartbeat_loop.rs": 1,
    # prune_restore_run: `remaining` reads -1 on an error (display only).
    "memory/provider.rs": 1,
    # user_role and effective_risk's saved-recipient read: an error leaves the
    # tool call at its base risk, so it needs approval (fail closed).
    "middleware.rs": 2,
    # OpCtx::still_live: an error answers "not live", so a destructive op
    # writes nothing (documented fail closed; reported as no longer wanted).
    "ops.rs": 1,
    # FINDING: emit_final_state drops the final state event on an unreadable
    # state, and is_addon_task reads an unreadable origin as core, so the
    # add-on's events are not routed to it.
    "task_events.rs": 2,
    # resolve_origin: an unreadable account is "not a person" (fail closed).
    "task_guard.rs": 1,
}

READ = re.compile(r"\.fetch_(?:optional|one|all)\s*\(|crate::repo::\w+::\w+\s*\(")
SWALLOWS = {"ok", "unwrap_or", "unwrap_or_default", "unwrap_or_else"}


def _close(text: str, i: int) -> int:
    """Index just past the parenthesis group opening at text[i] == '('."""
    depth = 0
    j = i
    while j < len(text):
        c = text[j]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return j + 1
        elif c == '"':
            j += 1
            while j < len(text) and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
        j += 1
    return len(text)


def _chain(text: str, i: int) -> list[str]:
    """The top-level method names chained after position i, up to the end
    of the expression (`;`, `?`, `{`, `,` or a closing bracket at depth 0)."""
    names: list[str] = []
    j = i
    while j < len(text):
        while j < len(text) and text[j] in " \t\r\n":
            j += 1
        if text.startswith(".await", j):
            names.append("await")
            j += len(".await")
            continue
        m = re.match(r"\.(\w+)\s*(?:::<[^>]*>)?\s*\(", text[j:])
        if not m:
            break
        names.append(m.group(1))
        j = _close(text, j + m.end() - 1)
    return names


def swallowing_reads(text: str) -> list[int]:
    """Line numbers of DB reads whose error is swallowed at the top level."""
    body = rs.own_code_lines(text)
    found = []
    for m in READ.finditer(body):
        open_paren = m.end() - 1
        names = _chain(body, _close(body, open_paren))
        if "await" not in names:
            continue
        after = names[names.index("await") + 1:]
        if any(n in SWALLOWS for n in after):
            found.append(body.count("\n", 0, m.start()) + 1)
    return found


def scan() -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for p in sorted(ROOT.rglob("*.rs")):
        if p.name.endswith("_tests.rs"):
            continue
        hits = swallowing_reads(p.read_text())
        if hits:
            out[str(p.relative_to(ROOT))] = hits
    return out


def test_no_new_db_read_turns_an_error_into_absent():
    found = scan()
    assert len(list(ROOT.rglob("*.rs"))) > 100, "the walk is broken, not the code"
    assert any("/" not in f for f in found), "the walk no longer reaches files outside routes/ and coordinator/"
    grew = {f: h for f, h in found.items() if len(h) > PINNED.get(f, 0)}
    assert not grew, (
        "a database read turns its error into absent/empty/default (new sites; "
        "propagate it, or match and log it): "
        + "; ".join(f"{f} lines {h} (pinned {PINNED.get(f, 0)})" for f, h in grew.items())
    )


def test_the_pins_are_not_stale():
    found = scan()
    stale = {f: n for f, n in PINNED.items() if len(found.get(f, [])) < n}
    assert not stale, f"a pinned site is gone: lower its count ({stale}, now {found})"


def test_the_scanner_sees_each_swallow_shape():
    # Each shape the class has taken, and the propagated forms beside them.
    bad = [
        'let x = sqlx::query_scalar("S").bind(a).fetch_optional(db).await.ok().flatten();',
        'let x = sqlx::query_as("S")\n    .fetch_all(&state.db)\n    .await\n    .unwrap_or_default();',
        "let x: bool = sqlx::query_scalar(\"S\").fetch_one(db).await.unwrap_or(false);",
        "let live = crate::repo::cluster::all_nodes(&state.db).await.map(|r| r.len()).unwrap_or_default();",
        "let o = crate::repo::cluster::overrides(&state.db, id).await.unwrap_or_else(|_| json!({}));",
    ]
    good = [
        'let x = sqlx::query_scalar("S").fetch_optional(db).await?;',
        'let x = sqlx::query_scalar("S").fetch_optional(db).await.map_err(|e| AppError::Unavailable(e.to_string()))?;',
        "let rows = crate::repo::cluster::all_nodes(&state.db).await.map(|r| r.len()).map_err(|e| e.to_string())?;",
        'let r = sqlx::query_scalar("S").fetch_one(db).await;\nmatch r { Ok(v) => v, Err(e) => { warn!(%e); 0 } }',
        # a default INSIDE a closure argument is not the read's error
        'let x = sqlx::query_scalar("S").fetch_all(db).await.map(|v: Vec<Option<i32>>| v.into_iter().map(|o| o.unwrap_or(0)).sum())?;',
    ]
    for src in bad:
        assert swallowing_reads(src), f"missed: {src}"
    for src in good:
        assert not swallowing_reads(src), f"flagged a propagated read: {src}"
    assert swallowing_reads("fn f() {}\n#[cfg(test)]\nmod t { fn g() { q.fetch_one(db).await.ok(); } }") == []


def test_a_read_after_a_test_only_item_is_still_seen():
    # i460 Finding 0: the old scan cut each file at its FIRST test-only item.
    attr = "#[cfg(" + "test)]"
    src = (
        "fn a() {}\n"
        + attr + "\nfn helper() {}\n"
        + "async fn b(db: &PgPool) -> bool {\n"
        + "    sqlx::query_scalar(\"S\").fetch_one(db).await.unwrap_or(false)\n"
        + "}\n"
    )
    assert swallowing_reads(src) == [5]
