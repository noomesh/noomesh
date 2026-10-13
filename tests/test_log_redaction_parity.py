# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The credential shapes the log path scrubs are declared in two languages.

The node-agent's log shipper scrubs every line at intake
(`node-agent-go/internal/logship/redact.go`, `shapes`) so neither its 0640
spill file nor the wire holds a secret; the gateway repeats the table on
ingest (`gateway-rust/src/redact.rs`, `SHAPES`, applied by
`routes/logs_ingest.rs::prepare_push`) for an agent that predates it. Go and
Rust cannot share the table, so they share a VECTOR:
`tests/fixtures/redaction_corpus.json` is loaded by both unit tests, and each
must reproduce every `expected` line, including the ones that must pass
through untouched. That is where the behaviour is proven; this guard proves
the declarations line up:

  1. the KINDS (`<redacted:KIND>`) the two tables emit are the same set, in
     the same order (the order is part of the contract: a placeholder is
     never re-wrapped only because the generic shapes run first);
  2. every kind appears in the corpus with at least one secret case, and the
     corpus carries must-not-touch lines of the classes that look like
     secrets (a 64-hex digest, a UUID, a plain key=value, a URL without a
     password), so a false-positive regression fails a unit test;
  3. both unit tests actually load the shared file (a copy pasted into one
     of them would pass its own test while the two drift);
  4. `docs/operating/monitoring.md` "What gets redacted" names exactly the
     kinds the code emits, and states the shape-based caveat;
  5. the shipper scrubs BEFORE its spill and its queue, and reports
     `redacted_total` in the heartbeat's `log_ship` the doc describes;
  6. the rows that carry a match predicate (`accept` in Go, `accept_for`
     in Rust: the bare and anchored shapes a regex alone cannot state
     without look-around) are the same set in both tables.

Planted 2026-09-28: `service-key` row removed from the Go table → (1) fails
here and the Go corpus test fails; the same row removed from the Rust table
→ (1) fails here and the Rust corpus test fails; the `aws-key` row removed
from the doc table → (4) fails.
Planted 2026-09-30: the `service-key` row removed from both
tables → both corpus tests fail on "service key as issued" and (4) fails;
the `aws-key` pattern widened with `|[0-9a-f]{40}` in both tables → the
Rust corpus test fails on the git-SHA must-not-touch lines; in Go the
AKIA/ASIA gate still hides it, so TestGatesNeverHideAMatch fails, and with
the gate widened too the Go corpus test fails on the same lines.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from tests.source_scan import executable_source

ROOT = Path(__file__).resolve().parents[1]
GO = ROOT / "node-agent-go/internal/logship/redact.go"
GO_TEST = ROOT / "node-agent-go/internal/logship/redact_test.go"
GO_SHIPPER = ROOT / "node-agent-go/internal/logship/shipper.go"
RS = ROOT / "gateway-rust/src/redact.rs"
RS_INGEST = ROOT / "gateway-rust/src/routes/logs_ingest.rs"
CORPUS = ROOT / "tests/fixtures/redaction_corpus.json"
MONITORING_MD = ROOT / "docs/operating/monitoring.md"

PLACEHOLDER = re.compile(r"<redacted:([a-z-]+)>")


def go_kinds() -> list[str]:
    src = executable_source(GO)
    table = src.split("var shapes = []shape{", 1)[1].split("\n}\n", 1)[0]
    kinds = re.findall(r'^\s*kind:\s*"([a-z-]+)",', table, re.M)
    assert kinds, "redact.go's `shapes` table declares no kinds — the parse found nothing"
    return kinds


def rust_kinds() -> list[str]:
    src = executable_source(RS)
    table = src.split("pub static SHAPES:", 1)[1].split("\n});\n", 1)[0]
    kinds = re.findall(r'kind:\s*"([a-z-]+)",', table)
    assert kinds, "redact.rs's `SHAPES` table declares no kinds — the parse found nothing"
    return kinds


def corpus() -> list[dict]:
    doc = json.loads(CORPUS.read_text())
    cases = doc["cases"]
    assert len(cases) >= 20, f"the corpus holds {len(cases)} cases; too thin to be real"
    for c in cases:
        assert {"name", "line", "expected"} <= set(c) <= {"name", "line", "expected", "waiver"}, c
        # A secret case is a fabricated sample the CI leak gate would flag;
        # it waives itself on its own line, with the reason the gate demands.
        if c["line"] != c["expected"]:
            assert c.get("waiver", "").startswith("leak-ok: "), f"{c['name']}: a secret case needs its leak-gate waiver"
    return cases


def documented_kinds() -> tuple[list[str], str]:
    text = MONITORING_MD.read_text()
    assert "### What gets redacted" in text, "monitoring.md lost its 'What gets redacted' section"
    section = text.split("### What gets redacted", 1)[1].split("\n### ", 1)[0]
    rows = re.findall(r"^\| `([a-z-]+)` \|", section, re.M)
    assert rows, "the 'What gets redacted' table has no rows"
    return rows, section


def test_go_and_rust_emit_the_same_kinds_in_the_same_order():
    assert go_kinds() == rust_kinds(), (
        "the shipper's table and the gateway's table have drifted; both load "
        "tests/fixtures/redaction_corpus.json, so add the shape to both and a case to the corpus"
    )


def test_every_kind_has_a_secret_case_and_the_corpus_keeps_its_decoys():
    cases = corpus()
    kinds = set(go_kinds())
    emitted = {k for c in cases for k in PLACEHOLDER.findall(c["expected"])}
    assert emitted <= kinds, f"the corpus expects kinds no table emits: {sorted(emitted - kinds)}"
    assert kinds <= emitted, f"kinds with no corpus case: {sorted(kinds - emitted)}"
    clean = [c["line"] for c in cases if c["line"] == c["expected"]]
    assert len(clean) >= 8, f"only {len(clean)} must-not-touch lines"
    # The decoy classes: each is something a careless shape would eat.
    decoys = {
        "a 64-hex digest": re.compile(r"[0-9a-f]{64}"),
        "a uuid": re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
        "level=info": re.compile(r"level=info"),
        "a key=value that is not secret-ish": re.compile(r"\bkey=value\b"),
        "a URL without a password": re.compile(r"https://[a-z.]+(:\d+)?/"),
        "a timestamp": re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),
        "prose containing 'token'": re.compile(r"tokens=|token_count="),
    }
    for what, rx in decoys.items():
        assert any(rx.search(line) for line in clean), f"the corpus has no untouched line holding {what}"
    # And no secret case leaves any of the credential it started with in
    # a recognisable run: the placeholder carries only the kind.
    for c in cases:
        if c["line"] == c["expected"]:
            continue
        for ph in PLACEHOLDER.finditer(c["expected"]):
            assert ph.group(0) == f"<redacted:{ph.group(1)}>"


def test_both_unit_tests_load_the_shared_corpus():
    go = executable_source(GO_TEST)
    assert "tests/fixtures/redaction_corpus.json" in go, "the Go test no longer reads the shared corpus"
    assert "os.ReadFile" in go and "corpusPath" in go
    rs = executable_source(RS)
    assert 'include_str!("../../tests/fixtures/redaction_corpus.json")' in rs, (
        "the Rust test no longer reads the shared corpus"
    )


def test_the_operator_doc_names_exactly_the_kinds_and_the_caveat():
    rows, section = documented_kinds()
    assert rows == go_kinds(), (
        f"monitoring.md's 'What gets redacted' table ({rows}) is not the code's table ({go_kinds()})"
    )
    assert "shape" in section.lower() and "ships" in section, (
        "the doc must say redaction is shape-based and that an unnamed shape ships"
    )
    assert "redacted_total" in MONITORING_MD.read_text(), "the heartbeat field is undocumented"


def test_the_shipper_scrubs_before_the_queue_and_the_spill_and_reports_it():
    src = executable_source(GO_SHIPPER)
    offer = src.split("func (s *Shipper) Offer(", 1)[1].split("\n}\n", 1)[0]
    redact_at = offer.find("RedactAfter(prev, e.Line)")
    assert redact_at >= 0, "Offer no longer calls RedactAfter (Redact with the stream's PEM context)"
    lock_at = offer.find("s.mu.Lock()")
    spill_at = offer.find("s.spill.write(")
    assert 0 <= redact_at < lock_at, "Redact must run before the entry is queued"
    assert 0 <= redact_at < spill_at, "Redact must run before the entry is spilled"
    state = src.split("func (s *Shipper) State()", 1)[1].split("\n}\n", 1)[0]
    assert '"redacted_total"' in state, "log_ship no longer reports redacted_total"


def test_the_gateway_scrubs_inside_prepare_push_and_counts_it():
    src = executable_source(RS_INGEST)
    body = src.split("pub fn prepare_push(", 1)[1].split("\n}\n", 1)[0]
    assert "crate::redact::scrub_secrets_after(prev, line)" in body, "prepare_push no longer scrubs the line"
    assert body.find("scrub_secrets") < body.find("out_values.push"), "the scrub must precede the push into the body"
    assert "noo_logs_ingest_redacted_total" in src, "the per-node redaction counter is gone"


def go_accept_kinds() -> set[str]:
    src = executable_source(GO)
    table = src.split("var shapes = []shape{", 1)[1].split("\n}\n", 1)[0]
    rows = re.split(r"^\t\{\n", table, flags=re.M)
    out = set()
    for row in rows:
        k = re.search(r'^\s*kind:\s*"([a-z-]+)",', row, re.M)
        if k and re.search(r"^\s*accept:\s", row, re.M):
            out.add(k.group(1))
    return out


def rust_accept_kinds() -> set[str]:
    src = executable_source(RS)
    body = src.split("fn accept_for(kind: &str)", 1)[1].split("\n}\n", 1)[0]
    return set(re.findall(r'^\s*"([a-z-]+)" => Some\(', body, re.M))


def test_both_tables_attach_a_match_predicate_to_the_same_rows():
    go, rs = go_accept_kinds(), rust_accept_kinds()
    assert go, "no Go row declares an accept predicate — the parse found nothing"
    assert go == rs, f"accept predicates drifted: Go {sorted(go)} vs Rust {sorted(rs)}"
    assert go <= set(go_kinds()), f"accept names kinds the table lacks: {sorted(go - set(go_kinds()))}"
