# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The audit trail pages when it breaks (noomesh-internal i520).

A failed chain verify and a lost audit row were visible only to someone who
called `/api/security/audit/verify`. The gateway now exports them
(gateway-rust/src/audit_verify.rs, audit_spool.rs `metrics_text`) and
monitoring/alerts/security.yml pages on them at `severity: critical`, which
Alertmanager routes to the gateway's intake (i515b).

These checks keep the three halves joined: each rule is critical, each rule
reads a metric the gateway really emits, and the deliberate exclusion of
`source="head_export"` from the verify rule cannot turn into silence (that
path must keep paging through its own PERSISTING operator alert).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
RULES = REPO / "monitoring" / "alerts" / "security.yml"
SRC = REPO / "gateway-rust" / "src"
WANT = {"AuditChainVerifyFailed", "AuditSpoolRowsLost"}


def _rules() -> dict[str, dict]:
    doc = yaml.safe_load(RULES.read_text())
    out = {r["alert"]: r for g in doc["groups"] for r in g["rules"] if "alert" in r}
    assert out, f"read no rules from {RULES.relative_to(REPO)}: this guard is looking in the wrong place"
    return out


def _emitted() -> set[str]:
    """Metric names the gateway's audit modules declare with `# TYPE`."""
    names: set[str] = set()
    for f in ("audit_verify.rs", "audit_spool.rs"):
        names |= set(re.findall(r"# TYPE (noo_audit_[a-z_]+) (?:counter|gauge)", (SRC / f).read_text()))
    assert {"noo_audit_verify_failures_total", "noo_audit_spool_lost_total"} <= names, names
    return names


def test_both_audit_rules_are_critical_and_immediate():
    rules = _rules()
    assert WANT <= set(rules), f"missing {WANT - set(rules)} in {RULES.relative_to(REPO)}"
    for name in WANT:
        r = rules[name]
        assert r["labels"]["severity"] == "critical", f"{name} must be critical so Alertmanager sends it to the intake"
        assert r.get("for", "0m") == "0m", f"{name} must fire at once: one lost row or one broken row is the event"


def test_every_metric_the_rules_read_is_one_the_gateway_emits():
    emitted = _emitted()
    for name in WANT:
        read = set(re.findall(r"\b(noo_audit_[a-z_]+)\b", _rules()[name]["expr"]))
        assert read, f"{name} reads no noo_audit_* metric"
        assert read <= emitted, f"{name} reads {sorted(read - emitted)}, which the gateway does not emit (renamed?)"


def test_the_verify_rule_leaves_out_head_export_and_that_path_still_pages():
    expr = _rules()["AuditChainVerifyFailed"]["expr"]
    assert 'source="verify"' in expr and "head_export" not in expr, expr
    # The excluded path pages by itself: its raise() is a PERSISTING operator
    # alert and is still counted. Without this, the exclusion is silence.
    src = (SRC / "audit_head_export.rs").read_text()
    m = re.search(r"async fn raise\(.*?\n\}\n", src, re.S)
    assert m, "audit_head_export.rs has no raise(): the head-export alert is gone"
    body = m.group(0)
    assert ".persisting()" in body, "the head-export alert must stay PERSISTING (the verify rule leaves that path to it)"
    assert "send_operator_alert" in body, "the head-export raise() no longer sends its operator alert"
    assert "Source::HeadExport" in body, "the head-export failure is no longer counted"
    assert src.count("raise(state,") >= 2, "both regressed and rewritten must raise"


def test_the_gateway_serves_the_audit_metrics():
    core = (SRC / "routes" / "core.rs").read_text()
    handler = core.split("async fn prometheus_metrics", 1)[1].split("\nasync fn ", 1)[0]
    for call in ("crate::audit_verify::metrics_text()", "crate::audit_spool::metrics_text()"):
        assert call in handler, f"/metrics does not include {call}"
    integrity = (SRC / "audit_integrity.rs").read_text()
    verify_db = integrity.split("pub async fn verify_db", 1)[1].split("\n}\n", 1)[0]
    assert "crate::audit_verify::count_report(&report)" in verify_db, "verify_db no longer counts its verdict"
    main = (SRC / "main.rs").read_text()
    assert "audit_verify::spawn(" in main, "the periodic verify is not started, so the verify rule could never fire on its own"
