# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""Every `noo onboard --only <sections>` we hand a user reaches a real step.

Remedies, closing lines, docs and launcher messages name `noo onboard --only
<section>`. Two ways that used to do nothing:

* on a configured host the idempotent-install guard answered it ("nothing to
  do" with --ci, "Reconfigure this installation?" defaulting to No on a TTY),
  so `noo onboard --only model`, the remedy for a box with no chat model,
  placed nothing and exited 0 (rc.2 install matrix, 22.04 cell). The guard
  now applies to a bare re-run only (onboard/mod.rs rerun_guard_applies);
* a section name the parser does not know is a usage error. `--only
  security` (the PKI and every service leaf are the `enrollment` step) sat in
  six messages in provision.rs, cluster_verify.rs and onboard/steps.rs:
  test_onboard_only_sections_are_real.py scans docs/ only, so the code that
  prints the remedy was never read. This scans the code, the scripts, docs/
  and the README.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ONBOARD = ROOT / "noo-cli" / "src" / "onboard" / "mod.rs"
SCAN = [ROOT / "noo-cli" / "src", ROOT / "gateway-rust" / "src", ROOT / "scripts", ROOT / "docs", ROOT / "README.md"]
REMEDY = re.compile(r"noo onboard --only ([a-z]+(?:,[a-z]+)*)")


def _valid_sections() -> set[str]:
    m = re.search(r"const VALID: \[&str; \d+\] = \[(.*?)\];", ONBOARD.read_text(), re.S)
    assert m, "onboard's --only section list was not found: this test checks nothing"
    return set(re.findall(r'"([a-z]+)"', m.group(1)))


def _remedies() -> list[tuple[str, str]]:
    found = []
    for base in SCAN:
        files = [base] if base.is_file() else [p for p in base.rglob("*") if p.is_file() and p.suffix in {".rs", ".sh", ".md", ".py"}]
        for f in files:
            for m in REMEDY.finditer(f.read_text(errors="replace")):
                found.append((f"{f.relative_to(ROOT)}", m.group(1)))
    return found


def test_every_remedy_names_sections_the_parser_knows():
    valid = _valid_sections()
    remedies = _remedies()
    assert len(remedies) > 10, "fewer remedies than expected: the scan is broken"
    bad = [(f, s) for f, secs in remedies for s in secs.split(",") if s not in valid]
    assert not bad, f"unknown --only sections (valid: {sorted(valid)}): {bad}"


def test_the_first_model_remedy_is_among_them():
    assert ("model" in {s for _, secs in _remedies() for s in secs.split(",")}), "the first-model remedy is not named anywhere"


def _rerun_safe() -> set[str]:
    m = re.search(r"pub\(crate\) const RERUN_SAFE: \[&str; \d+\] = \[(.*?)\];", ONBOARD.read_text(), re.S)
    assert m, "RERUN_SAFE was not found"
    return set(re.findall(r'"([a-z]+)"', m.group(1)))


def test_the_first_model_remedy_runs_without_reconfigure():
    """`noo onboard --only model` (verify, onboard's closing line, README) is a
    targeted re-run: the guard does not answer it on a configured host."""
    src = ONBOARD.read_text()
    assert "model" in _rerun_safe()
    m = re.search(r"pub\(crate\) fn rerun_guard_applies\([^)]*\) -> bool \{(.*?)\n\}", src, re.S)
    assert m and "RERUN_SAFE.contains" in m.group(1), m.group(1) if m else "rerun_guard_applies was not found"
    assert "if rerun_guard_applies(reconfigure, &ctx.skip.only, is_configured(ctx)) {" in src


def test_every_other_remedy_section_is_refused_loudly_not_answered_nothing_to_do():
    """A remedy naming a section that re-applies settings still needs
    --reconfigure on a configured host; under --ci it is refused with exit 1
    and the exact command, never "nothing to do" with exit 0."""
    src = ONBOARD.read_text()
    i = src.index("if ctx.non_interactive && !ctx.skip.only.is_empty() {")
    j = src.index("nothing to do.", i)
    assert "return 1;" in src[i:j] and "noo onboard --reconfigure --only" in src[i:j]
