# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The install matrix's WARN ratchet (noomesh-internal i1098): a fresh
install's verify may not show more WARN rows than its cell's ceiling, nor a
WARN row the ceiling does not name, and the ceiling only ever goes down."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RATCHET = ROOT / "scripts" / "install-cell" / "ratchet.py"
CEILING = ROOT / "scripts" / "install-cell" / "warn-ratchet.json"
RUN_SH = ROOT / "scripts" / "install-cell" / "run.sh"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R = _load("install_cell_ratchet", RATCHET)


def row(name, verdict, tier=None):
    return {"id": name.replace(" ", "_"), "name": name, "verdict": verdict, "detail": "", "remedy": None, "tier": tier}


def verify(controller=(), node=(), seats=None):
    """The `noo --json cluster verify` shape (noo-cli cluster_verify.rs:
    checks_json / seats_json): controller.checks, nodes[].checks, seats[].checks."""
    v = {"ok": True, "starting": False, "stack_tag": "stack-v0.0.0",
         "controller": {"ok": True, "checks": list(controller)},
         "nodes": [{"node": "node_a", "ok": True, "checks": list(node)}],
         "seats": seats if seats is not None else [], "summary": "", "next": []}
    return v


BASE_VERIFY = verify(controller=[row("holds", "warn", "later"), row("off-site backup", "warn", "later"),
                                 row("gateway", "ok")],
                     node=[row("ollama models", "warn"), row("tunnel", "ok")])
BASE_ROWS = ["controller:holds", "controller:off-site backup", "node:ollama models"]


def ceiling(cell="c", max_warn=3, rows=BASE_ROWS, measured="0.6.29-rc.2 run 1"):
    return {"cells": {cell: {"max_warn": max_warn, "rows": list(rows) if rows is not None else None,
                             "measured": measured, "why": "test"}}}


def as_log(v: dict) -> str:
    # what step() writes: stderr may come first, then the JSON as printed
    return "warning: a line on stderr\n" + json.dumps(v) + "\n"


def run_judge(tmp_path, v, ceil, cell="c", row_lines=False):
    """(exit, lines); the per-row status lines only when row_lines."""
    log = tmp_path / "probe-verify-json.log"
    log.write_text(as_log(v) if v is not None else "error: gateway unreachable\n")
    cf = tmp_path / "ceiling.json"
    cf.write_text(json.dumps(ceil))
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    r = subprocess.run([sys.executable, str(RATCHET), "judge", cell, str(log), "--ceiling", str(cf)],
                       capture_output=True, text=True, encoding="utf-8", env=env, timeout=60)
    lines = r.stdout.strip().splitlines()
    return r.returncode, lines if row_lines else [l for l in lines if not l.startswith("RATCHET ROW: ")]


# ── the judge, on canned verify JSON ────────────────────────────────────────

def test_pass_when_equal(tmp_path):
    rc, lines = run_judge(tmp_path, BASE_VERIFY, ceiling())
    assert rc == 0, lines
    assert lines == ["RATCHET PASS: 3 WARN ≤ 3 (rows: controller:holds, controller:off-site backup, node:ollama models)"]


def test_pass_when_fewer_and_says_lower_it(tmp_path):
    v = verify(controller=[row("holds", "warn"), row("off-site backup", "ok")], node=[row("ollama models", "warn")])
    rc, lines = run_judge(tmp_path, v, ceiling())
    assert rc == 0, lines
    assert lines[0] == "RATCHET NOTE: lower the ceiling: controller:off-site backup gone"
    assert lines[-1].startswith("RATCHET PASS: 2 WARN ≤ 3")


def test_fail_when_the_count_rises(tmp_path):
    # one more instance of an allowed row (a second node's ollama models)
    v = json.loads(json.dumps(BASE_VERIFY))
    v["nodes"].append({"node": "node_b", "ok": True, "checks": [row("ollama models", "warn")]})
    rc, lines = run_judge(tmp_path, v, ceiling())
    assert rc == 1, lines
    assert lines == ["RATCHET FAIL: 4 WARN > 3"]


def test_fail_on_a_new_row_name_even_at_an_equal_count(tmp_path):
    # one fixed (ollama models) + one new (tunnel): 3 == 3, still a FAIL
    v = verify(controller=[row("holds", "warn"), row("off-site backup", "warn")],
               node=[row("ollama models", "ok"), row("tunnel", "warn")])
    rc, lines = run_judge(tmp_path, v, ceiling())
    assert rc == 1, lines
    assert "RATCHET FAIL: new WARN row(s): node:tunnel" in lines
    assert "RATCHET NOTE: lower the ceiling: node:ollama models gone" in lines
    assert not any(l.startswith("RATCHET PASS") for l in lines)
    assert lines[-1].startswith("RATCHET FAIL"), "the step record takes the last line as the error"


def test_both_fails_print_when_both_apply(tmp_path):
    v = json.loads(json.dumps(BASE_VERIFY))
    v["controller"]["checks"].append(row("at-rest swap", "warn", "later"))
    rc, lines = run_judge(tmp_path, v, ceiling())
    assert rc == 1
    assert lines == ["RATCHET FAIL: 4 WARN > 3", "RATCHET FAIL: new WARN row(s): controller:at-rest swap"]


def test_note_while_the_ceiling_is_unmeasured(tmp_path):
    rc, lines = run_judge(tmp_path, BASE_VERIFY, ceiling(max_warn=None, rows=None, measured=None))
    assert rc == 0
    assert len(lines) == 1 and lines[0].startswith("RATCHET NOTE: no measured ceiling for c yet")
    assert "measured now: 3 WARN" in lines[0] and '"node:ollama models"' in lines[0], "the baseline to copy"
    # a cell the file does not list at all reads the same way
    rc, lines = run_judge(tmp_path, BASE_VERIFY, ceiling(cell="other"))
    assert rc == 0 and lines[0].startswith("RATCHET NOTE: no measured ceiling for c yet")


def test_a_later_tiered_ok_row_is_not_a_warn(tmp_path):
    # #1458: "default chat" is OK with tier "later" on a CPU-only one-box
    v = json.loads(json.dumps(BASE_VERIFY))
    v["controller"]["checks"].append(row("default chat", "ok", "later"))
    v["nodes"][0]["checks"].append(row("default chat", "ok", "later"))
    assert R.warn_rows(v) == R.warn_rows(BASE_VERIFY)
    rc, lines = run_judge(tmp_path, v, ceiling())
    assert rc == 0 and lines[-1].startswith("RATCHET PASS: 3 WARN ≤ 3"), lines


def test_seats_and_nodes_are_counted(tmp_path):
    v = verify(controller=[row("holds", "warn")], node=[row("ollama models", "warn")],
               seats=[{"seat": "seat_a", "ok": True, "checks": [row("seat display", "warn"), row("seat link", "ok")]}])
    assert sorted(R.warn_rows(v)) == ["controller:holds", "node:ollama models", "seat:seat display"]
    rc, lines = run_judge(tmp_path, v, ceiling(max_warn=2, rows=["controller:holds", "node:ollama models"]))
    assert rc == 1
    assert lines == ["RATCHET FAIL: 3 WARN > 2", "RATCHET FAIL: new WARN row(s): seat:seat display"]
    # seats null (the gateway did not answer the list) is no crash and no WARN
    v["seats"] = None
    assert sorted(R.warn_rows(v)) == ["controller:holds", "node:ollama models"]


def test_only_the_verdict_counts_never_the_text():
    v = verify(controller=[row("WARN in the name", "ok"), row("x", "fail"), row("y", "starting")],
               node=[row("z", "accepted")])
    v["controller"]["checks"][0]["detail"] = "WARN: looks like a warning"
    assert R.warn_rows(v) == []


def test_a_measured_ceiling_with_no_verify_json_fails(tmp_path):
    rc, lines = run_judge(tmp_path, None, ceiling())
    assert rc == 1 and lines == ["RATCHET FAIL: no verify JSON to judge for c"]


def test_the_skip_note():
    r = subprocess.run([sys.executable, str(RATCHET), "skip", "macos-15-node", "a node-only cell"],
                       capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0 and r.stdout.strip() == "RATCHET NOTE: macos-15-node not judged: a node-only cell"


# ── the ceiling only goes down ─────────────────────────────────────────────

def test_only_down_refuses_a_rise_and_an_added_row():
    base = ceiling()
    assert R.only_down(base, ceiling()) == []
    assert R.only_down(base, ceiling(max_warn=2, rows=BASE_ROWS[1:])) == [], "lowering is the point"
    up = R.only_down(base, ceiling(max_warn=4))
    assert len(up) == 1 and "max_warn 3 -> 4" in up[0]
    swapped = R.only_down(base, ceiling(rows=BASE_ROWS[:2] + ["node:tunnel"]))
    assert len(swapped) == 1 and "rows added: node:tunnel" in swapped[0], "a swap at an equal count"
    assert "removed" in R.only_down(base, {"cells": {}})[0]
    assert "unmeasured" in R.only_down(base, ceiling(max_warn=None, rows=None, measured=None))[0]


def test_the_first_measurement_and_a_new_cell_are_free():
    unmeasured = ceiling(max_warn=None, rows=None, measured=None)
    assert R.only_down(unmeasured, ceiling(max_warn=24)) == []
    new_cell = ceiling()
    new_cell["cells"]["d"] = {"max_warn": 9, "rows": ["node:x"], "measured": "rc", "why": "new"}
    assert R.only_down(ceiling(), new_cell) == []


def test_the_reviewed_escape_must_match_the_rise_exactly():
    base = ceiling()
    reason = "operator 11-20: the tunnel row warns by design until i1100 lands"
    ok = ceiling(max_warn=4, rows=BASE_ROWS + ["node:tunnel"])
    ok["cells"]["c"]["raise"] = {"from_max": 3, "to_max": 4, "add_rows": ["node:tunnel"], "reason": reason}
    assert R.only_down(base, ok) == []
    for bad in ({"from_max": 3, "to_max": 5, "add_rows": ["node:tunnel"], "reason": reason},
                {"from_max": 3, "to_max": 4, "add_rows": [], "reason": reason},
                {"from_max": 3, "to_max": 4, "add_rows": ["node:tunnel"], "reason": "because"}):
        b = json.loads(json.dumps(ok))
        b["cells"]["c"]["raise"] = bad
        assert R.only_down(base, b), bad
    # an old raise record cannot authorise the next rise
    base2 = json.loads(json.dumps(ok))
    again = json.loads(json.dumps(ok))
    again["cells"]["c"]["max_warn"] = 5
    assert R.only_down(base2, again)


def _git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, check=True,
                          env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid"))


def test_only_down_reads_the_base_through_git(tmp_path):
    """The CLI end to end in a throwaway repo: the file at the merge base
    with `dev` (the commit), against the work tree (the change)."""
    repo = tmp_path / "repo"
    (repo / "scripts" / "install-cell").mkdir(parents=True)
    f = repo / R.CEILING_REL
    _git(tmp_path, "init", "-q", "-b", "dev", str(repo))
    f.write_text(json.dumps(ceiling()))
    _git(repo, "add", ".")
    _git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base")

    def run():
        return subprocess.run([sys.executable, str(RATCHET), "only-down", "--base-ref", "dev", "--file", str(f)],
                              cwd=repo, capture_output=True, text=True, encoding="utf-8")
    assert run().returncode == 0
    f.write_text(json.dumps(ceiling(max_warn=4)))
    r = run()
    assert r.returncode == 1 and "RATCHET RAISED: c: max_warn 3 -> 4" in r.stdout, r.stdout + r.stderr
    f.write_text(json.dumps(ceiling(max_warn=2, rows=BASE_ROWS[1:])))
    assert run().returncode == 0
    r = subprocess.run([sys.executable, str(RATCHET), "only-down", "--base-ref", "no-such-ref", "--file", str(f)],
                       cwd=repo, capture_output=True, text=True)
    assert r.returncode == 2


def _base_branch() -> str:
    return os.environ.get("GITHUB_BASE_REF") or "dev"


def test_the_checked_in_ceiling_only_goes_down():
    """THE GUARD: this tree's warn-ratchet.json against its version on the
    base branch (origin/dev; a pull request's base). CI checks out one
    commit, so there the base is fetched first (the repo is public); a base
    that cannot be found skips, and a skip in CI fails the session
    (tests/_ci_skip_guard.py), so this cannot pass by not looking."""
    ref = f"refs/remotes/origin/{_base_branch()}"
    try:
        old = R.base_text(ref)
    except LookupError:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            subprocess.run(["git", "-C", str(ROOT), "fetch", "-q", "--depth=1", "--no-tags", "origin",
                            f"+refs/heads/{_base_branch()}:{ref}"], capture_output=True, timeout=120)
        try:
            old = R.base_text(ref)
        except LookupError:
            pytest.skip(f"{ref} is not in this clone: the ceiling's base cannot be read")
    if old is None:
        return  # no ceiling on the base yet: this change introduces it
    bad = R.only_down(json.loads(old), json.loads(CEILING.read_text()))
    assert not bad, "\n".join(bad)


# ── the file and the wiring ─────────────────────────────────────────────────

def test_every_full_install_cell_has_a_ceiling_entry():
    import yaml
    doc = yaml.safe_load((ROOT / ".github" / "workflows" / "install-matrix.yml").read_text())
    full = {r["cell"] for r in doc["jobs"]["cell"]["strategy"]["matrix"]["include"]
            if r.get("scope") == "full" and r.get("expect") != "refusal"}
    wf = (ROOT / ".github" / "workflows" / "install-matrix.yml").read_text()
    assert "CELL=windows-2025-wsl2" in wf and "SCOPE=full" in wf
    full.add("windows-2025-wsl2")
    cells = json.loads(CEILING.read_text())["cells"]
    assert set(cells) == full, (sorted(set(cells) ^ full))
    for name, e in cells.items():
        assert set(e) >= {"max_warn", "rows", "measured", "why"}, name
        if e["measured"] is None:
            continue
        assert isinstance(e["max_warn"], int) and e["max_warn"] >= 0, name
        assert isinstance(e["rows"], list) and len(e["rows"]) <= e["max_warn"], name
        for r in e["rows"]:
            assert r.split(":", 1)[0] in ("controller", "node", "seat") and ":" in r, (name, r)


def test_run_sh_judges_the_verify_json_and_skips_cells_without_an_install():
    text = RUN_SH.read_text()
    probe = text.index("step probe-verify-json 300 -- bash -c 'fresh --json cluster verify'\n")
    judge = text.index('step verify-ratchet 60 -- python3 "$HERE/ratchet.py" judge "$CELL" "$OUT/logs/probe-verify-json.log"\n')
    assert probe < judge < text.index("step first-answer "), "judged right after the JSON is written"
    line_end = text.index("\n", judge)
    assert "fail_onboarded" not in text[judge:line_end], "a FAIL fails the cell, but the probes after it still run"
    refusal = text[text.index('if [ "${EXPECT:-}" = refusal ]; then'):]
    assert refusal.index('ratchet.py" skip "$CELL"') < refusal.index("    finish\n")
    node = text[text.index('if [ "$SCOPE" = node-partial ]; then'):]
    assert node.index('ratchet.py" skip "$CELL"') < node.index("    finish\n")


def test_a_ratchet_fail_fails_the_cell_summary(tmp_path):
    C = _load("install_cell_for_ratchet", ROOT / "scripts" / "install-cell" / "cell.py")
    ok = {"step": "probe-verify-json", "rc": 0, "seconds": 3, "first_error": "", "prompts": [], "warnings": [], "tail": []}
    bad = {"step": "verify-ratchet", "rc": 1, "seconds": 0, "first_error": "RATCHET FAIL: 4 WARN > 3",
           "prompts": [], "warnings": [], "tail": []}
    (tmp_path / "steps.jsonl").write_text(json.dumps(ok) + "\n" + json.dumps(bad) + "\n")
    (tmp_path / "meta.json").write_text(json.dumps({"cell": "c"}))
    s = C.summarize(tmp_path)
    assert s["result"] == "fail" and s["failed_step"] == "verify-ratchet"


def test_the_judge_reads_the_redacted_log_step_writes(tmp_path):
    """probe-verify-json.log is what step() kept: the redactor's output. A
    masked detail must not cost the ratchet its JSON."""
    v = json.loads(json.dumps(BASE_VERIFY))
    v["controller"]["checks"][0]["detail"] = 'token: s3cr3t-value key="abcd1234" ' + "QUJD" * 12
    v["nodes"][0]["checks"][0]["detail"] = "admin password: Tr0ub4dor&3-horse"
    red = subprocess.run([sys.executable, str(ROOT / "scripts" / "install-cell" / "cell.py"), "redact"],
                         input=as_log(v), capture_output=True, text=True, check=True).stdout
    assert "s3cr3t-value" not in red and "Tr0ub4dor" not in red, red
    got = R.verify_json(red)
    assert got is not None and sorted(R.warn_rows(got)) == BASE_ROWS


# ── FAIL rows (i1098: "a FAIL row always fails the cell"), behind a flag ────

def _fail_verify():
    v = json.loads(json.dumps(BASE_VERIFY))
    v["controller"]["checks"].append(row("shared secrets", "fail"))
    v["seats"] = [{"seat": "seat_a", "ok": False, "checks": [row("seat display", "fail")]}]
    return v


def test_a_fail_row_fails_the_cell_when_the_rule_is_on(tmp_path):
    c = ceiling()
    c["fail_rows_fail_the_cell"] = True
    rc, lines = run_judge(tmp_path, _fail_verify(), c)
    assert rc == 1, lines
    assert lines[-1] == "VERIFY FAIL: controller:shared secrets, seat:seat display"
    assert any(l.startswith("RATCHET PASS: 3 WARN") for l in lines), "the WARN count is judged on its own"
    # also while the ceiling is still unmeasured: the FAIL rule does not wait for a baseline
    c = ceiling(max_warn=None, rows=None, measured=None)
    c["fail_rows_fail_the_cell"] = True
    rc, lines = run_judge(tmp_path, _fail_verify(), c)
    assert rc == 1 and lines[-1].startswith("VERIFY FAIL: ")


def test_an_allow_listed_fail_row_is_a_note(tmp_path):
    c = ceiling()
    c["fail_rows_fail_the_cell"] = True
    c["fail_allowed"] = {"controller:shared secrets": {"why": "runner-only: t"},
                         "seat:seat display": {"why": "runner-only: u"}}
    rc, lines = run_judge(tmp_path, _fail_verify(), c)
    assert rc == 0, lines
    assert ("VERIFY NOTE: allowed FAIL row(s): controller:shared secrets (runner-only: t); "
            "seat:seat display (runner-only: u)") in lines


def test_while_the_rule_is_off_a_fail_row_is_reported_not_fatal(tmp_path):
    for c in (ceiling(), dict(ceiling(), fail_rows_fail_the_cell=False)):
        rc, lines = run_judge(tmp_path, _fail_verify(), c)
        assert rc == 0, lines
        assert ("VERIFY NOTE: FAIL row(s) controller:shared secrets, seat:seat display "
                "(not fatal yet: fail_rows_fail_the_cell is false)") in lines


def test_each_warn_row_prints_with_its_status(tmp_path):
    c = ceiling()
    c["row_status"] = {"controller:holds": {"status": "awaiting operator decision", "why": "x"},
                       "node:ollama models": {"status": "accepted", "why": "y"}}
    rc, lines = run_judge(tmp_path, BASE_VERIFY, c, row_lines=True)
    assert rc == 0
    assert lines[:3] == ["RATCHET ROW: controller:holds (awaiting operator decision)",
                         "RATCHET ROW: controller:off-site backup (no status recorded)",
                         "RATCHET ROW: node:ollama models (accepted)"]


def test_the_fail_rule_and_its_allow_list_only_tighten():
    on = dict(ceiling(), fail_rows_fail_the_cell=True, fail_allowed={})
    assert R.only_down(on, on) == []
    assert R.only_down(dict(ceiling(), fail_rows_fail_the_cell=False), on) == [], "switching it on is free"
    assert "switched off" in R.only_down(on, dict(on, fail_rows_fail_the_cell=False))[0]
    added = dict(on, fail_allowed={"controller:x": {"why": "runner-only"}})
    assert "added without a" in R.only_down(on, added)[0]
    decided = dict(on, fail_allowed={"controller:x": {"why": "runner-only",
                                                       "decision": "release lead 11-20: a runner has no TPM"}})
    assert R.only_down(on, decided) == []
    assert R.only_down(decided, on) == [], "removing an allowed row is the point"


UNDECIDED = {  # i1098 rows 10, 11, 12, 14-24, and i1058: the operator has not decided them
    "controller:agent protect", "controller:last backup", "node:holds", "controller:at-rest tpm",
    "controller:postgres at rest", "controller:redis at rest", "controller:nats at rest",
    "controller:prometheus at rest", "controller:noo-data at rest", "controller:pki at rest",
    "controller:age key at rest", "controller:at-rest swap", "controller:at-rest outside the set",
    "controller:at-rest volume", "node:docker engine",
}


def test_undecided_rows_are_recorded_by_name_as_awaiting_the_operator():
    import re
    doc = json.loads(CEILING.read_text())
    st = doc["row_status"]
    awaiting = {r for r, e in st.items() if e["status"] == "awaiting operator decision"}
    assert awaiting == UNDECIDED, sorted(awaiting ^ UNDECIDED)
    for r, e in st.items():
        assert e["status"] in R.STATUSES and e.get("why"), r
    # every name is a real verify row, in the section the registry gives it
    reg = (ROOT / "noo-cli" / "src" / "commands" / "cluster_verify" / "rows.rs").read_text()
    scope = {n: s.lower() for n, s in re.findall(r'name: "([^"]+)",\s*scope: Scope::(\w+)', reg)}
    for r in st:
        sec, name = r.split(":", 1)
        assert scope.get(name) == sec, (r, scope.get(name))
    # a measured cell's rows all carry a status
    for cell, e in doc["cells"].items():
        for r in (e["rows"] or []) if e["measured"] is not None else []:
            assert r in st, (cell, r)
    assert doc["fail_rows_fail_the_cell"] is False, "OFF until the release lead approves fail_allowed"
