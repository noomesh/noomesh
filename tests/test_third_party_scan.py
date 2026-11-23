# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The third-party images we pin are scanned weekly, one issue per image (i1100).

An image we only PIN (scripts/stack-lock-third-party.py THIRD_PARTY) was
scanned nowhere after the day it was pinned; nginx sat at 3 CRITICAL / 67 HIGH
on an EOL line unnoticed. .github/workflows/third-party-scan.yml scans every
pinned digest and scripts/third-party-scan.py keeps one `third-party-image`
issue per row:

  * default-on: a fixable CRITICAL or HIGH, an EOSL base or a passed line
    re-check date opens it;
  * opt-in (declared in scripts/third-party-lines.json): only a fixable
    CRITICAL or an EOSL base; HIGH is a count, never a list;
  * a comment only when the triggering set changes; closed when the pin moves
    or nothing triggers.

Canned Trivy JSON only: no Trivy, no GitHub API (`gh` is faked on PATH).
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/third-party-scan.py"
WF_PATH = ROOT / ".github/workflows/third-party-scan.yml"
WF = yaml.safe_load(WF_PATH.read_text())
LINES = json.loads((ROOT / "scripts/third-party-lines.json").read_text())
COMPOSE = (ROOT / "docker-compose.cluster.yml").read_text()
RUN = "https://github.com/noomesh/noomesh/actions/runs/900"
TODAY = date(2026, 11, 20)
DA = "sha256:" + "a" * 64
DB = "sha256:" + "b" * 64


def _mod():
    spec = importlib.util.spec_from_file_location("third_party_scan", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


M = _mod()


def _vuln(vid, sev, fixed="", pkg="libfoo"):
    return {"VulnerabilityID": vid, "Severity": sev, "PkgName": pkg, "InstalledVersion": "1.0",
            "FixedVersion": fixed, "Title": "private-looking title", "PkgPath": "/home/runner/x"}


def _report(vulns=(), eosl=False):
    os_ = {"Family": "alpine", "Name": "3.18.4"}
    if eosl:
        os_["EOSL"] = True
    return {"ArtifactName": "/home/runner/secret-path", "Metadata": {"OS": os_},
            "Results": [{"Target": "x", "Vulnerabilities": list(vulns)}]}


def _tgt(row, digest=DA, version="1.0", by=("dev compose",)):
    return {"row": row, "repo": M.THIRD_PARTY[row]["repo"], "digest": digest, "version": version,
            "pinned_by": list(by)}


def _lines(**rows):
    return {"rows": rows}


DEFAULT = {"line": None, "policy": None, "recheck_by": None, "opt_in": False}
OPTIN = {"line": None, "policy": None, "recheck_by": None, "opt_in": True}


def _decide(row, report, meta, issues=(), digest=DA, today=TODAY, tags=None):
    return M.decide([_tgt(row, digest)], {digest: M.findings(report)}, _lines(**{row: meta}),
                    list(issues), tags or {}, today, RUN)


def _only(actions):
    assert len(actions) == 1, actions
    return actions[0]


# ------------------------------------------------------------------ default-on

def test_default_on_with_a_fixable_high_opens_an_issue():
    a = _only(_decide("nginx", _report([_vuln("CVE-2026-1001", "HIGH", "1.2")]), DEFAULT))
    assert a["action"] == "create"
    assert a["title"] == "third-party image nginx: 1 fixable HIGH"
    assert "CVE-2026-1001" in a["body"]


def test_a_high_with_no_fix_opens_nothing():
    a = _only(_decide("nginx", _report([_vuln("CVE-2026-1001", "HIGH", ""),
                                         _vuln("CVE-2026-1002", "CRITICAL", "")]), DEFAULT))
    assert a["action"] == "none"


def test_an_eosl_base_opens_an_issue():
    a = _only(_decide("nats", _report([], eosl=True), DEFAULT))
    assert a["action"] == "create" and "EOSL base" in a["title"]
    assert "yes (alpine 3.18.4)" in a["body"]


def test_a_passed_recheck_date_opens_an_issue():
    meta = {**DEFAULT, "line": "1.30", "policy": "https://nginx.org/en/download.html", "recheck_by": "2026-11-19"}
    a = _only(_decide("nginx", _report(), meta))
    assert a["action"] == "create" and "line re-check date passed" in a["title"]
    assert "re-check by 2026-11-19 (PASSED" in a["body"]
    assert _only(_decide("nginx", _report(), meta, today=date(2026, 11, 19)))["action"] == "none", \
        "the date itself is still inside"


# ------------------------------------------------------------------ opt-in

def test_opt_in_with_high_only_opens_nothing():
    a = _only(_decide("vllm", _report([_vuln("CVE-2026-2001", "HIGH", "2.0")]), OPTIN))
    assert a["action"] == "none"


def test_opt_in_ignores_a_passed_date():
    a = _only(_decide("vllm", _report(), {**OPTIN, "recheck_by": "2026-01-01"}))
    assert a["action"] == "none"


def test_opt_in_with_a_fixable_critical_opens_with_a_high_count_and_no_high_list():
    vulns = [_vuln("CVE-2026-3001", "CRITICAL", "2.0")] + [_vuln(f"CVE-2026-{4000 + i}", "HIGH", "2.0")
                                                           for i in range(40)]
    a = _only(_decide("vllm", _report(vulns), OPTIN))
    assert a["action"] == "create"
    assert a["title"] == "third-party image vllm: 1 fixable CRITICAL"
    b = a["body"]
    assert "CVE-2026-3001" in b
    assert "CVE-2026-4000" not in b and "CVE-2026-4039" not in b, "no HIGH list for an opt-in backend"
    assert "40 fixable of 40" in b
    assert "a 1,300-line issue helps no one" in b and "`third-party-scan` artifact" in b and RUN in b


def test_opt_in_is_read_from_the_data_file_not_a_name():
    # the same image, declared default-on, opens on HIGH
    a = _only(_decide("vllm", _report([_vuln("CVE-2026-2001", "HIGH", "2.0")]), DEFAULT))
    assert a["action"] == "create"
    assert {r for r, m in LINES["rows"].items() if m["opt_in"]} == {"vllm"}


# ------------------------------------------------------------------ issue life

def _open_issue(report, meta, row="nginx", digest=DA, number=7):
    a = _only(_decide(row, report, meta, digest=digest))
    assert a["action"] == "create"
    return {"number": number, "body": a["body"]}


def test_an_unchanged_set_adds_no_comment():
    r = _report([_vuln("CVE-2026-1001", "HIGH", "1.2")])
    a = _only(_decide("nginx", r, DEFAULT, issues=[_open_issue(r, DEFAULT)]))
    assert a["action"] == "none" and a["number"] == 7


def test_a_changed_set_comments_and_updates():
    r1 = _report([_vuln("CVE-2026-1001", "HIGH", "1.2")])
    r2 = _report([_vuln("CVE-2026-1001", "HIGH", "1.2"), _vuln("CVE-2026-1003", "CRITICAL", "1.3")])
    a = _only(_decide("nginx", r2, DEFAULT, issues=[_open_issue(r1, DEFAULT)]))
    assert a["action"] == "update" and a["number"] == 7
    assert "triggering set changed" in a["comment"]
    assert M.parse_marker(a["body"])["set"] != M.parse_marker(_open_issue(r1, DEFAULT)["body"])["set"]


def test_a_count_change_outside_the_set_adds_no_comment():
    r1 = _report([_vuln("CVE-2026-1001", "HIGH", "1.2")])
    r2 = _report([_vuln("CVE-2026-1001", "HIGH", "1.2"), _vuln("CVE-2026-1009", "HIGH", "")])
    assert _only(_decide("nginx", r2, DEFAULT, issues=[_open_issue(r1, DEFAULT)]))["action"] == "none"


def test_the_pin_moved_closes_the_issue():
    r = _report([_vuln("CVE-2026-1001", "HIGH", "1.2")])
    acts = _decide("nginx", _report(), DEFAULT, issues=[_open_issue(r, DEFAULT, digest=DA)], digest=DB)
    a = _only(acts)
    assert a["action"] == "close" and a["number"] == 7
    assert "The pin moved" in a["comment"] and DA in a["comment"] and DB in a["comment"]


def test_the_pin_moved_onto_a_bad_digest_closes_then_opens_fresh():
    r = _report([_vuln("CVE-2026-1001", "HIGH", "1.2")])
    acts = _decide("nginx", r, DEFAULT, issues=[_open_issue(r, DEFAULT, digest=DA)], digest=DB)
    assert [a["action"] for a in acts] == ["close", "create"]
    assert M.parse_marker(acts[1]["body"])["digests"] == [DB]


def test_an_empty_set_closes_the_issue():
    r = _report([_vuln("CVE-2026-1001", "HIGH", "1.2")])
    a = _only(_decide("nginx", _report(), DEFAULT, issues=[_open_issue(r, DEFAULT)]))
    assert a["action"] == "close" and "Nothing triggers any more" in a["comment"]


def test_a_missing_scan_leaves_the_issue_alone():
    r = _report([_vuln("CVE-2026-1001", "HIGH", "1.2")])
    acts = M.decide([_tgt("nginx")], {}, _lines(nginx=DEFAULT), [_open_issue(r, DEFAULT)], {}, TODAY, RUN)
    assert [a["action"] for a in acts] == ["skip"]


def test_an_issue_is_found_by_its_marker_not_its_title():
    r = _report([_vuln("CVE-2026-1001", "HIGH", "1.2")])
    issue = _open_issue(r, DEFAULT)
    other = {"number": 3, "body": M.marker("nats", [DA], "0" * 16)}
    acts = _decide("nginx", r, DEFAULT, issues=[other, issue])
    mine = [a for a in acts if a["row"] == "nginx"]
    assert mine == [{"action": "none", "row": "nginx", "number": 7, "why": "triggering set unchanged"}]


# ------------------------------------------------------------------ marker + public body

def test_the_marker_round_trips():
    mk = M.marker("loki", [DB, DA], "0123456789abcdef")
    assert M.parse_marker("text\n" + mk + "\nmore") == {"row": "loki", "digests": [DA, DB],
                                                          "set": "0123456789abcdef"}
    assert M.parse_marker("no marker") is None


def test_the_body_carries_only_public_fields():
    vulns = [_vuln("CVE-2026-1001", "HIGH", "1.2", pkg="secret-pkg-name"),
             _vuln("TOKEN-ghp_abcdef", "CRITICAL", "1.2"),
             _vuln("CVE-2026-1002", "CRITICAL", "1.2")]
    a = _only(_decide("nginx", _report(vulns), {**DEFAULT, "line": "1.30"},
                      tags={"nginx": ["1.30.9-alpine", "bad tag;rm", "1.31.0-alpine"]}))
    b = a["body"]
    for leak in ("secret-pkg-name", "TOKEN-ghp", "/home/runner", "private-looking title", "bad tag", "PkgPath"):
        assert leak not in b, leak
    assert "1 more omitted" in b, "a non-CVE/GHSA id is counted, not listed"
    # every backticked token is a digest, version, tag or the artifact name
    for tok in re.findall(r"`([^`]*)`", b):
        assert re.fullmatch(r"sha256:[0-9a-f]{64}|[0-9a-f]{12}|[A-Za-z0-9][A-Za-z0-9._/:-]*", tok), tok


def test_the_id_list_is_capped_and_says_how_many_are_omitted():
    vulns = [_vuln(f"CVE-2026-{5000 + i}", "HIGH", "1") for i in range(M.ID_CAP + 5)]
    b = _only(_decide("nginx", _report(vulns), DEFAULT))["body"]
    assert "(5 more omitted" in b and f"CVE-2026-{5000 + M.ID_CAP}" not in b


def test_a_bad_run_url_is_refused():
    with pytest.raises(ValueError):
        M.decide([], {}, _lines(), [], {}, TODAY, "https://evil.example/x")


def test_newer_upstream_tag_in_the_same_line():
    tags = ["1.30.0-alpine", "1.30.2-alpine", "1.30.3-alpine-slim", "1.31.0-alpine", "1.300.1-alpine",
            "1.30.10-alpine"]
    assert M.newer_in_line("1.30.1-alpine", "1.30", tags) == "1.30.10-alpine"
    assert M.newer_in_line("1.27.5-alpine", "1.30", tags) == "1.30.10-alpine", "off-line pin: the line's newest"
    assert M.newer_in_line("v0.25.0", "v0", ["v0.26.1", "v1.0.0", "latest"]) == "v0.26.1"
    assert M.newer_in_line("3", "3", ["3", "3.5.1", "30"]) is None, "a floating major tag has no newer"
    assert M.newer_in_line("1.6", None, ["1.7"]) is None


# ------------------------------------------------------------------ targets

def test_every_third_party_row_is_a_target_from_compose():
    tg = M.targets(COMPOSE)
    assert sorted({t["row"] for t in tg}) == sorted(M.THIRD_PARTY)
    for t in tg:
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", t["digest"]) and t["pinned_by"] == ["dev compose"]


def test_a_new_third_party_row_is_covered_automatically(monkeypatch):
    monkeypatch.setitem(M.THIRD_PARTY, "newthing", {"compose": "example/newthing", "repo": "docker.io/example/newthing",
                                                    "ver": M.LOCK._VER})
    text = COMPOSE + ("\n  newthing:\n    image: example/newthing:1.2${NOO_IMAGE_DIGEST_NEWTHING:-@" + DB + "}\n")
    tg = M.targets(text)
    assert {"row": "newthing", "repo": "docker.io/example/newthing", "digest": DB, "version": "1.2",
            "pinned_by": ["dev compose"]} in tg
    # no lines entry: scanned as default-on, a fixable HIGH opens its issue
    acts = M.decide([t for t in tg if t["row"] == "newthing"],
                    {DB: M.findings(_report([_vuln("CVE-2026-1", "HIGH", "2")]))}, LINES, [], {}, TODAY, RUN)
    assert [a["action"] for a in acts] == ["create"]


def test_the_final_lock_adds_its_digest_once():
    dev = {t["row"]: t["digest"] for t in M.targets(COMPOSE)}
    lock = "# stack v9.9.9\n# mesh-migration-head 001_x\ngateway@" + DA + "\n" + f"nginx@{DB}\nnats@{dev['nats']}\n"
    tg = M.targets(COMPOSE, lock, "stack-v9.9.9")
    nats = [t for t in tg if t["row"] == "nats"]
    assert len(nats) == 1 and nats[0]["pinned_by"] == ["dev compose", "final lock stack-v9.9.9"]
    nginx = [t for t in tg if t["row"] == "nginx"]
    assert [t["digest"] for t in nginx] == [dev["nginx"], DB] and nginx[1]["version"] is None
    assert not any(t["row"] == "gateway" for t in tg), "only THIRD_PARTY rows"
    scans = M.scan_list(tg)
    assert len(scans) == len({t["digest"] for t in tg}) and (DB, f"ghcr.io/noomesh/nginx@{DB}") in scans  # the lock row resolves from our mirror


def test_the_lines_file_names_only_third_party_rows():
    assert set(LINES["rows"]) <= set(M.THIRD_PARTY)
    for row, m in LINES["rows"].items():
        assert set(m) >= {"line", "policy", "recheck_by", "opt_in"}, row
        if m["recheck_by"]:
            date.fromisoformat(m["recheck_by"])
    assert LINES["rows"]["nginx"]["line"] == "1.30" and LINES["rows"]["nginx"]["recheck_by"] == "2027-04-30"


# ------------------------------------------------------------------ the workflow

def test_issues_write_is_granted_to_the_issue_job_only():
    assert WF["permissions"] == {"contents": "read"}
    assert WF["jobs"]["issues"]["permissions"] == {"contents": "read", "issues": "write"}
    for name, job in WF["jobs"].items():
        if name != "issues":
            assert "issues" not in (job.get("permissions") or {}), name
        assert "github.repository == 'noomesh/noomesh'" in job["if"], name


def test_the_triggers_are_a_schedule_a_dev_push_on_the_pins_and_a_dispatch():
    on = WF[True]  # PyYAML reads `on:` as True
    assert set(on) == {"schedule", "push", "workflow_dispatch"}, "a new trigger must be checked against the issue job"
    assert on["schedule"] and on["schedule"][0]["cron"]
    assert on["push"]["branches"] == ["dev"]
    paths = on["push"]["paths"]
    for p in ("docker-compose*.yml", "scripts/stack-lock-third-party.py", "scripts/third-party-lines.json"):
        assert p in paths, p


def test_the_scan_is_remote_with_the_pinned_trivy_and_release_settings():
    steps = WF["jobs"]["scan"]["steps"]
    runs = "\n".join(s.get("run", "") for s in steps)
    assert "scripts/infra-scan.sh install-trivy" in runs
    assert "scripts/ci-free-disk.sh" in runs
    scan = next(s["run"] for s in steps if "trivy image --skip-db-update" in s.get("run", ""))
    for flag in ("--image-src remote", "--platform linux/amd64", "--scanners vuln", "--severity HIGH,CRITICAL"):
        assert flag in scan, flag
    assert "--ignore-unfixed" not in scan, "the HIGH counts include unfixed findings; the rule reads FixedVersion"
    assert "trivy clean --scan-cache" in scan
    assert "third-party-scan.py targets" in runs and "--pattern \"$tag.lock\"" in runs
    assert "--exclude-pre-releases" in runs


def test_only_a_dev_run_writes_issues():
    run = WF["jobs"]["issues"]["steps"][-2]["run"]
    gate = run.index('if [ "$SCAN_REF" != "refs/heads/dev" ]')
    assert gate < run.index("third-party-scan.py apply")
    assert WF["env"]["SCAN_REF"] == "${{ github.event_name == 'schedule' && 'refs/heads/dev' || github.ref }}"


# ------------------------------------------------------------------ apply (gh faked)

FAKE_GH = r'''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
rec = {"argv": a}
if "--body-file" in a:
    rec["body"] = open(a[a.index("--body-file") + 1]).read()
with open(os.environ["FAKE_CALLS"], "a") as f:
    f.write(json.dumps(rec) + "\n")
if a[:2] == ["label", "list"]:
    print(json.dumps([{"name": "bug"}]))
'''


def test_apply_creates_with_the_label_updates_and_closes(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "gh").write_text(FAKE_GH.replace("/usr/bin/env python3", sys.executable))
    (bin_ / "gh").chmod(0o755)
    acts = [{"action": "create", "row": "nginx", "title": "t1", "body": "B1"},
            {"action": "update", "row": "nats", "number": 5, "title": "t2", "body": "B2", "comment": "C2"},
            {"action": "close", "row": "tempo", "number": 6, "comment": "C3"},
            {"action": "none", "row": "redis", "why": "x"}]
    (tmp_path / "a.json").write_text(json.dumps(acts))
    calls = tmp_path / "calls.jsonl"
    p = subprocess.run([sys.executable, str(SCRIPT), "apply", "--repo", "noomesh/noomesh", "--actions",
                        str(tmp_path / "a.json")], capture_output=True, text=True,
                       env={"PATH": f"{bin_}:/usr/bin:/bin", "FAKE_CALLS": str(calls)})
    assert p.returncode == 0, p.stderr
    recs = [json.loads(x) for x in calls.read_text().splitlines()]
    assert [r["argv"][:2] for r in recs] == [["label", "list"], ["label", "create"], ["issue", "create"],
                                             ["issue", "edit"], ["issue", "comment"], ["issue", "close"]]
    create = recs[2]["argv"]
    assert create[create.index("--label") + 1] == "third-party-image" and recs[2]["body"] == "B1"
    assert recs[3]["argv"][2] == "5" and recs[3]["body"] == "B2" and recs[4]["body"] == "C2"
    assert recs[5]["argv"][2] == "6" and recs[5]["argv"][-1] == "C3"
