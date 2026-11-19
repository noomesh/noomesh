# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""infra-staged.yml tells someone when it keeps failing (noomesh-internal i1042).

Four red nights went unnoticed. The workflow's last job (red-issue) runs
scripts/infra-staged-red.py: the second consecutive failed run opens one
`infra-staged-red` issue, later failures comment on it, a green run closes it.
The job never runs on an event a fork can trigger, it alone may write issues,
and the issue body (THE REPOSITORY IS PUBLIC) carries only the gate's
`NEW <id> <pkg>` lines that match the strict public pattern.

`gh` and `docker` are faked on PATH; the fake records every call.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/infra-staged-red.py"
WF = yaml.safe_load((ROOT / ".github/workflows/infra-staged.yml").read_text())
JOB = WF["jobs"]["red-issue"]
REPO = "noomesh/noomesh"
RUN_ID = "900"

FAKE_GH = r'''#!/usr/bin/env python3
import json, os, sys
state = json.load(open(os.environ["FAKE_STATE"]))
a = sys.argv[1:]
rec = {"argv": a}
if "--body-file" in a:
    rec["body"] = open(a[a.index("--body-file") + 1]).read()
with open(os.environ["FAKE_CALLS"], "a") as f:
    f.write(json.dumps(rec) + "\n")
if a[:2] == ["run", "list"]:
    print(json.dumps(state["runs"]))
elif a[0] == "api" and a[1].endswith("/logs"):
    print(state["logs"][a[1].split("/")[-2]])
elif a[0] == "api" and "/jobs" in a[1]:
    print(json.dumps({"jobs": state["jobs"]}))
elif a[:2] == ["label", "list"]:
    print(json.dumps([{"name": n} for n in state["labels"]]))
elif a[:2] == ["issue", "list"]:
    print(json.dumps(state["issues"]))
'''

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys
state = json.load(open(os.environ["FAKE_STATE"]))
ref = [x for x in sys.argv if x.startswith("ghcr.io/")][0]
image = ref.split("/")[-1].split(":")[0]
c = state["created"].get(image)
if c is None:
    sys.exit(1)
print(json.dumps({"linux/amd64": {"config": {"Labels": {"org.opencontainers.image.created": c}}}}))
'''

GATE_LOG = """2026-11-18T03:40:01.1234567Z fixable HIGH/CRITICAL in the new build: 3
2026-11-18T03:40:01.1234567Z   NEW CVE-2026-1234 libssl3
2026-11-18T03:40:01.1234567Z   NEW GHSA-abcd-efgh-ijkl starlette
2026-11-18T03:40:01.1234567Z       CVE-2025-0001 zlib1g
"""

FAILED_NEEDS = {"matrix": {"result": "success", "outputs": {}}, "stage": {"result": "failure", "outputs": {}}}
GREEN_NEEDS = {"matrix": {"result": "success", "outputs": {}}, "stage": {"result": "success", "outputs": {}}}


def _runs(*conclusions):
    """This run (in progress) first, then the earlier scheduled runs, newest first."""
    out = [{"databaseId": int(RUN_ID), "status": "in_progress", "conclusion": ""}]
    out += [{"databaseId": 899 - i, "status": "completed", "conclusion": c} for i, c in enumerate(conclusions)]
    return out


def _run(tmp_path, needs, runs, issues=(), labels=("bug",), logs=None, jobs=None, created=None):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    for name, src in (("gh", FAKE_GH), ("docker", FAKE_DOCKER)):
        (bin_ / name).write_text(src.replace("/usr/bin/env python3", sys.executable))
        (bin_ / name).chmod(0o755)
    state = {
        "runs": runs, "issues": list(issues), "labels": list(labels),
        "jobs": jobs if jobs is not None else [
            {"id": 11, "name": "matrix", "conclusion": "success"},
            {"id": 12, "name": "whisper (build, scan, stage)", "conclusion": "failure"},
            {"id": 13, "name": "ollama (build, scan, stage)", "conclusion": "success"}],
        "logs": logs if logs is not None else {"12": GATE_LOG},
        "created": created if created is not None else {"whisper": "2026-11-14T03:30:00Z"},
    }
    (tmp_path / "state.json").write_text(json.dumps(state))
    calls = tmp_path / "calls.jsonl"
    env = {"PATH": f"{bin_}:/usr/bin:/bin", "FAKE_STATE": str(tmp_path / "state.json"),
           "FAKE_CALLS": str(calls), "GH_REPO": REPO, "RUN_ID": RUN_ID, "NEEDS": json.dumps(needs),
           "STAGE_REF": "refs/heads/dev", "GITHUB_SERVER_URL": "https://github.com",
           "INFRA_RED_NOW": "2026-11-18T04:00:00+00:00", "INFRA_RED_RETRY_SLEEP": "0"}
    p = subprocess.run([sys.executable, str(SCRIPT)], env=env, capture_output=True, text=True)
    assert p.returncode == 0, p.stdout + p.stderr
    recs = [json.loads(l) for l in calls.read_text().splitlines()] if calls.exists() else []
    return p.stdout, recs


def _writes(recs):
    return [r for r in recs if r["argv"][:2] in (["issue", "create"], ["issue", "comment"],
                                                  ["issue", "close"], ["label", "create"])]


# ------------------------------------------------------------- the job

def test_the_job_runs_only_on_schedule_or_dispatch_never_on_a_fork_event():
    cond = JOB["if"]
    assert cond.startswith("always() && ")
    assert "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'" in cond
    assert "github.repository == 'noomesh/noomesh'" in cond
    assert "pull_request" not in cond and "!=" not in cond, "an allow-list, never an exclusion"
    triggers = set(WF[True])  # PyYAML reads `on:` as True
    assert triggers == {"schedule", "workflow_dispatch"}, \
        f"a new trigger ({triggers}) must be checked against the red-issue job's if:"
    assert set(JOB["needs"]) == {"matrix", "stage"}


def test_issues_write_is_granted_to_the_red_issue_job_only():
    assert JOB["permissions"] == {"contents": "read", "actions": "read", "issues": "write"}
    assert "issues" not in WF["permissions"], "the issue write must not be workflow-wide"
    for name, job in WF["jobs"].items():
        if name != "red-issue":
            assert "issues" not in (job.get("permissions") or {}), name
    step = JOB["steps"][-1]
    assert step["run"] == "python3 scripts/infra-staged-red.py"
    assert step["env"]["GH_TOKEN"] == "${{ github.token }}"


# ------------------------------------------------------------- the rule

def test_a_first_failure_opens_no_issue(tmp_path):
    out, recs = _run(tmp_path, FAILED_NEEDS, _runs("success", "failure"))
    assert "first failure; an issue opens on the next" in out
    assert _writes(recs) == []


def test_a_second_failure_creates_the_issue_with_the_label(tmp_path):
    out, recs = _run(tmp_path, FAILED_NEEDS, _runs("failure", "failure", "success"))
    creates = [r for r in _writes(recs) if r["argv"][:2] == ["issue", "create"]]
    assert len(creates) == 1, _writes(recs)
    a = creates[0]["argv"]
    assert a[a.index("--title") + 1] == "infra-staged has failed 3 runs in a row"
    assert a[a.index("--label") + 1] == "infra-staged-red"
    body = creates[0]["body"]
    assert "CVE-2026-1234 libssl3" in body and "GHSA-abcd-efgh-ijkl starlette" in body
    assert "CVE-2025-0001" not in body, "an inherited finding is not NEW"
    assert "### whisper" in body and "ollama" not in body
    assert "built 2026-11-14 03:30 UTC, 4 day(s) old" in body and "passed the release's 3-day limit on 2026-11-17" in body
    assert "the next release builds this image itself and gates it the same way; " \
           "a NEW finding will block its signed lock" in body
    assert f"https://github.com/{REPO}/actions/runs/{RUN_ID}" in body


def test_a_missing_label_is_created_before_the_issue(tmp_path):
    _, recs = _run(tmp_path, FAILED_NEEDS, _runs("failure", "success"), labels=("bug",))
    w = _writes(recs)
    assert [r["argv"][:2] for r in w] == [["label", "create"], ["issue", "create"]]
    assert w[0]["argv"][2] == "infra-staged-red"
    (tmp_path / "again").mkdir()
    _, recs = _run(tmp_path / "again", FAILED_NEEDS, _runs("failure", "success"), labels=("infra-staged-red",))
    assert [r["argv"][:2] for r in _writes(recs)] == [["issue", "create"]], "an existing label is not re-created"


def test_an_open_issue_gets_a_comment_not_a_second_issue(tmp_path):
    issue = {"number": 77, "url": f"https://github.com/{REPO}/issues/77"}
    _, recs = _run(tmp_path, FAILED_NEEDS, _runs("failure", "failure", "failure", "success"), issues=[issue])
    w = _writes(recs)
    assert [r["argv"][:3] for r in w] == [["issue", "comment", "77"]], w
    assert "has failed 4 runs in a row" in w[0]["body"]
    lst = next(r["argv"] for r in recs if r["argv"][:2] == ["issue", "list"])
    assert lst[lst.index("--label") + 1] == "infra-staged-red" and lst[lst.index("--state") + 1] == "open"


def test_a_green_run_closes_the_open_issue_naming_the_run(tmp_path):
    issue = {"number": 77, "url": f"https://github.com/{REPO}/issues/77"}
    _, recs = _run(tmp_path, GREEN_NEEDS, _runs("failure", "failure"), issues=[issue])
    w = _writes(recs)
    assert [r["argv"][:3] for r in w] == [["issue", "close", "77"]], w
    a = w[0]["argv"]
    assert f"https://github.com/{REPO}/actions/runs/{RUN_ID}" in a[a.index("--comment") + 1]


# ------------------------------------------------------------- public content

def test_the_body_filter_drops_paths_and_non_cve_tokens(tmp_path):
    noisy = GATE_LOG + "\n".join([
        "2026-11-18T03:40:02Z   NEW CVE-2026-9999 /home/runner/work/secret/pkg",
        "2026-11-18T03:40:02Z   NEW TOKEN-ghp_abcdef0123456789 libfoo",
        "2026-11-18T03:40:02Z   NEW CVE-2026-8888 libbar extra-field",
        "2026-11-18T03:40:02Z ::error::NEW CVE-2026-7777 libbaz",
    ]) + "\n"
    _, recs = _run(tmp_path, FAILED_NEEDS, _runs("failure"), logs={"12": noisy})
    body = next(r for r in _writes(recs) if r["argv"][:2] == ["issue", "create"])["body"]
    for leak in ("/home/runner", "secret", "ghp_", "TOKEN", "CVE-2026-9999", "CVE-2026-8888", "libbar",
                 "CVE-2026-7777"):
        assert leak not in body, leak
    assert "  - CVE-2026-1234 libssl3" in body
    assert "3 more NEW line(s) not shown" in body
