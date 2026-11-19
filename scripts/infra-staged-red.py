#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tell someone when infra-staged.yml keeps failing (noomesh-internal i1042).

infra-staged.yml went red on four scheduled runs in a row (whisper and piper
failed the gate on NEW fixable findings) and nobody was told: GitHub mails a
scheduled run's failure only to whoever last edited the cron line. It
surfaced when a release cut would have failed at its signed lock. So the
workflow's last job runs this script:

  * this run failed, and so did the previous scheduled run: one open issue
    labelled `infra-staged-red` (created, with the label, if none is open;
    commented on if one is), titled with the number of consecutive failed
    runs, this one included;
  * this run failed, the previous scheduled run did not: nothing, the next
    failure opens the issue (one red night can be a registry hiccup);
  * this run is green: every open `infra-staged-red` issue is closed with a
    comment naming the run.

THE REPOSITORY IS PUBLIC. The body names only image names, public CVE/GHSA
ids and package names (the gate's `NEW <id> <pkg>` lines, kept only when they
match PUBLIC_NEW_LINE in full), each failing image's `:staged` age and the
date it passes the release's 3-day limit, and the run URL. Nothing else from
a log reaches it.

Environment (set by the workflow job): GH_REPO, RUN_ID, NEEDS (toJSON(needs)),
STAGE_REF, GITHUB_SERVER_URL. Tests: INFRA_RED_NOW (ISO time),
INFRA_RED_RETRY_SLEEP (seconds between log fetch attempts).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

LABEL = "infra-staged-red"
WORKFLOW = "infra-staged.yml"
# release-retag-plan.py STAGED_MAX_AGE_DAYS: an older :staged is not re-tagged.
STAGED_MAX_AGE_DAYS = 3
CREATED_LABEL = "org.opencontainers.image.created"
FAILED = {"failure", "cancelled", "timed_out", "startup_failure"}
# The ONLY log lines that may reach the public issue.
PUBLIC_NEW_LINE = re.compile(r"^\s*NEW (CVE|GHSA)-[0-9A-Za-z-]+ [A-Za-z0-9._-]+$")
LOG_TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z ?")
STAGE_JOB = re.compile(r"^([a-z0-9][a-z0-9._-]*) \(build, scan, stage\)$")
RUN_URL = re.compile(r"^https://[A-Za-z0-9.-]+/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/actions/runs/\d+$")
LIMIT_MEANS = ("the next release builds this image itself and gates it the same way; "
               "a NEW finding will block its signed lock")


def log(msg: str) -> None:
    print(f"infra-staged-red: {msg}", flush=True)


def gh(*args: str, check: bool = True) -> str:
    p = subprocess.run(["gh", *args], capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"gh {args[0]} {args[1] if len(args) > 1 else ''} failed ({p.returncode}): "
                           f"{p.stderr.strip()[:300]}")
    return p.stdout


def run_state(needs: dict) -> str:
    """'failed', 'green' or 'other' (e.g. everything skipped)."""
    results = [v.get("result") for v in needs.values()]
    if any(r in FAILED for r in results):
        return "failed"
    if results and all(r == "success" for r in results):
        return "green"
    return "other"


def previous_failures(repo: str, run_id: str) -> int:
    """Consecutive failed scheduled runs before this one (newest first)."""
    runs = json.loads(gh("run", "list", "-R", repo, "--workflow", WORKFLOW, "--event", "schedule",
                         "--json", "databaseId,status,conclusion", "--limit", "30") or "[]")
    n = 0
    for r in runs:
        if str(r.get("databaseId")) == str(run_id) or r.get("status") != "completed":
            continue
        if r.get("conclusion") in FAILED:
            n += 1
        else:
            break
    return n


def public_new_lines(text: str) -> tuple[list[str], int]:
    """(kept 'CVE-x pkg' pairs, number of NEW lines dropped by the filter)."""
    kept, dropped = [], 0
    for raw in text.splitlines():
        line = LOG_TIMESTAMP.sub("", raw.rstrip("\r\n"), count=1)
        if "NEW " not in line:
            continue
        if PUBLIC_NEW_LINE.match(line):
            pair = line.strip()[len("NEW "):]
            if pair not in kept:
                kept.append(pair)
        elif re.match(r"^\s*NEW \S", line):
            dropped += 1
    return kept, dropped


def failed_images(repo: str, run_id: str) -> list[tuple[str, str]]:
    """(image, job id) of every failed or cancelled stage job of this run."""
    data = json.loads(gh("api", f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100") or "{}")
    out = []
    for j in data.get("jobs") or []:
        m = STAGE_JOB.match(str(j.get("name", "")))
        if m and j.get("conclusion") in FAILED:
            out.append((m.group(1), str(j.get("id"))))
    return out


def job_log(repo: str, job_id: str) -> str:
    # The job is complete (this job needs it), but its log can take a moment
    # to become downloadable.
    delay = float(os.environ.get("INFRA_RED_RETRY_SLEEP", "15"))
    for attempt in range(3):
        try:
            return gh("api", f"repos/{repo}/actions/jobs/{job_id}/logs")
        except RuntimeError as e:
            log(f"job {job_id} log not readable yet ({e})")
            if attempt < 2:
                time.sleep(delay)
    return ""


def staged_created(owner: str, image: str) -> datetime | None:
    """The current :staged's build time, from its created label."""
    ref = f"ghcr.io/{owner}/{image}:staged"
    p = subprocess.run(["docker", "buildx", "imagetools", "inspect", ref, "--format", "{{json .Image}}"],
                       capture_output=True, text=True)
    if p.returncode != 0:
        return None
    try:
        d = json.loads(p.stdout)
        cands = [d] if "config" in d else list(d.values())
        for c in cands:
            v = ((c.get("config") or {}).get("Labels") or {}).get(CREATED_LABEL, "")
            if v:
                return datetime.fromisoformat(v.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, AttributeError, TypeError):
        return None
    return None


def body(n: int, run_url: str, images: list[tuple[str, list[str], int, datetime | None]], now: datetime) -> str:
    lines = [f"infra-staged has failed {n} runs in a row (the scheduled runs, this one included).", "",
             f"Run: {run_url}", ""]
    if not images:
        lines += ["No image job failed; a job before them (the matrix) did.", ""]
    for image, pairs, dropped, created in images:
        lines.append(f"### {image}")
        if created is None:
            lines.append("- `:staged` age: unknown (its created label could not be read)")
        else:
            age = now - created
            limit = created + timedelta(days=STAGED_MAX_AGE_DAYS)
            when = "passed" if now > limit else "passes"
            lines.append(f"- `:staged` built {created:%Y-%m-%d %H:%M} UTC, {age.days} day(s) old; "
                         f"it {when} the release's {STAGED_MAX_AGE_DAYS}-day limit on {limit:%Y-%m-%d %H:%M} UTC")
        if pairs:
            lines.append("- NEW fixable HIGH/CRITICAL findings (the gate's output):")
            lines += [f"  - {p}" for p in pairs]
        else:
            lines.append("- no NEW finding in its log: the build or the scan failed")
        if dropped:
            lines.append(f"- {dropped} more NEW line(s) not shown here: see the run")
        lines.append("")
    lines.append(f"Past the {STAGED_MAX_AGE_DAYS}-day limit, {LIMIT_MEANS}.")
    return "\n".join(lines) + "\n"


def ensure_label(repo: str) -> None:
    names = {x.get("name") for x in json.loads(gh("label", "list", "-R", repo, "--json", "name",
                                                  "--limit", "500") or "[]")}
    if LABEL not in names:
        gh("label", "create", LABEL, "-R", repo, "--color", "B60205",
           "--description", "infra-staged.yml failed two or more runs in a row")


def open_issues(repo: str) -> list[dict]:
    return json.loads(gh("issue", "list", "-R", repo, "--label", LABEL, "--state", "open",
                         "--json", "number,url", "--limit", "10") or "[]")


def main() -> int:
    repo = os.environ["GH_REPO"]
    run_id = os.environ["RUN_ID"]
    run_url = f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{repo}/actions/runs/{run_id}"
    if not RUN_URL.match(run_url):
        log("refusing an unexpected run URL shape")
        return 2
    stage_ref = os.environ.get("STAGE_REF", "refs/heads/dev")
    if stage_ref != "refs/heads/dev":
        # A dispatch from a branch says nothing about dev's daily build.
        log(f"built {stage_ref}, not dev: no issue is opened or closed")
        return 0
    state = run_state(json.loads(os.environ.get("NEEDS") or "{}"))
    now = datetime.fromisoformat(os.environ["INFRA_RED_NOW"]) if os.environ.get("INFRA_RED_NOW") \
        else datetime.now(timezone.utc)

    if state == "green":
        issues = open_issues(repo)
        for i in issues:
            gh("issue", "close", str(i["number"]), "-R", repo, "--comment",
               f"infra-staged is green again: {run_url}")
            log(f"closed #{i['number']}")
        if not issues:
            log("green; no open issue")
        return 0
    if state != "failed":
        log("neither failed nor green (skipped jobs): nothing to do")
        return 0

    prev = previous_failures(repo, run_id)
    if prev == 0:
        log("first failure; an issue opens on the next")
        return 0
    n = prev + 1
    owner = repo.split("/", 1)[0]
    images = []
    for image, job_id in failed_images(repo, run_id):
        pairs, dropped = public_new_lines(job_log(repo, job_id))
        images.append((image, pairs, dropped, staged_created(owner, image)))
    text = body(n, run_url, images, now)
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write(text)
        path = f.name
    issues = open_issues(repo)
    if issues:
        num = str(issues[0]["number"])
        gh("issue", "comment", num, "-R", repo, "--body-file", path)
        log(f"commented on #{num} ({n} failed runs in a row)")
    else:
        ensure_label(repo)
        gh("issue", "create", "-R", repo, "--title", f"infra-staged has failed {n} runs in a row",
           "--label", LABEL, "--body-file", path)
        log(f"opened an issue ({n} failed runs in a row)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
