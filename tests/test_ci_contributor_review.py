# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""contributor-review: the required check that lets same-repo PRs queue and
holds fork PRs for a maintainer approval on the current head. Pins the
workflow's security shape and unit-tests the decision function that lives
inline in the workflow (nothing may be checked out, so there is no script file).
"""
from __future__ import annotations

import re
import urllib.error
from pathlib import Path

import yaml

WF = Path(__file__).resolve().parents[1] / ".github/workflows/contributor-review.yml"
TEXT = WF.read_text()
BODY = "\n" + TEXT.split("\nname: contributor-review", 1)[1]  # comments excluded
DOC = yaml.safe_load(TEXT)
ON = DOC.get("on", DOC.get(True))  # YAML 1.1 parses a bare `on` as True
JOB = DOC["jobs"]["contributor-review"]
STEPS = JOB["steps"]
DECIDE = next(s for s in STEPS if s.get("shell", "").startswith("python"))
MERGE = next(s for s in STEPS if s["if"] == "github.event_name == 'merge_group'")

REPO, SHA, OLD = "noomesh/noomesh", "a" * 40, "b" * 40


def _ns():
    ns: dict = {"__name__": "contributor_review"}
    exec(compile(DECIDE["run"], "contributor-review", "exec"), ns)
    return ns


NS = _ns()
decide = NS["decide"]


def review(user, state="APPROVED", sha=SHA):
    return {"user": {"login": user}, "state": state, "commit_id": sha}


def writers(*names):
    return lambda u: u in names


# ---- workflow shape -------------------------------------------------------

def test_no_pull_request_target_checkout_or_secrets():
    assert "pull_request_target" not in BODY
    assert "pull_request_target" not in ON
    assert not any("uses" in s for s in STEPS), "no actions at all: nothing to pin or hijack"
    assert "checkout" not in BODY
    assert "secrets." not in BODY


def test_permissions_read_only():
    assert DOC["permissions"] == {"pull-requests": "read", "contents": "read"}
    assert all(v == "read" for v in JOB.get("permissions", {}).values())


def test_job_name_and_triggers():
    assert JOB["name"] == "contributor-review"
    assert set(DOC["jobs"]) == {"contributor-review"}
    assert set(ON) == {"pull_request", "pull_request_review", "merge_group"}
    assert ON["pull_request"]["types"] == ["opened", "reopened", "synchronize", "ready_for_review"]
    assert ON["pull_request_review"]["types"] == ["submitted", "dismissed"]
    assert ON["merge_group"]["types"] == ["checks_requested"]


def test_merge_group_passes_and_gate_is_skipped_there():
    assert "exit" not in MERGE["run"] and "uses" not in MERGE
    assert DECIDE["if"] == "github.event_name != 'merge_group'"


def test_internal_external_inputs_are_the_designed_expressions():
    env = DECIDE["env"]
    assert env["REPO"] == "${{ github.repository }}"
    assert env["HEAD_REPO"] == "${{ github.event.pull_request.head.repo.full_name }}"
    assert env["HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    # event data reaches the script only through env, never interpolated into code
    assert "${{" not in DECIDE["run"]


def test_author_association_never_grants_a_pass():
    run = DECIDE["run"]
    assert "AUTHOR_ASSOCIATION" in run  # logged
    assert not re.search(r"\b(OWNER|MEMBER|COLLABORATOR)\b", run)
    assert run.count("author_association") == 1  # only in the log line


# ---- decision function ----------------------------------------------------

def test_same_repo_passes_without_review():
    ok, why = decide(REPO, REPO, SHA, [], writers())
    assert ok and why.startswith("internal")


def test_fork_without_review_fails_with_message():
    ok, why = decide("evil/noomesh", REPO, SHA, [], writers("alice"))
    assert not ok and why == (
        "external contribution: a maintainer must approve the current head before it can be queued")


def test_fork_approved_by_writer_on_current_sha_passes():
    ok, why = decide("evil/noomesh", REPO, SHA, [review("alice")], writers("alice"))
    assert ok and "alice" in why


def test_approval_on_old_sha_fails():
    assert not decide("evil/noomesh", REPO, SHA, [review("alice", sha=OLD)], writers("alice"))[0]


def test_approval_by_read_only_user_fails():
    assert not decide("evil/noomesh", REPO, SHA, [review("bob")], writers("alice"))[0]


def test_head_repo_null_is_external():
    for head in (None, ""):
        assert not decide(head, REPO, SHA, [], writers("alice"))[0]
        assert decide(head, REPO, SHA, [review("alice")], writers("alice"))[0]


def test_later_changes_requested_or_dismissal_revokes_that_approval():
    for state in ("CHANGES_REQUESTED", "DISMISSED"):
        revs = [review("alice"), review("alice", state=state)]
        assert not decide("f/n", REPO, SHA, revs, writers("alice"))[0]


def test_comment_review_does_not_revoke_and_does_not_approve():
    assert decide("f/n", REPO, SHA, [review("alice"), review("alice", "COMMENTED")], writers("alice"))[0]
    assert not decide("f/n", REPO, SHA, [review("alice", "COMMENTED")], writers("alice"))[0]


def test_one_writer_approval_suffices_among_others():
    revs = [review("bob"), review("carol", "CHANGES_REQUESTED"), review("alice")]
    assert decide("f/n", REPO, SHA, revs, writers("alice"))[0]


def test_can_write_fails_closed_and_accepts_maintain():
    cw = NS["can_write"]

    def boom(path):
        raise urllib.error.HTTPError(path, 403, "no", {}, None)

    NS["api"] = boom
    assert cw(REPO, "x") is False
    for perm, role, want in (("write", "write", True), ("admin", "admin", True),
                             ("write", "maintain", True), ("read", "triage", False),
                             ("none", None, False), ("read", "read", False)):
        NS["api"] = lambda path, p=perm, r=role: {"permission": p, "role_name": r}
        assert cw(REPO, "x") is want, (perm, role)
