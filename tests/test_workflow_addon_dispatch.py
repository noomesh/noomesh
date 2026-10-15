# SPDX-License-Identifier: AGPL-3.0-only
"""The stack release tells the add-on repos when its signed lock publishes.

Add-on bundles ride the stack tag, so the gap between a stack tag and its
add-on bundles is closed by dispatching `stack-tag-published` the moment the
`signed digest lock` job succeeds. What this pins:

  * the dispatch job runs only after the lock job succeeded, in the `release`
    environment (where the PAT secret lives), with no GITHUB_TOKEN powers;
  * the payload is `{tag, lock_digest}` with the event type the add-on
    workflows listen for;
  * public forks and OSS builds are unaffected: no repo list, or no token,
    is a notice and exit 0, not a failure; the public file names no org;
  * the token is never echoed, traced or put on a command line.
"""
from pathlib import Path

import yaml

WF = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "images-release.yml"
TEXT = WF.read_text()
DOC = yaml.safe_load(TEXT)
JOB = DOC["jobs"]["addon-dispatch"]
RUN = JOB["steps"][0]["run"]


def test_runs_only_after_the_signed_lock_job_succeeded():
    assert JOB["needs"] == "lock"
    assert "needs.lock.result == 'success'" in JOB["if"]
    assert "github.repository == 'noomesh/noomesh'" in JOB["if"]
    assert DOC["jobs"]["lock"]["name"] == "signed digest lock"


def test_the_token_lives_in_the_release_environment_and_the_job_holds_no_other_power():
    assert JOB["environment"] == "release"
    assert JOB["permissions"] == {}
    assert JOB["steps"][0]["env"]["NOO_ADDON_DISPATCH_TOKEN"] == "${{ secrets.NOO_ADDON_DISPATCH_TOKEN }}"


def test_the_target_list_is_a_repo_variable_not_a_hardcoded_org():
    assert JOB["steps"][0]["env"]["NOO_ADDON_REPOS"] == "${{ vars.NOO_ADDON_REPOS }}"
    assert "personifai" not in TEXT.lower().split("addon-dispatch:")[1]


def test_unconfigured_is_a_notice_and_exit_zero():
    for name in ("NOO_ADDON_REPOS", "NOO_ADDON_DISPATCH_TOKEN"):
        i = RUN.index(f"::notice::{name} is not set")
        assert "exit 0" in RUN[i : i + 400], name


def test_the_payload_is_tag_and_lock_digest_with_the_event_the_addons_listen_for():
    assert "stack-tag-published" in RUN
    assert '"client_payload":{"tag":sys.argv[1],"lock_digest":sys.argv[2]}' in RUN
    assert "/repos/$r/dispatches" in RUN
    out = DOC["jobs"]["lock"]["outputs"]
    assert set(out) == {"tag", "lock_digest"}


def test_the_token_is_never_printed_or_traced():
    assert "set -x" not in RUN and "set -eux" not in RUN
    assert "xtrace" not in RUN
    for line in RUN.splitlines():
        if "echo" in line:
            assert "$NOO_ADDON_DISPATCH_TOKEN" not in line, line
    assert RUN.count("$NOO_ADDON_DISPATCH_TOKEN") == 1, "only the Authorization header uses it"
    assert "-o /dev/null" in RUN, "the response body is discarded"


def test_a_refused_dispatch_fails_the_job_after_trying_every_repo():
    assert 'exit "$bad"' in RUN and "bad=1" in RUN
