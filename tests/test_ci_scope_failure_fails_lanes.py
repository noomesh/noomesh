# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A failed `scope` job FAILS the required lanes; it never skips them (2026-11-11).

Every lane below needed `needs.scope.result == 'success'` in its `if:`. If
`scope` failed, they were SKIPPED, and GitHub reports a skipped job as Success
to a required check ("It will not prevent a pull request from merging, even if
it is a required check", docs: using-conditions-to-control-job-execution). So
a broken scope passed every lane it gates. `scope` is not a required check.
test-core already guards this ("deferral is never the fallback"); these did not.

Now each lane runs whatever scope did (only `!cancelled()` and, where it
needs it, a green preflight), and its FIRST step fails when scope did not
succeed, before any checkout or work.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

CI = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"
DOC = yaml.safe_load(CI.read_text())
JOBS = DOC["jobs"]

# The required contexts that need scope (ruleset 25029394), plus sqlx-drift and
# router-harness, proposed as required on 2026-11-11.
GATED = ("go-node-agent", "rust-gateway", "noo-cli", "standalone-smoke", "sqlx-drift", "router-harness")


def test_no_gated_lane_is_skipped_by_a_failed_scope():
    for name in GATED:
        job = JOBS[name]
        assert "scope" in job["needs"], name
        cond = str(job.get("if", ""))
        assert "needs.scope.result" not in cond, f"{name}: a scope condition in `if:` turns a failed scope into a skip"
        assert "!cancelled()" in cond, name


def test_the_first_step_of_each_gated_lane_fails_when_scope_did_not_succeed():
    for name in GATED:
        first = JOBS[name]["steps"][0]
        assert first.get("name") == "Scope must have succeeded", f"{name}: the check must come before any work"
        assert first.get("if") == "needs.scope.result != 'success'", name
        run = first["run"]
        assert re.search(r"^exit 1$", run.strip().splitlines()[-1]), name
        assert "${{" not in run, f"{name}: pass the result through env:, not into the script"
        assert first.get("env", {}).get("SCOPE_RESULT") == "${{ needs.scope.result }}", name


def test_test_core_still_runs_when_scope_fails():
    cond = str(JOBS["test-core"]["if"])
    assert "needs.scope.result == 'success' &&" not in cond.replace("!(needs.scope.result == 'success' &&", ""), \
        "test-core may only be skipped when scope POSITIVELY defers it"


def test_every_job_that_needs_scope_is_gated_or_known_optional():
    # A new job that needs scope must choose: gated (fail on a broken scope)
    # or listed here as not required, where skipping is harmless.
    optional = {"test-core", "test-core-advisory", "ui", "build", "llamacpp-image", "ollama-image", "voice-images"}
    for name, job in JOBS.items():
        needs = job.get("needs") or []
        needs = [needs] if isinstance(needs, str) else needs
        if "scope" in needs:
            assert name in GATED or name in optional, f"{name} needs scope: add it to GATED or to the optional list"
