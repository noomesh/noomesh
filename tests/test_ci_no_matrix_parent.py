# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""ci.yml has no matrix job.

A pull request opened with the `full-ci` label fires `opened` and `labeled`
together, and the PR concurrency group lets the later run cancel the earlier.
A matrix job cancelled before it splits leaves one check named after the bare
job, which no check in the surviving run replaces (its legs carry the matrix
values), so the PR's rollup keeps a CANCELLED entry and the enqueue rule
(a cancelled check refuses) blocks the PR. `rust-advisories` was that job
(2026-11-18); it is two named jobs now. Every non-matrix job keeps its name in
both runs, so the later run's result replaces the cancelled one.
"""
from pathlib import Path

import yaml

CI = Path(__file__).resolve().parent.parent / ".github" / "workflows" / "ci.yml"


def test_no_job_in_ci_yml_is_a_matrix():
    jobs = yaml.safe_load(CI.read_text())["jobs"]
    matrix = [k for k, j in jobs.items() if (j.get("strategy") or {}).get("matrix")]
    assert matrix == [], f"matrix jobs in ci.yml leave a cancelled parent check on a superseded PR run: {matrix}"


def test_the_advisory_legs_keep_their_check_names():
    jobs = yaml.safe_load(CI.read_text())["jobs"]
    names = sorted(j.get("name", "") for k, j in jobs.items() if k.startswith("rust-advisories"))
    assert names == ["rust-advisories (gateway-rust)", "rust-advisories (noo-cli)"], names
