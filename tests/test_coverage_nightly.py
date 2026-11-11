# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Coverage runs once a night, not on every PR and merge-queue run.

Operator, 2026-11-11: nothing gates on coverage, and producing it cost every
test-core run its overhead, so the PR/queue command runs without `--cov`, and
.github/workflows/coverage-nightly.yml produces the same `coverage-py`
artifact on dev each night. The nightly job runs ci.yml's OWN test-core steps,
read at run time with scripts/ci_step.py, with coverage switched on through
PYTEST_ADDOPTS, so the two can never be two different suites.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CI = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
NIGHTLY = yaml.safe_load((ROOT / ".github/workflows/coverage-nightly.yml").read_text())


def _step(job: dict, name: str) -> dict:
    return next(s for s in job["steps"] if s.get("name") == name)


def test_pr_and_queue_test_core_produces_no_coverage() -> None:
    steps = CI["jobs"]["test-core"]["steps"]
    run = _step(CI["jobs"]["test-core"], "Run tests")["run"]
    assert "pytest tests/ -v -n auto" in run, run
    command = [l for l in run.splitlines() if l.strip().startswith("pytest tests/")]
    assert len(command) == 1 and "--cov" not in command[0], f"coverage is the nightly job's, not every PR's: {command}"
    assert not any("upload-artifact" in str(s.get("uses", "")) and "coverage" in str(s) for s in steps)


def test_the_nightly_job_runs_ci_yml_s_own_steps_with_coverage() -> None:
    on = NIGHTLY.get(True, NIGHTLY.get("on"))  # yaml reads a bare `on:` as True
    assert set(on) == {"schedule", "workflow_dispatch"}, "never a PR or push trigger: it must not add to a PR's time"
    job = NIGHTLY["jobs"]["coverage"]
    run = _step(job, "Run ci.yml's test-core steps, with coverage")["run"]
    for name in ("Is trellion declared public? (TRELLION_PUBLIC)", "Install dependencies", "Run tests"):
        assert f"step test-core '{name}'" in run, name
        _step(CI["jobs"]["test-core"], name)  # the step it reads still exists
    assert 'PYTEST_ADDOPTS="--cov=noomesh --cov-report=xml" bash -e -c "$run_body"' in run
    up = _step(job, "Upload coverage artifact")["with"]
    assert (up["name"], up["path"]) == ("coverage-py", "coverage.xml"), "same artifact name, so people find it"
    assert NIGHTLY["permissions"] == {"contents": "read"}
    assert job["steps"][0]["with"]["ref"] == "dev"
