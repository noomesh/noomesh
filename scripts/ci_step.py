#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Print one CI step's `run:` body, for running it locally verbatim.

    python3 scripts/ci_step.py <job> <step name>          # the run body
    python3 scripts/ci_step.py --env <job> <step name>    # its env: keys, one per line
    python3 scripts/ci_step.py --workflow-env <KEY>       # a top-level env: value (e.g. a switch)

scripts/test-core-local.sh uses this so a local test-core run installs and
runs exactly what .github/workflows/ci.yml does, with no hand-copied package
list to drift.

A body is REFUSED (exit 2, naming the step) when it could need or print a
credential locally: any `${{ }}` expression (GitHub substitutes those, a
local shell would not, and `secrets.` lives there), `sudo`, `GITHUB_TOKEN`
or `docker login`. The same holds for the step's env values, except the
`steps.<id>.outputs.` and `job.services.` expressions the local runner
supplies itself.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"

# What a step run locally must never contain.
FORBIDDEN = (
    ("${{", "a GitHub expression (`${{ }}`) that only CI substitutes"),
    ("sudo", "sudo"),
    ("GITHUB_TOKEN", "GITHUB_TOKEN"),
    ("docker login", "docker login"),
)
# Env-value expressions the local runner replaces with its own value.
LOCAL_ENV_EXPR = re.compile(r"\$\{\{\s*(?:steps\.[a-z0-9_-]+\.outputs\.[a-z0-9_]+|job\.services\.[a-z0-9_]+\.ports\['\d+'\]|github\.workspace)\s*\}\}")


class StepError(Exception):
    """The step is missing, ambiguous, or unsafe to run locally."""


def find_step(job: str, name: str, workflow: Path = WORKFLOW) -> dict:
    doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    steps = (doc.get("jobs", {}).get(job) or {}).get("steps") or []
    hits = [s for s in steps if s.get("name") == name]
    if len(hits) != 1:
        raise StepError(f"{workflow.name}: job {job!r} has {len(hits)} steps named {name!r} (want exactly 1)")
    if not isinstance(hits[0].get("run"), str):
        raise StepError(f"{workflow.name}: {job} / {name!r} has no run: body")
    return hits[0]


def refusal(step: dict, job: str) -> str | None:
    """Why this step must not run locally, or None."""
    name = step.get("name")
    for needle, what in FORBIDDEN:
        if needle in step["run"]:
            return f"{job} / {name!r}: its run body uses {what}; refusing to run it locally"
    for key, value in (step.get("env") or {}).items():
        v = LOCAL_ENV_EXPR.sub("", str(value))
        for needle, what in FORBIDDEN:
            if needle in v:
                return f"{job} / {name!r}: env {key} uses {what}; refusing to run it locally"
    return None


def safe_step(job: str, name: str, workflow: Path = WORKFLOW) -> dict:
    step = find_step(job, name, workflow)
    why = refusal(step, job)
    if why:
        raise StepError(why)
    return step


def workflow_env(key: str, workflow: Path = WORKFLOW) -> str:
    doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    env = doc.get("env") or {}
    if key not in env:
        raise StepError(f"{workflow.name}: no top-level env {key}")
    value = str(env[key])
    for needle, what in FORBIDDEN:
        if needle in value:
            raise StepError(f"{workflow.name}: top-level env {key} uses {what}; refusing to read it locally")
    return value


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--workflow-env":
        if len(argv) != 2:
            print(__doc__.strip().splitlines()[4], file=sys.stderr)
            return 64
        try:
            print(workflow_env(argv[1], WORKFLOW))
        except StepError as e:
            print(f"ci_step: {e}", file=sys.stderr)
            return 2
        return 0
    env_only = bool(argv) and argv[0] == "--env"
    args = argv[1:] if env_only else argv
    if len(args) != 2:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 64
    try:
        step = safe_step(args[0], args[1], WORKFLOW)
    except StepError as e:
        print(f"ci_step: {e}", file=sys.stderr)
        return 2
    if env_only:
        print("\n".join(sorted((step.get("env") or {}).keys())))
    else:
        sys.stdout.write(step["run"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
