# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A cache save can never fail a CI job, and a cargo cache is pruned first.

Dev push run 38058038769 (2026-10-10) passed every noo-cli test and still went
red: the GitHub-hosted runner's disk filled while actions/cache/save tarred
~/.cargo + noo-cli/target. A red dev push is not cosmetic — the promotion gate
(scripts/ci-promotion-gate.py) proves promotions from dev's push-run success,
so a cache write forced the full CI on the next promotion.

The rules this pins, for every workflow:
  1. every actions/cache/save step is `continue-on-error: true`;
  2. every save of a cargo `target` is preceded, in the same job, by the
     prune step (scripts/ci-prune-cargo-target.sh) under the same `if:`;
  3. every "Free hosted-runner disk" step is gated on
     runner.environment == 'github-hosted' (no sudo, and not our disk, on a
     self-hosted box) and is itself continue-on-error.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"


def _jobs():
    for wf in sorted(WORKFLOWS.glob("*.y*ml")):
        doc = yaml.safe_load(wf.read_text())
        for name, job in (doc.get("jobs") or {}).items():
            yield wf.name, name, job.get("steps") or []


def _is_save(step) -> bool:
    return str(step.get("uses", "")).startswith("actions/cache/save@")


def test_the_scan_finds_the_cargo_cache_saves():
    saves = [(wf, job) for wf, job, steps in _jobs() for s in steps if _is_save(s)]
    # rust-gateway, sqlx-drift and noo-cli all save a cargo cache from dev.
    jobs = {job for _, job in saves}
    assert {"rust-gateway", "sqlx-drift", "noo-cli"} <= jobs, saves


def test_every_cache_save_is_continue_on_error():
    bad = [
        f"{wf}:{job}:{s.get('name')}"
        for wf, job, steps in _jobs()
        for s in steps
        if _is_save(s) and s.get("continue-on-error") is not True
    ]
    assert not bad, f"cache save steps that can fail the job: {bad}"


def test_cargo_target_saves_are_pruned_first():
    checked = 0
    bad = []
    for wf, job, steps in _jobs():
        for i, s in enumerate(steps):
            if not _is_save(s):
                continue
            paths = str((s.get("with") or {}).get("path", ""))
            target = next((p.strip() for p in paths.splitlines() if p.strip().endswith("/target")), None)
            if not target:
                continue
            crate = target[: -len("/target")]
            prunes = [
                p for p in steps[:i]
                if "ci-prune-cargo-target.sh" in str(p.get("run", ""))
                and f"ci-prune-cargo-target.sh {crate}" in str(p.get("run", ""))
            ]
            checked += 1
            if not prunes:
                bad.append(f"{wf}:{job}: saves {target} with no prune step before it")
                continue
            p = prunes[-1]
            if p.get("if") != s.get("if"):
                bad.append(f"{wf}:{job}: prune `if:` {p.get('if')!r} != save `if:` {s.get('if')!r}")
            if p.get("continue-on-error") is not True:
                bad.append(f"{wf}:{job}: prune step is not continue-on-error")
    assert checked >= 3, f"found only {checked} cargo target saves — did the scan break?"
    assert not bad, bad


def test_free_disk_steps_are_hosted_only():
    found = 0
    bad = []
    for wf, job, steps in _jobs():
        for s in steps:
            if "Free hosted-runner disk" not in str(s.get("name", "")):
                continue
            found += 1
            if "runner.environment == 'github-hosted'" not in str(s.get("if", "")):
                bad.append(f"{wf}:{job}: not gated on github-hosted")
            if s.get("continue-on-error") is not True:
                bad.append(f"{wf}:{job}: not continue-on-error")
    assert found >= 1
    assert not bad, bad


def test_prune_script_exists_and_is_executable():
    script = ROOT / "scripts" / "ci-prune-cargo-target.sh"
    assert script.is_file()
    assert script.stat().st_mode & 0o111
