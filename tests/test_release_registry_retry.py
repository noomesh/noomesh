# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A transient registry error must not cost a release a whole lane re-run.

The 0.6.10 release candidates lost two runs to errors a re-run cleared with
no change: `docker pull moby/buildkit` answering "unauthorized:
authentication required" inside setup-buildx, and "buildx failed with:
ERROR: failed to build: unknown blob". scripts/retry-registry.sh retries
those classes, bounded, and never a real build failure; the release
workflows route their registry-facing build steps through it.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/retry-registry.sh"
IMAGES = ROOT / ".github/workflows/images-release.yml"
WEB = ROOT / ".github/workflows/publish-web.yml"


def _run(tmp_path: Path, outputs: list[tuple[int, str]], attempts: str = "3"):
    """Run the wrapper around a fake command that answers `outputs` in turn."""
    state = tmp_path / "n"
    state.write_text("0")
    fake = tmp_path / "fake.sh"
    lines = ['#!/usr/bin/env bash', f'n=$(cat "{state}"); echo $((n + 1)) > "{state}"', 'case "$n" in']
    for i, (rc, out) in enumerate(outputs):
        lines.append(f"  {i}) printf '%s\\n' {out!r}; exit {rc} ;;")
    lines += ["  *) echo 'unexpected extra attempt'; exit 99 ;;", "esac"]
    fake.write_text("\n".join(lines) + "\n")
    fake.chmod(0o755)
    env = {**os.environ, "RETRY_ATTEMPTS": attempts, "RETRY_DELAY": "0"}
    r = subprocess.run(["bash", str(SCRIPT), str(fake)], env=env, capture_output=True, text=True)
    return r, int(state.read_text())


def test_unknown_blob_is_retried_and_then_passes(tmp_path):
    r, n = _run(tmp_path, [(1, "ERROR: failed to build: unknown blob"), (0, "pushed")])
    assert r.returncode == 0 and n == 2, r.stdout + r.stderr
    assert "transient registry error (attempt 1/3)" in r.stdout


def test_hub_unauthorized_on_a_public_pull_is_retried(tmp_path):
    r, n = _run(tmp_path, [(1, "Error response from daemon: unauthorized: authentication required"), (0, "ok")])
    assert r.returncode == 0 and n == 2


def test_a_failed_build_step_is_never_retried(tmp_path):
    """Even when the failing RUN printed a transient-looking line."""
    out = ('#12 ERROR: process "/bin/sh -c pip install x" did not complete successfully: exit code: 1\n'
           'connection reset by peer')
    r, n = _run(tmp_path, [(1, out), (0, "never")])
    assert r.returncode == 1 and n == 1, r.stdout + r.stderr
    assert "not retried" in r.stderr


def test_an_error_with_no_transient_class_is_not_retried(tmp_path):
    r, n = _run(tmp_path, [(17, "ERROR: failed to build: failed to read dockerfile: no such file"), (0, "never")])
    assert r.returncode == 17 and n == 1


def test_retries_are_bounded_and_keep_the_exit_code(tmp_path):
    r, n = _run(tmp_path, [(1, "unknown blob")] * 3 + [(0, "never")], attempts="3")
    assert r.returncode == 1 and n == 3, r.stdout + r.stderr
    assert "persisted after 3 attempt(s)" in r.stdout


def _steps(doc, job):
    return doc["jobs"][job]["steps"]


def test_every_release_image_build_goes_through_the_retry():
    text = IMAGES.read_text()
    builds = re.findall(r"^\s*(\S.*)docker buildx build --push", text, re.M)
    assert len(builds) == 3 and all(b.strip() == "scripts/retry-registry.sh" for b in builds), builds


def test_every_buildx_setup_is_prepulled_and_tried_twice():
    doc = yaml.safe_load(IMAGES.read_text())
    for job in ("deps-core", "deps-base", "images"):
        steps = _steps(doc, job)
        idx = [i for i, s in enumerate(steps) if "setup-buildx-action" in str(s.get("uses", ""))]
        assert len(idx) == 2, f"{job}: {len(idx)} setup-buildx steps"
        first, second = steps[idx[0]], steps[idx[1]]
        pre = steps[idx[0] - 1]
        assert "retry-registry.sh docker pull moby/buildkit" in str(pre.get("run", "")), job
        assert first.get("id") == "buildx" and first.get("continue-on-error") is True, job
        assert "steps.buildx.outcome == 'failure'" in second["if"] and "env.RETAG != 'true'" in second["if"], job
        assert first["uses"] == second["uses"], "the second attempt must use the same pinned action"


def test_the_console_push_is_tried_twice():
    doc = yaml.safe_load(WEB.read_text())
    steps = _steps(doc, "publish")
    pushes = [s for s in steps if "build-push-action" in str(s.get("uses", ""))]
    assert len(pushes) == 2
    assert pushes[0].get("id") == "push" and pushes[0].get("continue-on-error") is True
    assert pushes[1]["if"] == "steps.push.outcome == 'failure'"
    assert pushes[0]["uses"] == pushes[1]["uses"] and pushes[0]["with"] == pushes[1]["with"], "the retry must push the same thing"


def test_actions_stay_pinned_by_sha():
    for wf in (IMAGES, WEB):
        for m in re.finditer(r"^\s*(?:-\s*)?uses:\s*(\S+)", wf.read_text(), re.M):
            ref = m.group(1)
            assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref), f"{wf.name}: {ref} is not pinned by SHA"
