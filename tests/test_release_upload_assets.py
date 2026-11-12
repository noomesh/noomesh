# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The CLI release uploads its assets one at a time, retrying transient errors.

noo-cli-v0.6.22-rc.1 lost a job run to one `HTTP 408: Upload body timed out
due to inactivity` (run 42862153616): a single `gh release create` uploaded
every asset with no retry. scripts/release-upload-assets.sh uploads each one
with `--clobber` and retries only a transient failure, bounded; the workflow
creates a DRAFT first and publishes only after every asset is in. These run
the REAL script against a fake `gh`.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release-upload-assets.sh"
WF = ROOT / ".github" / "workflows" / "noo-cli-release.yml"

FAKE_GH = """#!/bin/sh
# Each call takes the next scripted answer: "ok" or "<rc>:<message>".
n=$(cat "$STATE/n" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > "$STATE/n"
echo "$*" >> "$STATE/calls"
ans=$(sed -n "${n}p" "$STATE/answers"); [ -n "$ans" ] || ans=ok
[ "$ans" = ok ] && exit 0
echo "${ans#*:}" >&2; exit "${ans%%:*}"
"""


def _run(tmp_path: Path, answers: list[str], files: list[str]) -> tuple[subprocess.CompletedProcess, list[str]]:
    bindir, state = tmp_path / "bin", tmp_path / "state"
    bindir.mkdir(exist_ok=True)
    state.mkdir(exist_ok=True)
    (bindir / "gh").write_text(FAKE_GH)
    (bindir / "gh").chmod(0o755)
    (state / "answers").write_text("\n".join(answers) + "\n")
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "STATE": str(state), "RETRY_DELAY": "0"}
    p = subprocess.run(["bash", str(SCRIPT), "o/r", "noo-cli-v1.2.3-rc.1", *files], capture_output=True, text=True, env=env)
    calls = (state / "calls").read_text().splitlines() if (state / "calls").exists() else []
    return p, calls


def _asset(tmp_path: Path, name: str) -> str:
    f = tmp_path / name
    f.write_text("x")
    return str(f)


def test_a_transient_failure_is_retried_and_each_asset_is_uploaded_alone(tmp_path: Path) -> None:
    a, b = _asset(tmp_path, "noo-a"), _asset(tmp_path, "noo-b")
    p, calls = _run(tmp_path, ["1:HTTP 408: Upload body timed out due to inactivity", "1:HTTP 502: Bad Gateway", "ok", "ok"], [a, b])
    assert p.returncode == 0, p.stderr
    assert len(calls) == 4 and all("--clobber" in c and "release upload noo-cli-v1.2.3-rc.1" in c for c in calls), calls
    assert calls[:3] == [calls[0]] * 3 and calls[0].endswith(a) and calls[3].endswith(b), calls


def test_a_real_failure_is_not_retried(tmp_path: Path) -> None:
    p, calls = _run(tmp_path, ["1:HTTP 404: Not Found (release noo-cli-v1.2.3-rc.1)"], [_asset(tmp_path, "noo-a")])
    assert p.returncode == 1 and len(calls) == 1, (p.stderr, calls)
    assert "404" in p.stderr


def test_retries_are_bounded(tmp_path: Path) -> None:
    p, calls = _run(tmp_path, ["1:HTTP 408: timed out"] * 5, [_asset(tmp_path, "noo-a")])
    assert p.returncode == 1 and len(calls) == 3, (p.stderr, calls)
    assert "attempt 3 of 3" in p.stderr


def test_a_missing_asset_fails_before_any_upload(tmp_path: Path) -> None:
    p, calls = _run(tmp_path, [], [str(tmp_path / "never-built")])
    assert p.returncode == 1 and calls == [], (p.stderr, calls)


def test_the_release_is_a_draft_until_every_asset_is_uploaded() -> None:
    steps = yaml.safe_load(WF.read_text())["jobs"]["release"]["steps"]
    run = next(s for s in steps if s.get("name") == "Create GitHub Release")["run"]
    create = run.index('gh release create "${TAG}" --repo "$repo" --draft')
    upload = run.index('scripts/release-upload-assets.sh "$repo" "${TAG}"')
    publish = run.index('gh release edit "${TAG}" --repo "$repo" --draft=false $flags')
    assert create < upload < publish, run
    assert 'false) echo "::error::${TAG} is already published' in run, "a published release is never touched"
    assert "gh release upload" not in run, "every upload goes through the retrying script"
