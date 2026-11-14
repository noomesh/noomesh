# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Image layers are reproducible (2026-11-11).

Our layers got a new digest on every build, even ollama's 1688.5 MB copy of
upstream's unchanged runners, so every roll re-downloaded them (2776 MB per
amd64 node from 0.6.21 to 0.6.22). Every image build now clamps file times
to SOURCE_DATE_EPOCH (buildx `rewrite-timestamp=true`), and the epoch is the
newest commit touching the image's declared inputs (scripts/build-epoch.py).

The epoch tests run the REAL script in a throwaway git repo; the workflow
tests read every `docker buildx build` in the two build workflows.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
EPOCH = ROOT / "scripts" / "build-epoch.py"
WORKFLOWS = [ROOT / ".github" / "workflows" / "images-release.yml",
             ROOT / ".github" / "workflows" / "infra-staged.yml"]


# ---- scripts/build-epoch.py ------------------------------------------------

def _git(repo: Path, *args: str, env: dict | None = None) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=True, env=env).stdout.strip()


def _commit(repo: Path, files: dict[str, str], when: int) -> None:
    for name, text in files.items():
        p = repo / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    _git(repo, "add", "-A")
    env = {**os.environ, "GIT_AUTHOR_DATE": f"@{when} +0000", "GIT_COMMITTER_DATE": f"@{when} +0000"}
    _git(repo, "commit", "-qm", f"at {when}", env=env)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "r"
    (repo / "scripts").mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "dev")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    shutil.copy(EPOCH, repo / "scripts" / "build-epoch.py")
    table = {"images": {
        "base": {"parents": [], "inputs": ["docker/Dockerfile.base"]},
        "child": {"parents": ["base"], "inputs": ["docker/Dockerfile.child", "src/**"]},
        "other": {"parents": [], "inputs": ["docker/Dockerfile.other"]},
    }}
    _commit(repo, {"scripts/release-image-inputs.json": json.dumps(table),
                   "docker/Dockerfile.base": "1", "docker/Dockerfile.child": "1",
                   "docker/Dockerfile.other": "1", "src/a.py": "1"}, 1_000_000)
    _commit(repo, {"src/deep/b.py": "2"}, 2_000_000)          # child's input
    _commit(repo, {"docker/Dockerfile.base": "3"}, 3_000_000)  # base's, so child's too
    _commit(repo, {"README.md": "4"}, 4_000_000)               # nobody's input
    return repo


def _epoch(repo: Path, image: str) -> subprocess.CompletedProcess:
    return subprocess.run(["python3", str(repo / "scripts" / "build-epoch.py"), image],
                          capture_output=True, text=True)


def test_the_epoch_is_the_newest_commit_touching_the_images_own_or_parents_inputs(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    got = {i: _epoch(repo, i).stdout.strip() for i in ("base", "child", "other")}
    assert got == {"base": "3000000", "child": "3000000", "other": "1000000"}, got
    assert _git(repo, "log", "-1", "--format=%ct") == "4000000", \
        "HEAD is newer than every input: the epoch must not follow it"
    _commit(repo, {"src/deep/c.py": "5"}, 5_000_000)
    assert _epoch(repo, "child").stdout.strip() == "5000000", "a ** glob reaches nested inputs"
    assert _epoch(repo, "base").stdout.strip() == "3000000", "a child's input never moves its parent"


def test_a_shallow_clone_or_an_undeclared_image_is_refused(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{repo}", str(shallow)], check=True)
    r = _epoch(shallow, "other")
    assert r.returncode == 1 and "shallow clone" in r.stderr and r.stdout == "", \
        "a shallow log dates every file to HEAD: the epoch would silently move every commit"
    r = _epoch(repo, "nope")
    assert r.returncode == 1 and "no declared inputs" in r.stderr and r.stdout == ""


def test_every_real_image_has_an_epoch() -> None:
    if _git(ROOT, "rev-parse", "--is-shallow-repository") != "false":
        import pytest
        pytest.skip("shallow checkout")
    table = json.loads((ROOT / "scripts" / "release-image-inputs.json").read_text())["images"]
    for image in table:
        r = subprocess.run(["python3", str(EPOCH), image], capture_output=True, text=True)
        assert r.returncode == 0 and r.stdout.strip().isdigit(), (image, r.stderr)


# ---- the workflows ---------------------------------------------------------

def _build_steps():
    for wf in WORKFLOWS:
        doc = yaml.safe_load(wf.read_text())
        for job_name, job in doc["jobs"].items():
            steps = job.get("steps", [])
            for s in steps:
                if "docker buildx build" in str(s.get("run", "")):
                    yield wf.name, job_name, steps, s["run"]


def test_every_image_build_clamps_its_layers_to_the_inputs_epoch() -> None:
    builds = list(_build_steps())
    assert len(builds) == 4, [(w, j) for w, j, _, _ in builds]  # deps-core, deps-base, images, staged
    for wf, job, steps, run in builds:
        where = f"{wf} / {job}"
        assert run.count("docker buildx build") == 1, where
        assert "--push" not in run, f"{where}: --push cannot carry rewrite-timestamp"
        assert "--output type=registry,rewrite-timestamp=true" in run, where
        m = re.search(r'^\s*SOURCE_DATE_EPOCH="\$\(python3 scripts/build-epoch\.py ([^)]+)\)"\s*\n\s*export SOURCE_DATE_EPOCH\s*$',
                      run, re.M)
        assert m, f'{where}: assign SOURCE_DATE_EPOCH from build-epoch.py, then export it (export X="$(…)" hides a refusal)'
        assert run.index("export SOURCE_DATE_EPOCH") < run.index("docker buildx build"), where
        assert re.match(r"^set -\w*e", run.strip()), f"{where}: a refused epoch must stop the step"
        assert "--build-arg SOURCE_DATE_EPOCH" not in run, f"{where}: buildx passes the env itself"
        checkout = next(s for s in steps if "actions/checkout@" in str(s.get("uses", "")))
        w = checkout.get("with") or {}
        assert w.get("fetch-depth") == 0, f"{where}: build-epoch.py needs full history"


def test_the_epoch_names_the_image_the_step_builds() -> None:
    names = {}
    for wf, job, _, run in _build_steps():
        names[(wf, job)] = re.search(r"build-epoch\.py ([^)]+)\)", run).group(1).strip('"')
    assert names[("images-release.yml", "deps-core")] == "deps-core"
    assert names[("images-release.yml", "deps-base")] == "deps-base"
    assert names[("images-release.yml", "images")] == "${{ matrix.image }}"
    assert names[("infra-staged.yml", "stage")] == "${{ matrix.image }}"
