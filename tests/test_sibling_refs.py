# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Promotion-time sibling installs use the release line's commits.

A staging->main promotion once went red because a job installed trellion from
trellion's DEV branch (pyproject's `[trellion]` extra), and a trellion dev
merge had added a dependency. The job must test the siblings the release pins: a PR or push into
staging -> sibling staging heads, main -> sibling mains, dev -> dev, resolved
to SHAs once, by the same script the release line uses.
"""
from __future__ import annotations

import re
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github/workflows"
SCRIPT = ROOT / "scripts/sibling-refs.py"

_spec = importlib.util.spec_from_file_location("sibling_refs", SCRIPT)
sibling_refs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sibling_refs)


@pytest.mark.parametrize("base,line", [
    ("dev", "dev"), ("develop", "dev"), ("staging", "staging"), ("main", "main"),
])
def test_the_line_for_each_base(base: str, line: str) -> None:
    assert sibling_refs.line_for(base) == line
    out = subprocess.run([sys.executable, str(SCRIPT), "line", base], capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.strip() == line


@pytest.mark.parametrize("base", ["feature/x", "release", "", "Main"])
def test_any_other_base_is_refused(base: str) -> None:
    out = subprocess.run([sys.executable, str(SCRIPT), "line", base], capture_output=True, text=True)
    assert out.returncode == 1
    assert "no sibling branch" in out.stderr


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True,
                          env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                               "GIT_COMMITTER_EMAIL": "t@t", "HOME": str(cwd), "PATH": "/usr/bin:/bin"}).stdout.strip()


@pytest.fixture
def siblings(tmp_path: Path) -> dict[str, dict[str, str]]:
    """One local repo per sibling with a distinct commit on dev, staging and main."""
    heads: dict[str, dict[str, str]] = {}
    for repo in sibling_refs.SIBLINGS.values():
        d = tmp_path / "personifAI" / repo
        d.mkdir(parents=True)
        _git(d, "init", "-q", "-b", "dev")
        heads[repo] = {}
        for branch in ("dev", "staging", "main"):
            if branch != "dev":
                _git(d, "checkout", "-q", "-b", branch)
            (d / "f").write_text(f"{repo} {branch}\n")
            _git(d, "add", "f")
            _git(d, "commit", "-q", "-m", branch)
            heads[repo][branch] = _git(d, "rev-parse", "HEAD")
    heads["_root"] = {"path": str(tmp_path)}
    return heads


@pytest.mark.parametrize("base,line", [("staging", "staging"), ("main", "main"), ("dev", "dev")])
def test_resolve_pins_each_sibling_to_its_line_head(siblings, tmp_path: Path, base: str, line: str) -> None:
    root = siblings["_root"]["path"]
    out_file = tmp_path / "gh_output"
    p = subprocess.run(
        [sys.executable, str(SCRIPT), "resolve", sibling_refs.line_for(base), "trellion",
         "--url-template", f"file://{root}/{{org}}/{{repo}}"],
        capture_output=True, text=True, env={"GITHUB_OUTPUT": str(out_file), "PATH": "/usr/bin:/bin"})
    assert p.returncode == 0, p.stderr
    rows = dict(r.split("=", 1) for r in out_file.read_text().split())
    assert rows == {
        "trellion_sha": siblings["trellion"][line],
    }
    # Never a neighbouring line's head.
    for other in {"dev", "staging", "main"} - {line}:
        assert rows["trellion_sha"] != siblings["trellion"][other]


def test_resolve_fails_loudly_on_a_missing_branch(siblings, tmp_path: Path) -> None:
    root = siblings["_root"]["path"]
    d = Path(root) / "personifAI" / "trellion"
    _git(d, "checkout", "-q", "dev")
    _git(d, "branch", "-D", "main")
    p = subprocess.run(
        [sys.executable, str(SCRIPT), "resolve", "main", "trellion",
         "--url-template", f"file://{root}/{{org}}/{{repo}}"],
        capture_output=True, text=True, env={"GITHUB_OUTPUT": str(tmp_path / "o"), "PATH": "/usr/bin:/bin"})
    assert p.returncode == 1
    assert "could not resolve personifAI/trellion main" in p.stderr


def test_resolve_refuses_a_non_line() -> None:
    with pytest.raises(SystemExit):
        sibling_refs.resolve("feature", ["trellion"], "file:///nonexistent/{org}/{repo}", "")


def _job(wf: str, name: str) -> dict:
    return yaml.safe_load((WF / wf).read_text())["jobs"][name]


def test_release_line_resolves_with_the_same_script() -> None:
    steps = _job("images-release.yml", "release-line")["steps"]
    sib = next(s for s in steps if s.get("id") == "siblings")
    assert 'scripts/sibling-refs.py resolve "$LINE" trellion' in sib["run"]
    assert "ls-remote" not in sib["run"], "one implementation, in the script"
