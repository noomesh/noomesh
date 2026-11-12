# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""scripts/openapi-merge3.py resolves the conflict two route PRs leave in
the generated OpenAPI files, and stops on a real collision (2026-11-11).

Run on a throwaway git repo with a REAL conflicted rebase, so the index
stages it reads are the ones git actually leaves.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MERGE = ROOT / "scripts" / "openapi-merge3.py"
REGEN = ROOT / "scripts" / "regen-openapi-on-rebase.sh"
F = "spec.json"


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=check)


def _write(repo: Path, spec: dict) -> None:
    (repo / F).write_text(json.dumps(spec, indent=2, ensure_ascii=True) + "\n")


def _spec(**paths: dict) -> dict:
    return {"openapi": "3.0.1", "info": {"title": "t"}, "paths": dict(paths)}


def _conflicted(tmp_path: Path, base: dict, upstream: dict, mine: dict) -> Path:
    """Rebase `mine` onto `upstream` (both from `base`) and stop on the conflict."""
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "dev")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    _write(repo, base)
    _git(repo, "add", F)
    _git(repo, "commit", "-qm", "base")
    _git(repo, "checkout", "-qb", "mine")
    _write(repo, mine)
    _git(repo, "commit", "-qam", "mine")
    _git(repo, "checkout", "-q", "dev")
    _write(repo, upstream)
    _git(repo, "commit", "-qam", "upstream")
    _git(repo, "checkout", "-q", "mine")
    r = _git(repo, "rebase", "dev", check=False)
    assert r.returncode != 0 and F in _git(repo, "diff", "--name-only", "--diff-filter=U").stdout, \
        "the fixture must leave a REAL conflict, else this proves nothing"
    return repo


def _merge(repo: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["python3", str(MERGE), F], cwd=repo, capture_output=True, text=True)


A = {"get": {"summary": "a"}}
B = {"get": {"summary": "b"}}
C = {"post": {"summary": "c, hand-written"}}


def test_two_prs_adding_different_routes_merge_and_keep_both_sides(tmp_path: Path) -> None:
    repo = _conflicted(tmp_path, _spec(**{"/a": A}),
                       _spec(**{"/a": A, "/b": B}),
                       _spec(**{"/a": A, "/c": C}))
    r = _merge(repo)
    assert r.returncode == 0, r.stderr
    text = (repo / F).read_text()
    assert "<<<<<<<" not in text
    got = json.loads(text)
    assert list(got["paths"]) == ["/a", "/b", "/c"], "upstream's order, then the branch's additions"
    assert got["paths"]["/c"] == C, "the branch's hand-written entry is kept as written"
    assert text == json.dumps(got, indent=2, ensure_ascii=True) + "\n", "written the way the generators write"


def test_the_same_route_changed_differently_on_both_sides_stops_and_names_it(tmp_path: Path) -> None:
    repo = _conflicted(tmp_path, _spec(**{"/a": A}),
                       _spec(**{"/a": {"get": {"summary": "upstream's"}}, "/b": B}),
                       _spec(**{"/a": {"get": {"summary": "mine"}}, "/c": C}))
    before = (repo / F).read_text()
    r = _merge(repo)
    assert r.returncode == 1
    assert "/paths/~1a" not in r.stderr and "/paths//a/get/summary" in r.stderr, r.stderr
    assert (repo / F).read_text() == before, "a refused merge writes nothing"


def test_one_side_changes_and_the_other_side_removes_are_both_applied() -> None:
    spec = importlib.util.spec_from_file_location("m3", MERGE)
    m3 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m3)
    base = {"x": 1, "gone": 1, "kept": {"k": 1}}
    ours = {"x": 2, "kept": {"k": 1}}            # changed x, removed gone
    theirs = {"x": 1, "gone": 1, "kept": {"k": 1, "new": 3}}
    conflicts: list[str] = []
    assert m3.merge3(base, ours, theirs, "", conflicts) == {"x": 2, "kept": {"k": 1, "new": 3}}
    assert conflicts == []
    m3.merge3({"x": 1}, {}, {"x": 9}, "", conflicts)
    assert conflicts == ["/x"], "removed on one side, changed on the other is a conflict"


def test_the_wrapper_refuses_other_conflicts_and_regenerates_every_derived_file() -> None:
    text = REGEN.read_text(encoding="utf-8")
    assert "other files are conflicted too" in text
    for gen in ("gen-openapi.py", "export-openapi.py", "gen-public-openapi.py", "gen:api"):
        assert gen in text, gen
    checks = text.index("# 3. Every check")
    stage = text.index('git add -- "${generated[@]}"')
    for check in ("gen-openapi.py --check", "export-openapi.py --check",
                  "gen-public-openapi.py --check", "check-openapi-drift.py"):
        assert checks < text.index(check) < stage, f"{check} must run before staging"
