# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Files the Rust build needs at COMPILE time must be in the Docker COPY list.

`cargo build` on a developer machine runs from a full checkout, so every file
is simply there. The image build copies an explicit subset. Nothing reconciles
the two, which means a new compile-time file dependency is invisible to every
Rust CI job and only shows up when the image is built — or worse, does not
show up at all.

Both failure modes have happened:

- `migrations/0001_baseline.sql` (include_str!) — LOUD. The image build died
  with "couldn't read `src/../migrations/0001_baseline.sql`".
- `build.rs` — SILENT, and much worse. Cargo AUTO-DETECTS build.rs; when it is
  missing there is no error, the build script just never runs and every cfg it
  would set stays off. The shipped gateway image therefore contained NO pro
  routes at all (the evolve add-on's), while every local build had them. Nothing failed. Nobody noticed.

The mcp-tools.json COPY line already carried a comment predicting exactly this
("the COPY list is the only place this dependency has to be declared") — the
comment was right and still did not prevent a recurrence, because a comment is
not a check.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO / "docker" / "Dockerfile.gateway-rust"
CRATES = ("gateway-rust",)


def _builder_stage(text: str) -> str:
    """Only the builder stage — later stages copy different things."""
    start = text.index("AS builder")
    nxt = text.find("\nFROM ", start)
    return text[start : nxt if nxt != -1 else len(text)]


def _copied_paths(stage: str) -> set[str]:
    out: set[str] = set()
    for line in stage.splitlines():
        line = line.strip()
        if not line.startswith("COPY "):
            continue
        parts = line.split()[1:]
        # drop --flags and the destination
        srcs = [p for p in parts[:-1] if not p.startswith("--")]
        out.update(srcs)
    return out


def _is_copied(path: str, copied: set[str]) -> bool:
    """path is repo-relative, e.g. gateway-rust/build.rs."""
    if path in copied:
        return True
    # a copied directory covers everything under it
    return any(path.startswith(c.rstrip("/") + "/") for c in copied)


@pytest.mark.parametrize("crate", CRATES)
def test_include_str_targets_are_in_the_build_context(crate: str) -> None:
    """Every include_str!("../X") outside src/ must be COPYed."""
    src = REPO / crate / "src"
    if not src.exists():
        pytest.skip(f"{crate} not present")

    copied = _copied_paths(_builder_stage(DOCKERFILE.read_text()))
    missing: list[str] = []

    for rs in src.rglob("*.rs"):
        for target in re.findall(r'include_str!\s*\(\s*"([^"]+)"', rs.read_text()):
            if not target.startswith("../"):
                continue  # under src/, already covered
            resolved = (rs.parent / target).resolve()
            try:
                rel = resolved.relative_to(REPO).as_posix()
            except ValueError:
                continue
            if not _is_copied(rel, copied):
                missing.append(f"{rel} (from {rs.relative_to(REPO)})")

    assert not missing, (
        "these files are embedded at compile time but are NOT copied into the "
        f"Docker builder stage, so the image build will fail: {sorted(set(missing))}. "
        f"Add a COPY line to {DOCKERFILE.relative_to(REPO)}."
    )


DOCKERIGNORE = REPO / ".dockerignore"


def _dockerignore_rules() -> list[tuple[bool, str]]:
    """(negated, pattern) in file order; blanks and comments dropped."""
    rules = []
    for line in DOCKERIGNORE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rules.append((line.startswith("!"), line.lstrip("!").strip("/")))
    assert rules, ".dockerignore parsed to nothing — the parse broke"
    return rules


def _rule_matches(pattern: str, path: str) -> bool:
    """Directory prefixes and plain paths only — the subset this file uses."""
    if "*" in pattern:
        return False
    return path == pattern or path.startswith(pattern + "/")


def _ignored(path: str) -> bool:
    """Last matching rule wins, the way Docker evaluates .dockerignore."""
    verdict = False
    for negated, pattern in _dockerignore_rules():
        if _rule_matches(pattern, path):
            verdict = not negated
    return verdict


def test_copied_sources_are_not_shadowed_by_dockerignore() -> None:
    """A COPY line is a promise the build context cannot keep if .dockerignore
    excludes the source. PR #540 shipped `COPY tests/fixtures/…` over a
    `tests/` ignore: local checks green, image build "not found"."""
    copied = _copied_paths(_builder_stage(DOCKERFILE.read_text()))
    assert copied, "no COPY sources parsed — the parse broke"
    shadowed = sorted(p for p in copied if _ignored(p.rstrip("/")))
    assert not shadowed, (
        f"{shadowed} are COPYed by {DOCKERFILE.relative_to(REPO)} but excluded "
        f"by {DOCKERIGNORE.name}; add a `!<path>` exception after the rule that "
        "excludes them."
    )


def test_dockerignore_parse_sees_the_tests_rule() -> None:
    # The guard above is only as good as its parser: `tests/` must read as ignored
    # and the corpus as re-included.
    assert _ignored("tests/test_rust_build_context.py")
    assert not _ignored("tests/fixtures/redaction_corpus.json")


@pytest.mark.parametrize("crate", CRATES)
def test_build_rs_is_in_the_build_context(crate: str) -> None:
    """A missing build.rs disables every cfg SILENTLY — no error, no warning."""
    if not (REPO / crate / "build.rs").exists():
        pytest.skip(f"{crate}/build.rs not present")

    copied = _copied_paths(_builder_stage(DOCKERFILE.read_text()))
    assert _is_copied(f"{crate}/build.rs", copied), (
        f"{crate}/build.rs is not copied into the Docker builder stage. Cargo "
        "auto-detects build scripts, so this does NOT fail the build — it "
        "silently drops every cfg the script sets, which is how the shipped "
        "image lost its pro routes. Add a COPY line."
    )


def test_every_path_dependency_is_in_the_build_context() -> None:
    """A path dependency outside the crate (`../crates/addon-manifest`, i302)
    is compiled from the build context like the crate's own sources: missing
    from the COPY list, the image build dies resolving the dependency graph.
    Every `path = "..."` dependency in the gateway's Cargo.toml must be COPYed."""
    manifest = (REPO / "gateway-rust" / "Cargo.toml").read_text()
    deps = re.findall(r'^[A-Za-z0-9_-]+\s*=\s*\{[^}\n]*\bpath\s*=\s*"([^"]+)"', manifest, re.M)
    assert deps, "no path dependency parsed from gateway-rust/Cargo.toml — the parse broke"
    copied = _copied_paths(_builder_stage(DOCKERFILE.read_text()))
    missing = []
    for d in deps:
        rel = (REPO / "gateway-rust" / d).resolve().relative_to(REPO).as_posix()
        if not _is_copied(rel, copied):
            missing.append(rel)
    assert not missing, (
        f"path dependencies {missing} are not copied into the Docker builder stage of "
        f"{DOCKERFILE.relative_to(REPO)}; add a COPY of each to the directory the "
        "dependency's relative path resolves to from WORKDIR /build"
    )
