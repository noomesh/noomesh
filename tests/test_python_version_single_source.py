# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""One Python version, declared once, asserted everywhere.

`.python-version` at the repo root is the single source of truth for the
interpreter this project builds, ships and tests on. Nine other places in the
tree have to agree with it, and until this file existed they did not:

  * `docker/Dockerfile.deps-core` installed 3.12 — the interpreter every
    shipped Python service actually runs;
  * the root `Dockerfile`, which CI's `build` job compiles on every PR, was
    `FROM python:3.11-slim` — so the one interpreter a merge was gated on was
    an interpreter nothing deployed;
  * `pyproject.toml` said `requires-python = ">=3.11"` with classifiers for
    3.11, 3.12 and 3.13;
  * CI ran the whole suite on a 3.11/3.12/3.13 matrix, two thirds of it on
    Pythons no user has, on the same self-hosted runners the Rust jobs queue
    behind.

None of that was caught because nothing compared the numbers. A version that
lives in nine files is nine independent facts, and drift between them is
invisible until an image is built or a leg goes red. So the numbers are
compared here, statically, from the sources themselves.

WHAT THIS FILE IS NOT: a check that 3.12 specifically is the right choice.
Bumping the interpreter is a one-line edit to `.python-version` plus the
matching literals these assertions name — and this test is what turns
"plus the matching literals" from a thing you have to remember into a thing
CI tells you about.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = ROOT / ".python-version"
PYPROJECT = ROOT / "pyproject.toml"
CI = ROOT / ".github/workflows/ci.yml"
ROOT_DOCKERFILE = ROOT / "Dockerfile"
DEPS_CORE = ROOT / "docker/Dockerfile.deps-core"


def _declared() -> tuple[str, int, int]:
    """The single source of truth, as ("3.12", 3, 12)."""
    raw = VERSION_FILE.read_text().strip()
    m = re.fullmatch(r"(\d+)\.(\d+)", raw)
    assert m, (
        f".python-version must hold a bare MAJOR.MINOR (e.g. '3.12'), got {raw!r}. "
        "A patch-level pin here would force every consumer — uv, setup-python, "
        "the Dockerfile ARGs — to chase point releases."
    )
    return raw, int(m.group(1)), int(m.group(2))


@pytest.fixture(scope="module")
def declared() -> tuple[str, int, int]:
    return _declared()


def test_version_file_exists() -> None:
    assert VERSION_FILE.is_file(), (
        ".python-version is missing. It is the single source of truth for the "
        "interpreter: uv reads it, actions/setup-python reads it via "
        "python-version-file, and every other pin in this test is checked "
        "against it."
    )


# ── pyproject ────────────────────────────────────────────────────────────────


def test_requires_python_is_a_closed_range_on_the_declared_version(declared) -> None:
    version, major, minor = declared
    requires = tomllib.loads(PYPROJECT.read_text())["project"]["requires-python"]

    expected = f">={version},<{major}.{minor + 1}"
    assert requires == expected, (
        f"pyproject requires-python is {requires!r}, expected {expected!r} to match "
        f".python-version ({version}).\n"
        "It must be a CLOSED range. `>=3.11` is what let CI justify testing three "
        "interpreters when the images install exactly one, and it is what makes "
        "ruff and mypy infer the OLDEST allowed Python as their target rather "
        "than the one the code runs on."
    )


def test_exactly_one_python_classifier_and_it_is_the_declared_one(declared) -> None:
    version, _, _ = declared
    classifiers = tomllib.loads(PYPROJECT.read_text())["project"]["classifiers"]
    python_versions = [
        c.rsplit("::", 1)[1].strip()
        for c in classifiers
        if c.startswith("Programming Language :: Python ::")
    ]
    assert python_versions == [version], (
        f"pyproject declares Python classifiers {python_versions}, expected exactly "
        f"['{version}'].\n"
        "One interpreter ships, so one classifier. Listing versions that are "
        "neither built nor tested advertises support this project does not have."
    )


def test_ruff_target_version_matches(declared) -> None:
    _, major, minor = declared
    ruff = tomllib.loads(PYPROJECT.read_text())["tool"]["ruff"]
    expected = f"py{major}{minor}"
    assert ruff.get("target-version") == expected, (
        f"[tool.ruff] target-version is {ruff.get('target-version')!r}, expected "
        f"{expected!r}.\n"
        "Unset, ruff infers the target from requires-python's LOWER bound — it "
        "was linting for 3.11 while every container ran 3.12."
    )


def test_mypy_python_version_matches(declared) -> None:
    version, _, _ = declared
    mypy = tomllib.loads(PYPROJECT.read_text())["tool"]["mypy"]
    assert mypy.get("python_version") == version, (
        f"[tool.mypy] python_version is {mypy.get('python_version')!r}, expected "
        f"{version!r}.\n"
        "Same failure mode as ruff's target-version: mypy otherwise checks "
        "against the oldest Python requires-python permits."
    )


# ── the images ───────────────────────────────────────────────────────────────


def _python_version_arg(dockerfile: Path) -> str:
    """The `ARG PYTHON_VERSION=X.Y` default declared in a Dockerfile."""
    matches = re.findall(
        r"^ARG\s+PYTHON_VERSION=(\S+)\s*$", dockerfile.read_text(), re.M
    )
    assert matches, (
        f"{dockerfile.relative_to(ROOT)} declares no `ARG PYTHON_VERSION=…`. "
        "The interpreter must come from an ARG so there is one literal per file "
        "for this test to check, instead of a bare version buried in a FROM or a "
        "`uv python install`."
    )
    assert len(matches) == 1, (
        f"{dockerfile.relative_to(ROOT)} declares PYTHON_VERSION {len(matches)} "
        f"times ({matches}); two defaults is two sources of truth."
    )
    return matches[0]


def test_deps_core_installs_the_declared_interpreter(declared) -> None:
    version, _, _ = declared
    assert _python_version_arg(DEPS_CORE) == version, (
        f"docker/Dockerfile.deps-core pins PYTHON_VERSION="
        f"{_python_version_arg(DEPS_CORE)}, but .python-version says {version}.\n"
        "This is THE interpreter: every Python service image FROMs this tier, so "
        "this ARG is what the fleet runs."
    )

    body = DEPS_CORE.read_text()
    assert "uv python install \"${PYTHON_VERSION}\"" in body, (
        "docker/Dockerfile.deps-core no longer installs ${PYTHON_VERSION} — the "
        "ARG has stopped being what the image acts on, so this test would be "
        "checking a value nothing reads."
    )
    stray = re.findall(r"uv python (?:install|find) (\d+\.\d+)", body)
    assert not stray, (
        f"docker/Dockerfile.deps-core still names literal Python version(s) "
        f"{stray} in a `uv python` call; use ${{PYTHON_VERSION}}."
    )


def test_root_dockerfile_uses_the_declared_interpreter(declared) -> None:
    version, _, _ = declared
    assert _python_version_arg(ROOT_DOCKERFILE) == version, (
        f"the root Dockerfile pins PYTHON_VERSION="
        f"{_python_version_arg(ROOT_DOCKERFILE)}, but .python-version says "
        f"{version}.\n"
        "CI's `build` job compiles this file on every PR. When it was 3.11 and "
        "the fleet was 3.12, the only interpreter a merge was gated on was one "
        "nothing deployed."
    )
    # Through the Docker Hub mirror (tests/test_hub_mirror.py): the tag still interpolates.
    assert "FROM ${HUB_MIRROR}/library/python:${PYTHON_VERSION}-slim" in ROOT_DOCKERFILE.read_text(), (
        "the root Dockerfile's FROM no longer interpolates ${PYTHON_VERSION}."
    )


# ── CI ───────────────────────────────────────────────────────────────────────


def _ci() -> dict:
    return yaml.safe_load(CI.read_text())


def test_ci_has_no_python_matrix() -> None:
    for name, job in _ci()["jobs"].items():
        matrix = (job.get("strategy") or {}).get("matrix") or {}
        assert "python-version" not in matrix, (
            f"ci.yml job {name!r} has a python-version matrix {matrix['python-version']}. "
            "The images install exactly ONE interpreter, so extra legs prove "
            "nothing about what ships while spending self-hosted queue time the "
            "Rust jobs need — and a red leg on an undeployed Python blocks merges."
        )


def test_every_ci_setup_python_reads_the_version_file() -> None:
    """No job may restate the version; they all read `.python-version`."""
    seen: list[str] = []
    bad: list[str] = []
    for name, job in _ci()["jobs"].items():
        for step in job.get("steps") or []:
            if not (step.get("uses") or "").startswith("actions/setup-python"):
                continue
            with_ = step.get("with") or {}
            seen.append(name)
            if with_.get("python-version-file") != ".python-version":
                bad.append(f"{name}: with={with_ or None}")

    # Without this the whole check passes vacuously the day someone deletes or
    # renames the setup-python steps — the exact edit that would put the version
    # somewhere this file no longer looks.
    assert seen, (
        "ci.yml has no actions/setup-python step at all. Either Python setup "
        "moved somewhere this test does not read, or the jobs lost it."
    )
    assert not bad, (
        "these ci.yml setup-python steps do not read `.python-version`:\n  "
        + "\n  ".join(bad)
        + "\nA literal `python-version: '3.12'` is a second source of truth that "
        "drifts silently: setup-python installs whatever it is handed, so the "
        "job goes green on an interpreter the images do not contain."
    )


def test_ci_does_not_reference_a_dead_matrix_context() -> None:
    """An undefined `matrix.*` renders as "", it does not fail the run.

    That is the trap in removing a matrix: `coverage-py${{ matrix.python-version }}`
    becomes `coverage-py-`, and a cache key built the same way collapses to
    `Linux--pip-`, matching a cache from any interpreter. Both stay GREEN while
    being wrong, which is the only reason this check is worth having.

    Parsed, not grepped: the yaml round-trip drops comments, so the historical
    notes in ci.yml that quote the old expression do not trip it. Only an
    expression a job would actually evaluate counts.
    """
    workflow = _ci()
    stale = []
    for name, job in workflow["jobs"].items():
        defined = set((job.get("strategy") or {}).get("matrix") or {})
        for ref in re.findall(r"matrix\.([\w-]+)", yaml.safe_dump(job)):
            if ref not in defined:
                stale.append(f"{name}: matrix.{ref} (job defines {sorted(defined)})")
    assert not stale, (
        "these ci.yml jobs read a matrix key no strategy defines — Actions "
        "substitutes the empty string and the step goes green anyway:\n  "
        + "\n  ".join(stale)
    )


# ── the docs that state a version ────────────────────────────────────────────


def test_readme_badge_states_the_declared_version(declared) -> None:
    version, _, _ = declared
    badge = re.search(r"\[!\[Python ([^\]]+)\]", (ROOT / "README.md").read_text())
    assert badge, "README.md has no Python badge to check."
    assert badge.group(1) == version, (
        f"README.md advertises Python {badge.group(1)}, but the project builds and "
        f"ships {version}. The badge said '3.11+' while nothing could install on "
        "3.11 but the CI smoke image."
    )
