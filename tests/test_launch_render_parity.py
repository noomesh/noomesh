# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`noo config launch-render <section>` must be byte-compatible with the
`python3` + PyYAML blocks it replaces in the launcher scripts.

Why this exists: the launcher (`scripts/lib-config.sh`, `scripts/lib-addons.sh`,
`scripts/noomesh-start.sh`) used to embed a `python3` heredoc for each of
three `noomesh.yaml` sections (`compose_env:`, `addons:`, the
watched_folders/workspace override). On a newcomer host with no host
Python or no PyYAML installed, all three silently produced nothing — every
`noo stack start` printed `ModuleNotFoundError: No module named 'yaml'` and
compose_env / the add-on map / the mount overlay were skipped without the
operator being told (2026-09-29 upgrade rehearsal).

The fix is not a second, independent parser: `noo` already parses this file
for itself (`envfile.rs::load_yaml_compose_env`,
`commands/addons.rs::declared_map`) and is on every host that runs the
launcher — it IS what invoked it. `noo config launch-render <section>`
(noo-cli/src/commands/launch_render.rs) is that ONE reader, exposed to the
shell in the exact shape the Python blocks used to produce, so the shell's
own parsing (the `!ERR` handling in `lib-config.sh`, the `name=1`/`name=0`
reads in `lib-addons.sh`) never had to change — only where the text comes
from.

ORIGINAL SHAPE (PR #551): this test built the `noo` binary and diff'd it
against a freshly-run python3 block, per fixture, inline in the test file.
It SKIPPED in CI — the pytest job never builds noo-cli/target/debug/noo —
so all 18 cases were SKIPPED, not passed, in PR #551's own CI run, and the
byte-compatibility claim was untested where it mattered.

CURRENT SHAPE: golden files. `tests/fixtures/launch_render/<case>/` holds
one `noomesh.yaml` plus the python3 block's committed output for each of
the three sections (`compose-env.out`, `addons.out`, `override.out`, or
`override.err` containing the word "fail" when the override block is
expected to exit nonzero and leave the existing file alone). This test
runs ONLY the python3 side against each fixture and compares it to the
committed golden — it needs no Rust binary, so it runs in every CI job that
has pytest + PyYAML (there is no skip: a missing PyYAML is itself something
this test must catch, see test_pyyaml_is_available_in_ci below).

The Rust side of the same golden files is proven separately, by
`noo-cli/src/commands/launch_render.rs`'s own `#[cfg(test)] mod golden`,
which walks the identical fixture directory and asserts
`render_compose_env`/`render_addons`/`render_override` match the same
goldens this file checks the python3 side against. Two independent readers
converging on one committed expectation is the actual parity proof; neither
side has to run the other's language to provide it.

To regenerate the goldens (only when the python3 fallback's OWN behaviour
is meant to change — see that script's docstring for why):
    python3 tests/fixtures/launch_render/regen.py
"""

from __future__ import annotations

import re
import sys
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "launch_render"

# See tests/fixtures/launch_render/regen.py's docstring: PyYAML's own
# syntax-error message embeds the absolute path of the file it was
# reading, so this one case cannot have a byte-identical golden across
# machines/checkouts. Both this file and launch_render.rs's test module
# special-case it by name instead of doing a byte comparison.
SYNTAX_ERROR_CASES = {"yaml_syntax_error"}


def test_pyyaml_is_available_in_ci():
    """A missing PyYAML must FAIL this suite loudly, not skip it. The whole
    point of this file is proving the python3 fallback path behaves — a
    skip here is exactly the silent-failure shape (2026-09-29 rehearsal)
    the launch-render split exists to remove. pyproject.toml declares
    pyyaml>=6.0 as a base (non-optional) dependency, so the CI test job
    that runs `pytest tests/` always has it; if this assertion ever fires
    in CI, that dependency broke, and every test below would otherwise
    have failed for the wrong, confusing reason (ModuleNotFoundError deep
    in a subprocess) instead of this clear one.
    """
    import importlib

    assert importlib.util.find_spec("yaml") is not None, (
        "PyYAML is not importable — the launch-render python3 fallback "
        "(and this whole parity test) cannot run. Check pyproject.toml's "
        "pyyaml dependency and the environment that installed it."
    )


def _extract_heredoc(text: str, marker: str) -> str:
    """Pull the body of a `<<'MARKER' ... MARKER` heredoc out of shell
    source. Fails loudly if the marker is not found exactly once — a
    vacuous pass (empty extracted source) would prove nothing."""
    pattern = re.compile(rf"<<'{marker}'[^\n]*\n(.*?\n){marker}\n", re.DOTALL)
    matches = pattern.findall(text)
    assert len(matches) == 1, (
        f"expected exactly one <<'{marker}' heredoc, found {len(matches)}"
    )
    body = matches[0]
    assert body.strip(), f"{marker} heredoc extracted empty — the marker moved"
    return body


COMPOSE_ENV_PY = _extract_heredoc((SCRIPTS / "lib-config.sh").read_text(), "PY")
ADDONS_PY = _extract_heredoc((SCRIPTS / "lib-addons.sh").read_text(), "PYEOF")
# The override regen (originally inline in noomesh-start.sh) now lives in
# `regen_compose_override()` in lib-config.sh, so it can be called from a
# test without sourcing the whole launcher script — see that function's
# comment and tests/test_launcher_noo_fallback.py.
OVERRIDE_PY = _extract_heredoc((SCRIPTS / "lib-config.sh").read_text(), "PYOVR")


def _py_compose_env(yaml_path: Path) -> str:
    out = subprocess.run(
        [sys.executable, "-c", COMPOSE_ENV_PY, str(yaml_path)],
        capture_output=True, text=True, timeout=30,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout


def _py_addons(cwd: Path) -> str:
    out = subprocess.run(
        [sys.executable, "-c", ADDONS_PY],
        cwd=cwd, capture_output=True, text=True, timeout=30,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout


def _py_override(cwd: Path) -> tuple[bool, str]:
    """Returns (ok, text). ok=False means the python block itself exited
    nonzero (a YAML syntax error — the block has no try/except of its
    own), matching the shell's `|| echo … ; keep existing file` handling."""
    override_path = cwd / "docker-compose.override.yml"
    if override_path.exists():
        override_path.unlink()
    out = subprocess.run(
        [sys.executable, "-c", OVERRIDE_PY],
        cwd=cwd, capture_output=True, text=True, timeout=30,
    )
    if out.returncode != 0:
        return False, ""
    return True, override_path.read_text()


def _cases() -> list[Path]:
    return sorted(p for p in FIXTURES.iterdir() if p.is_dir())


CASES = _cases()
# A glob that silently matched nothing would make every parametrized test
# below vacuously pass ("no tests ran" reads as green in most CI summaries).
assert len(CASES) >= 10, (
    f"expected >= 10 launch_render golden cases under {FIXTURES}, found "
    f"{len(CASES)} — an empty/broken glob must not silently pass this suite"
)


@pytest.fixture
def tmp_repo(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    return d


def _load_case(case_dir: Path, tmp_repo: Path) -> None:
    (tmp_repo / "noomesh.yaml").write_text((case_dir / "noomesh.yaml").read_text())


@pytest.mark.parametrize("case_dir", CASES, ids=lambda p: p.name)
def test_compose_env_matches_golden(case_dir, tmp_repo):
    _load_case(case_dir, tmp_repo)
    out = _py_compose_env(tmp_repo / "noomesh.yaml")

    if case_dir.name in SYNTAX_ERROR_CASES:
        assert out.startswith("!ERR "), out
        assert out.count("\n") == 1, out
        return

    golden_path = case_dir / "compose-env.out"
    assert golden_path.exists(), f"{case_dir.name}: missing compose-env.out golden"
    golden = golden_path.read_text()
    assert out == golden, (
        f"[{case_dir.name}] compose-env python output != golden:\n"
        f"  python: {out!r}\n  golden: {golden!r}"
    )


@pytest.mark.parametrize("case_dir", CASES, ids=lambda p: p.name)
def test_addons_matches_golden(case_dir, tmp_repo):
    _load_case(case_dir, tmp_repo)
    out = _py_addons(tmp_repo)
    golden_path = case_dir / "addons.out"
    assert golden_path.exists(), f"{case_dir.name}: missing addons.out golden"
    golden = golden_path.read_text()
    assert out == golden, (
        f"[{case_dir.name}] addons python output != golden:\n"
        f"  python: {out!r}\n  golden: {golden!r}"
    )


@pytest.mark.parametrize("case_dir", CASES, ids=lambda p: p.name)
def test_override_matches_golden(case_dir, tmp_repo):
    _load_case(case_dir, tmp_repo)
    ok, out = _py_override(tmp_repo)
    err_golden = case_dir / "override.err"
    out_golden = case_dir / "override.out"
    if err_golden.exists():
        assert not ok, (
            f"[{case_dir.name}] expected the override python block to fail "
            f"(override.err present) but it succeeded with: {out!r}"
        )
        assert err_golden.read_text().strip() == "fail"
    else:
        assert ok, f"[{case_dir.name}] override python block unexpectedly failed"
        assert out_golden.exists(), f"{case_dir.name}: missing override.out golden"
        golden = out_golden.read_text()
        assert out == golden, (
            f"[{case_dir.name}] override python output != golden:\n"
            f"  python: {out!r}\n  golden: {golden!r}"
        )


def test_addons_truthiness_is_not_vacuous():
    case_dir = FIXTURES / "addons_truthiness"
    assert case_dir.is_dir(), "addons_truthiness fixture case is required"
    golden = (case_dir / "addons.out").read_text()
    assert golden.strip(), "the truthiness fixture must produce lines"
    assert golden.count("=") == 7


def test_override_with_folders_is_not_vacuous():
    case_dir = FIXTURES / "watched_folders_readonly_and_writable"
    assert case_dir.is_dir(), "watched_folders_readonly_and_writable fixture case is required"
    golden = (case_dir / "override.out").read_text()
    assert "services:" in golden
    assert "/home/op/docs:/data/docs:ro" in golden
    assert "/home/op/scratch:/data/scratch:rw" in golden


def test_no_compose_env_case_present():
    """Required by the launch-render task: a case where noomesh.yaml has
    OTHER sections but no compose_env: at all, proving compose-env renders
    empty while addons/override (which have their own sections in this
    fixture) still work."""
    case_dir = FIXTURES / "no_compose_env"
    assert case_dir.is_dir()
    assert "compose_env" not in (case_dir / "noomesh.yaml").read_text().split("\n")[0]
    golden = (case_dir / "compose-env.out").read_text()
    assert golden == "", "no_compose_env case must render nothing for compose-env"


def test_watched_folders_disabled_case_present():
    case_dir = FIXTURES / "watched_folders_disabled"
    assert case_dir.is_dir()
    golden = (case_dir / "override.out").read_text()
    assert "services: {}" in golden
    assert "volumes" not in golden
