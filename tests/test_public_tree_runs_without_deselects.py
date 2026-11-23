# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""test-core and the mutants python lane run the same suite the same way.

A test whose input is not in the public tree skips ITSELF, with a reason that
starts with `not in this tree:`; no runner passes `--deselect` for it. When one
runner carried a hand list and the other did not, an unscoped python-lane
mutant started from a red base and every verdict from it was void.

What cannot decide for itself (modules that import trellion at collection
time) lives in tests/_public_tree.py and is applied by tests/conftest.py, keyed
on TRELLION_PUBLIC, which both runners set.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from tests import _public_tree

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"


def _test_core_run_step() -> str:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    job = text[text.index("\n  test-core:"):]
    start = job.index("    - name: Run tests")
    end = job.index("\n    - name:", start + 10)
    return job[start:end]


def _code(step: str) -> str:
    return "\n".join(l for l in step.splitlines() if not l.lstrip().startswith("#"))


def test_test_core_passes_pytest_no_hand_kept_exclusions() -> None:
    code = _code(_test_core_run_step())
    assert "pytest tests/" in code
    for flag in ("--deselect", "--ignore", "--ignore-glob", "-k "):
        assert flag not in code, (
            f"test-core passes `{flag}`: a test that needs an input this tree lacks must "
            "skip itself ('not in this tree: ...'); what cannot belongs in tests/_public_tree.py, "
            "which the mutants python lane reads too"
        )
    assert "needs_trellion" not in code


def test_every_ci_yml_deselect_names_no_module_that_skips_itself() -> None:
    """Anywhere in ci.yml, not only test-core: a `--deselect` of a self-skipping module is drift."""
    ci = _code((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    selfskip = {p.name for p in TESTS.glob("test_*.py") if _public_tree.SELF_SKIP_PREFIX in p.read_text()}
    for m in re.finditer(r"--deselect=tests/(\w+\.py)", ci):
        assert m.group(1) not in selfskip, f"ci.yml deselects {m.group(1)}, which skips itself"


def test_the_mutants_python_lane_and_test_core_share_the_mechanism() -> None:
    src = (ROOT / "scripts" / "ci-mutants.py").read_text()
    end = src.rindex('raise Refused(f"unknown lane')
    lane = src[src.rindex('if lane == "python":', 0, end):end]
    assert "--deselect" not in lane and "--ignore" not in lane, "the python lane keeps no list of its own"
    assert f'"{_public_tree.TRELLION_ENV}"' in lane, "the lane must set the variable the shared hook reads"
    step = _test_core_run_step()
    assert _public_tree.TRELLION_ENV in step, "test-core must set the same variable"
    conftest = (TESTS / "conftest.py").read_text()
    for hook in ("collect_ignore", "pytest_collection_modifyitems", "pytest_terminal_summary"):
        assert re.search(rf"^{hook} = _public_tree\.", conftest, re.M), f"conftest must wire {hook}"


def test_every_self_skip_reason_carries_the_prefix_the_summary_counts() -> None:
    """Each test module that skips because a file or tree is absent says so with the prefix,
    so the summary counts it. Guarded here: the modules this change converted."""
    for name in ("test_pro_build_cfg_excluded_from_oss.py",):
        tree = ast.parse((TESTS / name).read_text())
        reasons = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and ast.unparse(node.func) == "pytest.skip" and node.args:
                reasons.append(ast.unparse(node.args[0]))
        assert reasons, f"{name} no longer skips itself"
        for r in reasons:
            assert _public_tree.SELF_SKIP_PREFIX in r, f"{name}: skip reason {r} lacks {_public_tree.SELF_SKIP_PREFIX!r}"


def test_the_trellion_exclusions_follow_the_switch() -> None:
    assert _public_tree.collect_ignore_list({"TRELLION_PUBLIC": "true"}) == []
    assert _public_tree.collect_ignore_list({}) == []
    off = _public_tree.collect_ignore_list({"TRELLION_PUBLIC": "false"})
    assert off and set(off) == set(_public_tree.NEEDS_TRELLION_IGNORE)
    assert _public_tree.collect_ignore_list({"TRELLION_PUBLIC": ""}) == off
    for name in off + list(_public_tree.NEEDS_TRELLION_DESELECT):
        assert (TESTS / name).is_file(), f"{name} is listed in tests/_public_tree.py but does not exist"
