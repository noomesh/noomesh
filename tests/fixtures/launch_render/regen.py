#!/usr/bin/env python3
"""Regenerate the golden files under tests/fixtures/launch_render/<case>/.

DO NOT run this to "fix" a failing test. The goldens are the CONTRACT: they
encode what the python3+PyYAML fallback blocks embedded in
scripts/lib-config.sh, scripts/lib-addons.sh and scripts/noomesh-start.sh
are supposed to produce, extracted straight from those scripts' own heredoc
source (the same extraction tests/test_launch_render_parity.py uses to run
them). Regenerate ONLY when you have deliberately changed one of those
python blocks' behaviour, and review the resulting diff line by line before
committing it — a golden file silently drifting to match a bug is exactly
the failure mode this fixture set exists to catch.

Usage (from the repo root):
    python3 tests/fixtures/launch_render/regen.py

For each case directory containing a noomesh.yaml, writes:
    compose-env.out   — stdout of the compose_env python block
    addons.out        — stdout of the addons python block
    override.out      — contents of docker-compose.override.yml after the
                         override python block runs successfully
    override.err      — written INSTEAD of override.out, containing just
                         the word "fail", when the override block exits
                         nonzero (a YAML syntax error: the python block has
                         no try/except of its own, so it dies with a
                         traceback and the caller's `|| echo …` fires,
                         leaving the existing override file untouched).

One case, yaml_syntax_error, is a genuine YAML *syntax* error. serde_yaml's
and PyYAML's error text differ (different libraries, different messages),
and PyYAML's message additionally embeds the absolute path of the yaml file
it was reading ("...in \"/abs/path/to/noomesh.yaml\", line 2, column 1"),
which is not reproducible across machines/checkouts at all. So this case
gets NO compose-env.out golden: the pytest and Rust tests both special-case
it by name, asserting only that the output is a single line starting with
"!ERR " on each side, never a byte comparison. See SYNTAX_ERROR_CASES in
test_launch_render_parity.py and the matching constant in
launch_render.rs's test module.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

SYNTAX_ERROR_CASES = {"yaml_syntax_error"}

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = REPO_ROOT / "scripts"
FIXTURES = Path(__file__).resolve().parent


def _extract_heredoc(text: str, marker: str) -> str:
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
# regen_compose_override() in lib-config.sh (moved out of noomesh-start.sh).
OVERRIDE_PY = _extract_heredoc((SCRIPTS / "lib-config.sh").read_text(), "PYOVR")


def run_compose_env(yaml_path: Path) -> str:
    out = subprocess.run(
        [sys.executable, "-c", COMPOSE_ENV_PY, str(yaml_path)],
        capture_output=True, text=True, timeout=30,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout


def run_addons(cwd: Path) -> str:
    out = subprocess.run(
        [sys.executable, "-c", ADDONS_PY],
        cwd=cwd, capture_output=True, text=True, timeout=30,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout


def run_override(cwd: Path) -> tuple[bool, str]:
    """Returns (ok, text). ok=False means the python block itself failed
    (matching the shell's `|| echo … ; keep existing file` fallback)."""
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


def main() -> int:
    cases = sorted(p for p in FIXTURES.iterdir() if p.is_dir())
    assert cases, f"no case directories under {FIXTURES}"
    for case_dir in cases:
        yaml_path = case_dir / "noomesh.yaml"
        if not yaml_path.exists():
            continue

        compose_env_out = case_dir / "compose-env.out"
        if case_dir.name in SYNTAX_ERROR_CASES:
            # Non-reproducible across machines (embeds an absolute path) —
            # no golden; the tests special-case this case by name instead.
            compose_env_out.unlink(missing_ok=True)
        else:
            compose_env_out.write_text(run_compose_env(yaml_path))
        (case_dir / "addons.out").write_text(run_addons(case_dir))

        ok, text = run_override(case_dir)
        err_path = case_dir / "override.err"
        out_path = case_dir / "override.out"
        if ok:
            out_path.write_text(text)
            err_path.unlink(missing_ok=True)
        else:
            err_path.write_text("fail\n")
            out_path.unlink(missing_ok=True)

        # regen leaves no docker-compose.override.yml behind in the fixture
        (case_dir / "docker-compose.override.yml").unlink(missing_ok=True)

        print(f"regenerated {case_dir.relative_to(FIXTURES)}")
    print(f"{len(cases)} case(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
