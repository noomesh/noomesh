# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""scripts/test-core-local.sh runs CI's test-core steps, not its own copy.

2026-11-05: each session hand-built its own `uv --with` list to run the
Python suite locally, and the lists drifted (one reached 3 failures CI
never shows). The script now installs and runs the bodies of ci.yml's
test-core `Install dependencies` and `Run tests` steps verbatim, so its
dependency list IS the install step's. These tests pin that it stays so:
the steps it reads exist and keep their shape, every env key they set is
one the script supplies, the script carries no package list of its own,
and a step that could need or print a credential is refused.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "test-core-local.sh"
sys.path.insert(0, str(ROOT / "scripts"))
import ci_step  # noqa: E402


def _script_value(name: str) -> str:
    m = re.search(rf'^{name}="([^"]+)"$', SCRIPT.read_text(encoding="utf-8"), re.M)
    assert m, f"{name}= not found in {SCRIPT.name}"
    return m.group(1)


def _handled_env() -> set[str]:
    m = re.search(r"^HANDLED_ENV=\(([^)]*)\)$", SCRIPT.read_text(encoding="utf-8"), re.M)
    assert m, "HANDLED_ENV=(...) not found"
    return set(m.group(1).split())


def test_the_script_reads_the_steps_that_exist_in_ci() -> None:
    job = _script_value("JOB")
    # The trellion switch is a workflow-level env, fed through test-core's own
    # probe step; the script hard-codes neither.
    assert ci_step.workflow_env(_script_value("SWITCH")) in ("true", "false")
    probe = ci_step.safe_step(job, _script_value("PROBE_STEP"))
    assert 'echo "public=' in probe["run"] and "$GITHUB_OUTPUT" in probe["run"], probe["run"]
    install = ci_step.safe_step(job, _script_value("INSTALL_STEP"))
    run = ci_step.safe_step(job, _script_value("RUN_STEP"))
    # The shape the script depends on: an editable install of extras, and the
    # suite run from tests/.
    assert re.search(r'pip install -e "\.\[[a-z,]+\]"', install["run"]), install["run"]
    assert re.search(r"^\s*pytest tests/", run["run"], re.M), run["run"]


def test_every_env_key_the_steps_set_is_supplied_by_the_script() -> None:
    job, handled = _script_value("JOB"), _handled_env()
    assert handled, "HANDLED_ENV parsed to nothing"
    for step in (_script_value("PROBE_STEP"), _script_value("INSTALL_STEP"), _script_value("RUN_STEP")):
        keys = set((ci_step.safe_step(job, step).get("env") or {}).keys())
        assert keys <= handled, f"{job} / {step!r} sets {sorted(keys - handled)}; add them to HANDLED_ENV and supply them"
    body = SCRIPT.read_text(encoding="utf-8")
    for key in handled:
        assert re.search(rf"\b{key}\b", body.split("HANDLED_ENV=", 1)[1].split("\n", 1)[1]), f"{key} is listed but never set"


def test_the_script_has_no_package_list_of_its_own() -> None:
    code = [ln for ln in SCRIPT.read_text(encoding="utf-8").splitlines() if not ln.lstrip().startswith("#")]
    assert code, "the script parsed to nothing"
    installs = [ln for ln in code if re.search(r"\bpip install\b|--with\b", ln)]
    # The extractor's own pyyaml is the only thing the script names.
    assert installs == [ln for ln in installs if "--with pyyaml python scripts/ci_step.py" in ln], installs
    assert any("--with pyyaml" in ln for ln in installs), "the extractor call moved; re-check this test"
    assert 'bash -e -c "$install_body"' in "\n".join(code)
    assert 'bash -e -c "$run_body"' in "\n".join(code)


def test_the_venv_lives_outside_the_checkout() -> None:
    # test_ci_public_safety scans the tree for user-visible paths; a venv
    # inside it (site-packages docstrings) failed that test locally.
    body = SCRIPT.read_text(encoding="utf-8")
    assert 'cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/noomesh/test-core-venv"' in body
    assert 'venv="${NOO_TEST_CORE_VENV:-$cache_dir/' in body
    assert 'case "$venv" in "$root"|"$root"/*)' in body
    assert "TRELLION_PUBLIC=false" not in body, "the switch comes from ci.yml, not from here"


def _workflow(tmp_path: Path, run: str, env: dict[str, str] | None = None) -> Path:
    import yaml

    step = {"name": "Run tests", "run": run}
    if env:
        step["env"] = env
    wf = tmp_path / "ci.yml"
    wf.write_text(yaml.safe_dump({"jobs": {"test-core": {"steps": [step]}}}), encoding="utf-8")
    return wf


@pytest.mark.parametrize(
    "run, env",
    [
        ("echo ${{ secrets.TOKEN }}", None),
        ("sudo apt-get install -y bubblewrap", None),
        ("echo $GITHUB_TOKEN | gh auth login --with-token", None),
        ("docker login ghcr.io -u x --password-stdin", None),
        ("pytest tests/", {"TOKEN": "${{ secrets.GITHUB_TOKEN }}"}),
        ("pytest tests/", {"WHO": "${{ github.actor }}"}),
    ],
)
def test_a_step_that_could_touch_a_credential_is_refused(tmp_path: Path, monkeypatch, capsys, run, env) -> None:
    wf = _workflow(tmp_path, run, env)
    with pytest.raises(ci_step.StepError, match="refusing to run it locally"):
        ci_step.safe_step("test-core", "Run tests", wf)
    # The command line refuses too, naming the step, and prints no body.
    monkeypatch.setattr(ci_step, "WORKFLOW", wf)
    assert ci_step.main(["test-core", "Run tests"]) == 2
    out, err = capsys.readouterr()
    assert out == "" and "'Run tests'" in err and "refusing" in err, (out, err)


def test_the_expressions_the_local_runner_supplies_are_allowed(tmp_path: Path) -> None:
    env = {
        "TRELLION_PUBLIC": "${{ steps.trellion.outputs.public }}",
        "NOO_KB_AUDIENCE_TEST_DSN": "postgresql://noo:noo@localhost:${{ job.services.postgres.ports['5432'] }}/noomesh",
        "PAI_TRELLION_CHECKOUT": "${{ github.workspace }}/_no_sibling_checkout",
    }
    step = ci_step.safe_step("test-core", "Run tests", _workflow(tmp_path, "pytest tests/", env))
    assert step["run"] == "pytest tests/"


def test_a_missing_or_doubled_step_is_an_error(tmp_path: Path) -> None:
    wf = _workflow(tmp_path, "pytest tests/")
    with pytest.raises(ci_step.StepError, match="0 steps"):
        ci_step.safe_step("test-core", "Install dependencies", wf)
    with pytest.raises(ci_step.StepError, match="0 steps"):
        ci_step.safe_step("no-such-job", "Run tests", wf)
    import yaml

    doubled = {"jobs": {"test-core": {"steps": [{"name": "Run tests", "run": "a"}, {"name": "Run tests", "run": "b"}]}}}
    wf.write_text(yaml.safe_dump(doubled), encoding="utf-8")
    with pytest.raises(ci_step.StepError, match="2 steps"):
        ci_step.safe_step("test-core", "Run tests", wf)


def test_a_workflow_switch_with_an_expression_is_refused(tmp_path: Path) -> None:
    import yaml

    wf = tmp_path / "ci.yml"
    wf.write_text(yaml.safe_dump({"env": {"TRELLION_PUBLIC": "${{ secrets.X }}", "OK": "true"}}), encoding="utf-8")
    assert ci_step.workflow_env("OK", wf) == "true"
    with pytest.raises(ci_step.StepError, match="refusing"):
        ci_step.workflow_env("TRELLION_PUBLIC", wf)
    with pytest.raises(ci_step.StepError, match="no top-level env"):
        ci_step.workflow_env("MISSING", wf)
