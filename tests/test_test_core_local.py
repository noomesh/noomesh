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
    assert 'venv="${NOO_TEST_CORE_VENV:-${XDG_CACHE_HOME:-$HOME/.cache}/' in body
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


# --- venv cleanup (--gc-only) -------------------------------------------------
# The script keeps one ~1.7 GB venv per checkout path and used to never delete
# one (a shared box reached 176 GB). `--gc-only` runs just the cleanup, with
# XDG_CACHE_HOME pointed at a temp dir; no uv, no install.

import hashlib  # noqa: E402
import os  # noqa: E402
import subprocess  # noqa: E402
import time  # noqa: E402

_CURRENT = hashlib.sha256(str(ROOT).encode()).hexdigest()[:16]
_DAY = 86400


def _venv(base: Path, name: str, *, root: Path | None = None, age_days: float = 0, used: bool = True) -> Path:
    d = base / name
    (d / "bin").mkdir(parents=True)
    (d / "bin" / "python").write_text("", encoding="utf-8")
    (d / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    if root is not None:
        (d / ".root").write_text(f"{root}\n", encoding="utf-8")
    t = time.time() - age_days * _DAY
    if used:
        (d / ".last-used").write_text("", encoding="utf-8")
        os.utime(d / ".last-used", (t, t))
    os.utime(d, (t, t))
    return d


def _gc(tmp_path: Path, **env: str) -> subprocess.CompletedProcess:
    e = {k: v for k, v in os.environ.items() if not k.startswith("NOO_TEST_CORE_")}
    e["XDG_CACHE_HOME"] = str(tmp_path / "cache")
    e.update(env)
    return subprocess.run(
        ["bash", str(SCRIPT), "--gc-only"], cwd=ROOT, env=e, capture_output=True, text=True, timeout=60
    )


def _base(tmp_path: Path) -> Path:
    b = tmp_path / "cache" / "noomesh" / "test-core-venv"
    b.mkdir(parents=True)
    return b


def test_gc_removes_a_venv_whose_checkout_is_gone(tmp_path: Path) -> None:
    base = _base(tmp_path)
    live = tmp_path / "live-checkout"
    live.mkdir()
    gone = _venv(base, "a" * 16, root=tmp_path / "deleted-worktree")
    kept = _venv(base, "b" * 16, root=live)
    r = _gc(tmp_path)
    assert r.returncode == 0, r.stderr
    assert not gone.exists() and kept.exists()
    assert f"removed venv {'a' * 16} (its checkout {tmp_path / 'deleted-worktree'} is gone," in r.stdout
    assert "removed 1 venv(s)" in r.stdout


def test_gc_removes_an_old_venv_with_no_root_and_keeps_a_fresh_one(tmp_path: Path) -> None:
    base = _base(tmp_path)
    old = _venv(base, "c" * 16, age_days=15)
    fresh = _venv(base, "d" * 16, age_days=2)
    old_no_stamp = _venv(base, "e" * 16, age_days=20, used=False)  # dir mtime decides
    fresh_no_stamp = _venv(base, "f" * 16, age_days=1, used=False)
    r = _gc(tmp_path)
    assert r.returncode == 0, r.stderr
    assert not old.exists() and not old_no_stamp.exists()
    assert fresh.exists() and fresh_no_stamp.exists()


def test_gc_caps_the_count_least_recently_used_first_and_spares_the_current(tmp_path: Path) -> None:
    base = _base(tmp_path)
    live = tmp_path / "live"
    live.mkdir()
    current = _venv(base, _CURRENT, root=ROOT, age_days=100)  # oldest, but current
    names = ["1" * 16, "2" * 16, "3" * 16, "4" * 16]
    venvs = [_venv(base, n, root=live, age_days=age) for n, age in zip(names, [1, 2, 3, 4])]
    r = _gc(tmp_path, NOO_TEST_CORE_VENVS_KEEP="3")
    assert r.returncode == 0, r.stderr
    # current + the 2 most recently used survive; the 2 least recent go.
    assert current.exists() and venvs[0].exists() and venvs[1].exists()
    assert not venvs[2].exists() and not venvs[3].exists()
    assert r.stdout.count("removed venv") == 2 and "over the cap of 3" in r.stdout


def test_gc_default_cap_is_four(tmp_path: Path) -> None:
    base = _base(tmp_path)
    live = tmp_path / "live"
    live.mkdir()
    vs = [_venv(base, f"{i:016x}", root=live, age_days=i) for i in range(1, 7)]
    assert _gc(tmp_path).returncode == 0
    # the current venv does not exist here, so 4 are kept: ages 1..4.
    assert [v.exists() for v in vs] == [True, True, True, True, False, False]


def test_gc_leaves_odd_names_and_symlinks_alone(tmp_path: Path) -> None:
    base = _base(tmp_path)
    odd = _venv(base, "not-a-venv-name", age_days=400)
    upper = _venv(base, "A" * 16, age_days=400)
    short = _venv(base, "abc", age_days=400)
    no_python = base / ("9" * 16)
    no_python.mkdir()
    os.utime(no_python, (0, 0))
    target = _venv(tmp_path, "t" * 16, age_days=400)
    link = base / ("8" * 16)
    link.symlink_to(target, target_is_directory=True)
    r = _gc(tmp_path, NOO_TEST_CORE_VENVS_KEEP="0")
    assert r.returncode == 0, r.stderr
    for p in (odd, upper, short, no_python, target):
        assert p.exists(), p
    assert link.is_symlink() and (target / "bin" / "python").exists()
    assert "removed venv" not in r.stdout


def test_gc_does_nothing_when_the_user_chose_the_venv(tmp_path: Path) -> None:
    base = _base(tmp_path)
    gone = _venv(base, "a" * 16, root=tmp_path / "deleted")
    mine = _venv(tmp_path, "mine", age_days=400)
    r = _gc(tmp_path, NOO_TEST_CORE_VENV=str(mine))
    assert r.returncode == 0, r.stderr
    assert gone.exists() and mine.exists() and r.stdout == ""


def test_the_run_records_root_and_last_used_before_it_prunes() -> None:
    body = SCRIPT.read_text(encoding="utf-8")
    assert '> "$venv/.root"' in body and 'touch "$venv/.last-used"' in body
    # The cleanup runs before pytest is exec'd.
    assert body.index("\ngc_venvs ||") < body.index('exec pytest "$@"')


def test_gc_never_removes_a_venv_a_live_process_is_using(tmp_path: Path) -> None:
    if not Path("/proc/self").is_dir():
        pytest.skip("needs Linux /proc")
    base = _base(tmp_path)
    busy = _venv(base, "a" * 16, root=tmp_path / "deleted", age_days=50)  # root gone AND over cap
    idle = _venv(base, "b" * 16, root=tmp_path / "deleted", age_days=50)
    proc = subprocess.Popen(["sleep", "30"], cwd=busy)
    try:
        r = _gc(tmp_path, NOO_TEST_CORE_VENVS_KEEP="0")
    finally:
        proc.kill()
        proc.wait()
    assert r.returncode == 0, r.stderr
    assert busy.exists() and not idle.exists()
    assert f"kept venv {'a' * 16} (in use by pid {proc.pid})" in r.stdout


def test_gc_orders_by_the_last_used_marker_not_dir_mtime(tmp_path: Path) -> None:
    base = _base(tmp_path)
    live = tmp_path / "live"
    live.mkdir()
    old_marker = _venv(base, "1" * 16, root=live, age_days=30)
    new_marker = _venv(base, "2" * 16, root=live, age_days=1)
    no_marker = _venv(base, "3" * 16, root=live, age_days=0, used=False)
    now = time.time()
    os.utime(old_marker, (now, now))  # fresh dir mtime, old marker
    os.utime(new_marker, (now - 90 * _DAY,) * 2)  # old dir mtime, fresh marker
    r = _gc(tmp_path, NOO_TEST_CORE_VENVS_KEEP="2")
    assert r.returncode == 0, r.stderr
    assert not no_marker.exists()  # no marker sorts oldest
    assert old_marker.exists() and new_marker.exists()
    r = _gc(tmp_path, NOO_TEST_CORE_VENVS_KEEP="1")
    assert not old_marker.exists() and new_marker.exists()
