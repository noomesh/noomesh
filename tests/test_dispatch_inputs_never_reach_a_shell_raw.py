# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""No `workflow_dispatch` input reaches a shell unvalidated, in any workflow.

The finding (2026-11-20): install-matrix.yml passed the free-text input
`cli_tag` through `env:` correctly, but scripts/install-cell/run.sh spliced it
into the README install line with sed and ran that with `sh -c`: a dispatched
`cli_tag` holding `$(...)`, a backtick or `;` ran on a runner with a token.

The rules this file holds:

1. No `run:` script contains `${{ inputs.* }}` or `${{ github.event.inputs.* }}`
   (the expression is pasted into the script before the shell parses it). An
   input reaches a script only through `env:`.
2. Every FREE-TEXT dispatch input (not `type: choice`, not `type: boolean`:
   GitHub refuses a value outside a choice's options or a boolean server-side,
   on the UI and the API alike) is either
   - checked by a job's FIRST step, named `Validate dispatch inputs`, in every
     job that reads it (shell: bash, no `if:`, no continue-on-error), against
     the narrowest pattern for its meaning (KINDS below); this file RUNS each
     such step on the kind's corpus, so every copy of a rule is held to the
     same accepted and refused values; or
   - in ALLOWED with the reason it never reaches a shell unvalidated.
3. The install cells refuse on their own: run.sh and upgrade.sh source
   scripts/install-cell/validate_tag.sh and refuse before any use, and
   upgrade_judge.py resolve fullmatches CLI_TAG before any network read.
"""
import importlib.util
import pathlib
import re
import subprocess

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
CELL = ROOT / "scripts" / "install-cell"
VALIDATE_SH = CELL / "validate_tag.sh"
JUDGE = CELL / "upgrade_judge.py"
STEP_NAME = "Validate dispatch inputs"
END_OF_CHECK = "# ── end of the dispatch-input check ──"

# A `${{ ... }}` expression that reads a dispatch input (`inputs.x`, or
# `github.event.inputs.x`, anywhere inside the expression).
INPUT_EXPR = re.compile(r"\$\{\{[^}]*\binputs\.")


# ── the corpora ─────────────────────────────────────────────────────────────

def _injections(valid: str) -> list[str]:
    """Shell metacharacters, whitespace and newlines around a valid value."""
    return [valid + ";id", valid + "$(id)", valid + "`id`", valid + " ", " " + valid,
            valid + "\n", valid + "\nid", valid + "|id", valid + "&id", "$(id)", "`id`", ";", "a b"]


CLI_TAG_OK = ["latest", "noo-cli-v0.6.29", "noo-cli-v0.6.29-rc.1", "noo-cli-v10.20.300-rc.12"]
CLI_TAG_BAD = (_injections("noo-cli-v0.6.29") + _injections("latest") + [
    "", "noo-cli-v1.2.3.4", "noo-cli-v1.2", "noo-cli-v1.2.3-rc", "noo-cli-v1.2.3-beta.1",
    "noo-cli-v1.2.3-rc.1-rc.2", "noo-cli-v1.2.3-rc.", "v1.2.3", "stack-v1.2.3", "LATEST",
    "noo-cli-v٣.1.2", "noo-cli-v１.2.3", "noo-cli-v1.2.3-rc.¹", "noo-cli-v1.2.3-rc.1\n",
])
PREV_TAG_OK = ["", "noo-cli-v0.6.28", "noo-cli-v1.0.0"]
PREV_TAG_BAD = (_injections("noo-cli-v0.6.28") + [
    "latest", "noo-cli-v0.6.28-rc.1", "noo-cli-v1.2", "noo-cli-v1.2.3.4", "v1.2.3",
    "noo-cli-v٣.1.2", " ",
])
STACK_TAG_OK = ["v0.6.29", "stack-v0.6.29", "v0.6.29-rc.1", "stack-v0.6.29-rc.3"]
STACK_TAG_BAD = (_injections("stack-v0.6.29") + _injections("v0.6.29") + [
    "", "stack-stack-v1.2.3", "stack-v1.2", "stack-v1.2.3.4", "stack-v1.2.3-rc", "stack-v1.2.3-beta.1",
    "noo-cli-v1.2.3", "latest", "main", "stack-v٣.1.2", "stack-v1.2.3-rc.1\n",
])
HARRIER_RELEASE_OK = ["models-harrier-v1", "models-harrier-v12"]
HARRIER_RELEASE_BAD = _injections("models-harrier-v1") + [
    "", "models-harrier-v", "models-harrier-v1.2", "v1", "models-harrier-v١"]
HARRIER_IMAGE_TAG_OK = ["v1", "v2", "v10"]
HARRIER_IMAGE_TAG_BAD = _injections("v2") + ["", "latest", "v", "v1.2", "2", "V2", "v٢"]

# kind -> (accepted, refused)
CORPORA = {
    "cli_tag": (CLI_TAG_OK, CLI_TAG_BAD),
    "prev_tag": (PREV_TAG_OK, PREV_TAG_BAD),
    "stack_tag": (STACK_TAG_OK, STACK_TAG_BAD),
    "harrier_release": (HARRIER_RELEASE_OK, HARRIER_RELEASE_BAD),
    "harrier_image_tag": (HARRIER_IMAGE_TAG_OK, HARRIER_IMAGE_TAG_BAD),
}

# (workflow file, free-text input) -> its kind. A new free-text input fails
# test_every_free_text_input_is_declared until it is declared here (and
# validated) or in ALLOWED.
KINDS = {
    ("install-matrix.yml", "cli_tag"): "cli_tag",
    ("install-matrix.yml", "prev_tag"): "prev_tag",
    ("images-release.yml", "tag"): "stack_tag",
    ("publish-web.yml", "tag"): "stack_tag",
    ("publish-harrier.yml", "release"): "harrier_release",
    ("publish-harrier.yml", "image_tag"): "harrier_image_tag",
}

# Free-text inputs validated somewhere other than a first step, with why.
ALLOWED = {
    ("mutants.yml", "mutants"): (
        "read only through env MUTANTS by `python3 scripts/ci-mutants.py plan` (the harness from the "
        "workflow's own commit), whose parse_mutants holds every token to BRANCH_RE/FILTER_RE before any "
        "git call; git runs from argv lists, never a shell (tests/test_mutants_workflow.py)"),
    ("mutants.yml", "lanes"): (
        "read only through env LANES by `python3 scripts/ci-mutants.py plan`, whose parse_lanes refuses "
        "anything but the four lane names (tests/test_mutants_workflow.py)"),
}


# ── reading the workflows ───────────────────────────────────────────────────

def _load(path: pathlib.Path) -> dict:
    return yaml.safe_load(path.read_text())


def _workflows() -> dict[str, dict]:
    return {p.name: _load(p) for p in sorted(WORKFLOWS.glob("*.y*ml"))}


def _dispatch_inputs(doc: dict) -> dict:
    on = doc.get("on", doc.get(True))
    if not isinstance(on, dict) or "workflow_dispatch" not in on:
        return {}
    return (on["workflow_dispatch"] or {}).get("inputs") or {}


def _free_text(spec: dict) -> bool:
    return (spec or {}).get("type", "string") not in ("choice", "boolean")


def _runs(node, where=""):
    """Every `run:` script in a workflow document: (where, script)."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "run" and isinstance(v, str):
                yield where, v
            else:
                yield from _runs(v, f"{where}/{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _runs(v, f"{where}[{i}]")


def interpolated_runs(doc: dict) -> list[str]:
    """Where a `run:` script pastes a dispatch input in with `${{ }}`."""
    return [where for where, script in _runs(doc) if INPUT_EXPR.search(script)]


def _strip_ifs(node):
    """The node without its `if:` keys: an `if:` is an expression GitHub
    evaluates, never shell text."""
    if isinstance(node, dict):
        return {k: _strip_ifs(v) for k, v in node.items() if k != "if"}
    if isinstance(node, list):
        return [_strip_ifs(v) for v in node]
    return node


def _reads(node, name: str) -> bool:
    return re.search(r"\binputs\." + re.escape(name) + r"\b", yaml.safe_dump(_strip_ifs(node))) is not None


def _validation_sites():
    """(workflow, job, step, env, {var: kind}) for every job that reads a
    declared free-text input, and the problems found on the way."""
    sites, problems = [], []
    for wf, doc in _workflows().items():
        inputs = {n: s for n, s in _dispatch_inputs(doc).items() if (wf, n) in KINDS}
        if not inputs:
            continue
        top_env = doc.get("env") or {}
        for job_id, job in (doc.get("jobs") or {}).items():
            names = [n for n in inputs if _reads(job, n) or _reads(top_env, n)]
            if not names:
                continue
            steps = job.get("steps") or []
            first = steps[0] if steps else {}
            if first.get("name") != STEP_NAME:
                problems.append(f"{wf} job {job_id} reads {names} but its first step is not {STEP_NAME!r}")
                continue
            for key in ("if", "continue-on-error"):
                if key in first:
                    problems.append(f"{wf} job {job_id}: {STEP_NAME!r} has `{key}:` (it must always run and fail)")
            if first.get("shell") != "bash":
                problems.append(f"{wf} job {job_id}: {STEP_NAME!r} must say `shell: bash` (every runner OS)")
            env = {**top_env, **(job.get("env") or {}), **(first.get("env") or {})}
            kinds = {}
            for n in names:
                vars_ = [k for k, v in env.items() if re.search(r"\binputs\." + re.escape(n) + r"\b", str(v))]
                if not vars_:
                    problems.append(f"{wf} job {job_id}: {STEP_NAME!r} does not read input {n} from env")
                for k in vars_:
                    kinds[k] = KINDS[(wf, n)]
                    if not re.search(r"\$\{?" + re.escape(k) + r"\b", first.get("run") or ""):
                        problems.append(f"{wf} job {job_id}: {STEP_NAME!r} never checks ${k} (input {n})")
            sites.append((wf, job_id, first, env, kinds))
    return sites, problems


def _run_step(step: dict, env: dict) -> subprocess.CompletedProcess:
    # GitHub's `shell: bash` is `bash --noprofile --norc -eo pipefail {0}`.
    return subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]],
                          env={"PATH": "/usr/bin:/bin", **env}, capture_output=True, text=True, timeout=30)


# ── rule 1: no `${{ inputs.* }}` in a run: script ────────────────────────────

def test_no_run_script_interpolates_a_dispatch_input():
    bad = {wf: hits for wf, doc in _workflows().items() if (hits := interpolated_runs(doc))}
    assert not bad, (
        f"run: scripts paste a dispatch input in with ${{{{ }}}} (script injection): {bad}; "
        "pass it through `env:` and validate it in the job's first step")


def test_the_run_scan_catches_every_interpolation_shape():
    """The scan itself: a scan that reads nothing passes every workflow."""
    for expr in ("${{ inputs.tag }}", "${{ github.event.inputs.tag }}", "${{inputs.tag}}",
                 "${{ inputs.tag || github.ref_name }}", "${{ github.ref_name || github.event.inputs.tag }}"):
        doc = {"jobs": {"j": {"steps": [{"run": "echo ok"}, {"run": f'raw="{expr}"'}]}}}
        assert interpolated_runs(doc) == ["/jobs/j/steps[1]"], expr
    clean = {"jobs": {"j": {"steps": [{"env": {"T": "${{ inputs.tag }}"}, "run": 'echo "$T"'}]}}}
    assert interpolated_runs(clean) == []


# ── rule 2: every free-text input is validated first, or allowed ────────────

def test_every_free_text_input_is_declared():
    seen, missing = set(), []
    for wf, doc in _workflows().items():
        for name, spec in _dispatch_inputs(doc).items():
            if not _free_text(spec):
                if (spec or {}).get("type") == "choice":
                    assert (spec or {}).get("options"), f"{wf} choice input {name} has no options"
                continue
            seen.add((wf, name))
            if (wf, name) not in KINDS and (wf, name) not in ALLOWED:
                missing.append(f"{wf}: {name}")
    assert not missing, (
        f"free-text dispatch inputs with no declared rule: {missing}. Validate each in a first step "
        f"{STEP_NAME!r} and declare its kind in KINDS, or make it a choice/boolean, or add it to "
        "ALLOWED with the reason it never reaches a shell unvalidated")
    stale = (set(KINDS) | set(ALLOWED)) - seen
    assert not stale, f"declared inputs that are no longer free-text dispatch inputs: {sorted(stale)}"
    assert not set(KINDS) & set(ALLOWED)


def test_every_job_that_reads_a_free_text_input_validates_it_first():
    sites, problems = _validation_sites()
    assert not problems, "\n".join(problems)
    covered = {(wf, k) for wf, _, _, _, kinds in sites for k in kinds.values()}
    assert {(wf, kind) for (wf, _), kind in KINDS.items()} <= covered, "a declared input is read by no job"


def test_the_install_matrix_validates_cli_tag_in_every_job_that_runs_a_cell():
    sites, _ = _validation_sites()
    jobs = {job for wf, job, _, _, kinds in sites if wf == "install-matrix.yml" and "cli_tag" in kinds.values()}
    assert jobs == {"cell", "wsl2", "upgrade"}, jobs


def _site_ids():
    sites, _ = _validation_sites()
    return [pytest.param(s, id=f"{s[0]}:{s[1]}") for s in sites]


@pytest.mark.parametrize("site", _site_ids())
def test_each_validation_step_holds_its_inputs_to_the_corpus(site):
    wf, job, step, env, kinds = site
    valid = {var: CORPORA[kind][0][-1] for var, kind in kinds.items()}
    for var, kind in kinds.items():
        ok, bad = CORPORA[kind]
        for value in ok:
            r = _run_step(step, {**valid, var: value})
            assert r.returncode == 0, f"{wf}:{job} refused {var}={value!r}: {r.stdout}{r.stderr}"
        for value in bad:
            r = _run_step(step, {**valid, var: value})
            assert r.returncode != 0, f"{wf}:{job} ACCEPTED {var}={value!r}"
            assert "::error::" in r.stdout and "refused" in r.stdout, (wf, job, var, value, r.stdout)


# ── rule 3: the install cells refuse on their own ───────────────────────────

def _bash_validator(fn: str, value: str) -> int:
    return subprocess.run(["bash", "-c", f'. "$1"; {fn} "$2"', "v", str(VALIDATE_SH), value],
                          env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=30).returncode


def _judge():
    spec = importlib.util.spec_from_file_location("upgrade_judge_dispatch", JUDGE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("kind,fn", [("cli_tag", "require_cli_tag"), ("prev_tag", "require_prev_tag")])
def test_the_shared_shell_validator_holds_the_corpus(kind, fn):
    ok, bad = CORPORA[kind]
    assert [v for v in ok if _bash_validator(fn, v) != 0] == []
    assert [v for v in bad if _bash_validator(fn, v) == 0] == []


def test_the_judge_holds_cli_tag_to_the_same_rule():
    judge = _judge()
    assert [v for v in CLI_TAG_OK if not judge.CLI_TAG.fullmatch(v)] == []
    assert [v for v in CLI_TAG_BAD if judge.CLI_TAG.fullmatch(v)] == []
    assert [v for v in PREV_TAG_OK if v and not judge.FINAL.fullmatch(v)] == []
    assert [v for v in PREV_TAG_BAD if judge.FINAL.fullmatch(v)] == []


def test_resolve_refuses_a_bad_cli_tag_before_any_network_read(tmp_path, monkeypatch):
    judge = _judge()

    def no_network(*a, **k):
        raise AssertionError("resolve read the network for a CLI_TAG it must refuse")

    monkeypatch.setattr(judge, "_api", no_network)
    for tag in CLI_TAG_BAD:
        with pytest.raises(SystemExit) as e:
            judge.resolve("example-org/example-repo", tag, str(tmp_path / "p"), str(tmp_path / "t"))
        assert "refused" in str(e.value) and "latest or noo-cli-vX.Y.Z" in str(e.value), (tag, e.value)


def _prefix(script: pathlib.Path) -> str:
    text = script.read_text()
    assert text.count(END_OF_CHECK) == 1, f"{script.name}: the end-of-check marker is missing"
    return text[: text.index(END_OF_CHECK)]


@pytest.mark.parametrize("name,checks", [
    ("run.sh", {"CLI_TAG": "cli_tag"}),
    ("upgrade.sh", {"CLI_TAG": "cli_tag", "PREV_TAG": "prev_tag"}),
])
def test_each_cell_script_refuses_at_its_top(tmp_path, name, checks):
    """The script's own lines up to the end-of-check marker, run as the
    script: a refused value exits 2 there, before anything else runs."""
    script = CELL / name
    prefix = _prefix(script)
    for var in checks:
        uses = [ln for ln in prefix.splitlines() if var in ln and not ln.lstrip().startswith("#")]
        assert len(uses) == 2 and f'${{{var}:=' in uses[0] and f'"${var}" || exit 2' in uses[1], (name, uses)
    valid = {var: CORPORA[kind][0][1] for var, kind in checks.items()}
    for var, kind in checks.items():
        ok, bad = CORPORA[kind]
        for value, want in [(v, 0) for v in ok] + [(v, 2) for v in bad if v]:
            env = {"PATH": "/usr/bin:/bin", "OUT": str(tmp_path / "out"), "CELL": "t", **valid, var: value}
            r = subprocess.run(["bash", "-c", prefix, str(script)], env=env, capture_output=True, text=True,
                               timeout=30)
            assert r.returncode == want, f"{name} {var}={value!r}: exit {r.returncode}, want {want}: {r.stderr}"
    # Empty CLI_TAG is the documented default (`latest`), never passed raw.
    env = {"PATH": "/usr/bin:/bin", "OUT": str(tmp_path / "out"), "CELL": "t", **valid, "CLI_TAG": ""}
    assert subprocess.run(["bash", "-c", prefix, str(script)], env=env, capture_output=True,
                          timeout=30).returncode == 0
