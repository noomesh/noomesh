# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every workflow that SHIPS to the public repository is safe to run there.

One `ci.yml` is used by the private source repository and by the public one.
It stays safe in the public repository because every job that needs something
the public repository does not have carries

    if: github.repository == 'noomesh/noomesh'

so it is SKIPPED (not failed) anywhere else. This test holds the shipped
workflows to that rule:

  (a) a job that references a secret other than GITHUB_TOKEN, a self-hosted
      runner or a private sibling repository carries the private-repo guard
      (a step-level guard covers a reference inside that step only);
  (b) no `runs-on` can resolve to a self-hosted runner in the public
      repository, even if someone sets the CI_RUNNER variable there;
  (c) the public repository still has a job for each language the product is
      written in (python, rust gateway, rust noo-cli, go, ui);
  (d) nothing hands fork code a secret or a write token through
      `pull_request_target`, and ci.yml's optional leak gate is skipped, not
      failed, when the script is absent.

The set of workflows that ship is computed the way scripts/leak-check.sh
computes the files that ship: the sync's own exclude arrays, applied by rsync.
In the public tree there is no sync script and every workflow present ships.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO / ".github" / "workflows"
SYNC = REPO / "scripts" / "sync-to-oss.sh"

# After the org move (#787) the canonical repo, the one that holds the secrets and
# the app credentials, is the public one; a fork has a different github.repository,
# so a guarded job is SKIPPED there instead of failing on secrets it cannot read.
PRIVATE_REPO = "noomesh/noomesh"
PRIVATE_GUARD = f"github.repository == '{PRIVATE_REPO}'"
PUBLIC_GUARD = "github.repository == 'noomesh/noomesh'"

# Triggers a stranger can cause. A secret in a workflow that only runs on tags,
# schedules and manual dispatch cannot be reached from a fork.
FORK_REACHABLE = {"pull_request", "pull_request_target", "issue_comment", "issues", "pull_request_review", "pull_request_review_comment", "workflow_run"}

# (workflow, job) -> secrets that may be used without the private guard, with
# the reason. The CLA job is public-only (`PUBLIC_GUARD`) and is the one job
# whose whole purpose is a public pull_request_target gate; it checks out no
# code (asserted below).
ALLOWED_UNGUARDED_SECRETS = {
    ("cla.yml", "cla"): {"CLA_PAT"},
}


# ---- helpers ----------------------------------------------------------------


def _array(name: str) -> list[str]:
    text = SYNC.read_text()
    m = re.search(rf"^{name}=\((.*?)^\)", text, re.S | re.M)
    assert m, f"{name} not found in {SYNC}"
    out = []
    for line in m.group(1).splitlines():
        line = line.split("#", 1)[0].strip() if not line.strip().startswith('"') else line.strip()
        m2 = re.match(r'^"([^"]+)"', line)
        if m2:
            out.append(m2.group(1))
    return out


def _shipped_workflow_names() -> list[str]:
    names = sorted(p.name for p in WORKFLOWS_DIR.glob("*.yml"))
    if not SYNC.exists():  # the public tree: whatever is here ships
        return names
    rsync = shutil.which("rsync")
    assert rsync, "rsync is required to apply the sync's exclude list (leak-check.sh needs it too)"
    import tempfile

    excludes = []
    for arr in ("PRO_EXCLUDES", "PRIVATE_EXCLUDES", "ARTIFACT_EXCLUDES"):
        excludes += [f"--exclude={e}" for e in _array(arr)]
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "src"
        (src / ".github" / "workflows").mkdir(parents=True)
        for n in names:
            (src / ".github" / "workflows" / n).write_text("")
        r = subprocess.run(
            [rsync, "-rn", "--out-format=%n", "--exclude=.git", *excludes, f"{src}/", f"{td}/dest/"],
            capture_output=True,
            text=True,
            check=True,
        )
    shipped = {Path(line).name for line in r.stdout.splitlines() if line.startswith(".github/workflows/") and line.endswith(".yml")}
    return sorted(shipped)


def _load(name: str) -> dict:
    doc = yaml.safe_load((WORKFLOWS_DIR / name).read_text())
    assert isinstance(doc, dict), name
    return doc


def _triggers(doc: dict) -> set[str]:
    on = doc.get("on", doc.get(True))  # PyYAML reads a bare `on:` as True
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    return set(on or {})


def _strip_expr(s: str) -> str:
    s = s.strip()
    m = re.fullmatch(r"\$\{\{(.*)\}\}", s, re.S)
    return (m.group(1) if m else s).strip()


def _split_top(expr: str, op: str) -> list[str]:
    """Split on `op` outside parentheses and quotes."""
    parts, depth, quote, cur, i = [], 0, None, "", 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            cur += ch
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            cur += ch
        elif ch == "(":
            depth += 1
            cur += ch
        elif ch == ")":
            depth -= 1
            cur += ch
        elif depth == 0 and expr.startswith(op, i):
            parts.append(cur.strip())
            cur = ""
            i += len(op)
            continue
        else:
            cur += ch
        i += 1
    parts.append(cur.strip())
    return parts


def _guarded(cond, guard: str | None = None) -> bool:
    """True when `guard` is a top-level conjunct of the `if:` expression.

    With no `guard`, the canonical-repo guard counts (a secret other than GITHUB_TOKEN)."""
    if cond is None:
        return False
    conjuncts = _split_top(_strip_expr(str(cond)), "&&")
    if guard is None:
        return PRIVATE_GUARD in conjuncts
    return guard in conjuncts


SECRET_RE = re.compile(r"secrets\.([A-Za-z0-9_]+)")
PUBLIC_ORGS = {"noomesh", "personifAI"}
# A private sibling repo is named by its `pai-*` slug under any org, or reached through the sibling PAT.
SIBLING_RE = re.compile(r"[A-Za-z0-9_.-]+/pai-[a-z-]+|PAI_REPOS_PAT")


def _refs(blob) -> set[str]:
    """Things in `blob` that exist only in the private repository."""
    text = json.dumps(blob, default=str)  # not yaml: its line folding can split a word
    found = {f"secret:{s}" for s in SECRET_RE.findall(text) if s != "GITHUB_TOKEN"}
    found |= {f"sibling:{s}" for s in SIBLING_RE.findall(text)}
    return found


def _private_refs(job: dict) -> list[tuple[str, set[str]]]:
    """[(where, refs)] for the job outside its steps and for each step."""
    rest = {k: v for k, v in job.items() if k != "steps"}
    out = [("job", _refs(rest) | ({"self-hosted"} if "self-hosted" in json.dumps(job.get("runs-on")) else set()))]
    for i, step in enumerate(job.get("steps") or []):
        out.append((f"step {i} ({step.get('name') or step.get('uses') or step.get('run', '')[:30]!r})", _refs(step)))
    return [(w, r) for w, r in out if r]


def _jobs():
    for wf in _shipped_workflow_names():
        doc = _load(wf)
        for name, job in (doc.get("jobs") or {}).items():
            yield wf, name, job, doc


JOBS = list(_jobs()) if WORKFLOWS_DIR.exists() else []


def _id(v):
    return f"{v[0]}::{v[1]}"


# ---- the shipped set ----------------------------------------------------------


# The release machinery that ships so the public repository can cut the stack
# release. Neither is reachable from a fork: tag push / manual dispatch only.
RELEASE_WORKFLOWS = ("images-release.yml", "mirror-images.yml")


def test_the_shipped_set_includes_ci_and_the_release_workflows():
    shipped = set(_shipped_workflow_names())
    assert "ci.yml" in shipped, "ci.yml must ship: the public repository's CI"
    for wf in RELEASE_WORKFLOWS:
        assert wf in shipped, f"{wf} must ship: the public repository cuts the stack release"
    if SYNC.exists():
        # gateway-image.yml is a pull_request build check, not a release; the public CI builds the gateway in ci.yml.
        assert "gateway-image.yml" not in shipped, "gateway-image.yml triggers on pull_request and is not shipped"


def test_e_the_public_release_workflow_is_core_only():
    """The stack release is core-only: no add-on build job (the generic
    `addon-dispatch` notifier names no repo: its targets are a repo variable),
    no add-on repo name, no add-on image, and the app token reads only the open
    library. The add-ons release from their own repos with their own lock."""
    if not (WORKFLOWS_DIR / "images-release.yml").exists():
        pytest.skip("images-release.yml not present")
    doc = _load("images-release.yml")
    assert set(doc["jobs"]) == {"release-line", "static-ffmpeg", "deps-core", "deps-base", "images", "lock", "addon-dispatch"}, sorted(doc["jobs"])
    text = (WORKFLOWS_DIR / "images-release.yml").read_text()
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    for private in ("trellion-intel", "trellion-evolve", "evolve", "addon-image-resolve", "PRIVATE_UPSTREAM", "PAI_REPOS_PAT"):
        assert private not in code, f"images-release.yml (shipped) mentions the private add-on {private!r}"
    orgs = set(re.findall(r"(?<![\w.])github\.com/([\w.-]+)/", code))
    assert orgs <= PUBLIC_ORGS, f"images-release.yml (shipped) names a non-public org: {sorted(orgs - PUBLIC_ORGS)}"
    for m in re.findall(r"repositories:\s*(\S+)", code):
        assert set(m.split(",")) <= {"trellion", "trellion-protocols"}, f"the app token may read only the open library, got {m}"


def _release_docs():
    return [(wf, _load(wf)) for wf in RELEASE_WORKFLOWS if (WORKFLOWS_DIR / wf).exists()]


@pytest.mark.parametrize("wf,doc", _release_docs(), ids=[w for w, _ in _release_docs()])
def test_e_a_release_workflow_runs_only_on_a_tag_or_a_manual_dispatch(wf, doc):
    on = doc.get("on", doc.get(True))
    assert isinstance(on, dict), wf
    assert set(on) <= {"push", "workflow_dispatch"}, f"{wf} has triggers a stranger can cause or that fire unattended: {sorted(on)}"
    push = on.get("push")
    if push is not None:
        assert set(push) == {"tags"}, f"{wf}: a push trigger must be tags-only, got {sorted(push)}"
        assert all(t.startswith("stack-v") for t in push["tags"]), push


@pytest.mark.parametrize("wf,doc", _release_docs(), ids=[w for w, _ in _release_docs()])
def test_e_every_job_of_a_release_workflow_is_skipped_outside_the_canonical_repo(wf, doc):
    for name, job in (doc.get("jobs") or {}).items():
        assert _guarded(job.get("if"), PUBLIC_GUARD), (
            f"{wf}::{name} must carry `if: {PUBLIC_GUARD}`: a fork that pushes a stack-v* tag has no "
            "app credentials, registry token or signing seed, and must not start a release"
        )
        assert "self-hosted" not in _runs_on_text(job)


def test_e_the_llamacpp_leg_is_a_plain_core_entry_with_the_shipped_dockerfile():
    """The hardened llama.cpp image ships in the public release (DHI Community): its leg is built, pushed, re-tagged and locked like every other
    core image, with no repository-variable gate and no skip step. A missing
    Dockerfile therefore fails the build instead of dropping a lock row."""
    if not (WORKFLOWS_DIR / "images-release.yml").exists():
        pytest.skip("images-release.yml not present")
    doc = _load("images-release.yml")
    job = doc["jobs"]["images"]
    text = json.dumps(job["steps"])
    assert "LLAMACPP_HARDENED_BUILD" not in text, "the llamacpp leg must not be gated on a repo variable"
    assert "llamacpp" not in text.replace("matrix.image", ""), "no step may special-case llamacpp by name"
    assert "hashFiles" not in text, "a hashFiles gate turns a moved Dockerfile into a silent skip"
    for label, pick in {
        "Build + push": lambda st: st.get("name", "").startswith("Build + push"),
        "Record digest": lambda st: st.get("name") == "Record digest",
        "upload digest": lambda st: "upload-artifact" in str(st.get("uses", "")),
    }.items():
        hits = [st for st in job["steps"] if pick(st)]
        assert hits, f"the images job lost its {label} step"
    entry = [m for m in job["strategy"]["matrix"]["include"] if m.get("name") == "llamacpp"]
    assert len(entry) == 1
    assert entry[0]["dockerfile"] == "docker/Dockerfile.llamacpp"
    assert entry[0]["platforms"] == "linux/amd64", "x86 only: ARM nodes use the upstream multi-arch image"
    assert (REPO / entry[0]["dockerfile"]).is_file()


# ---- (a) private things are guarded -------------------------------------------


@pytest.mark.parametrize("wf,name,job,doc", JOBS, ids=[_id(j) for j in JOBS])
def test_a_job_that_needs_private_access_carries_the_private_guard(wf, name, job, doc):
    if _guarded(job.get("if")):
        return  # private-only: skipped in every other repository
    fork_reachable = bool(_triggers(doc) & FORK_REACHABLE)
    allowed = ALLOWED_UNGUARDED_SECRETS.get((wf, name), set())
    steps = job.get("steps") or []
    bad = []
    for where, refs in _private_refs(job):
        if where != "job" and _guarded(steps[int(re.match(r"step (\d+)", where).group(1))].get("if")):
            continue  # a step-level guard covers a reference inside that step only
        for ref in sorted(refs):
            kind, _, val = ref.partition(":")
            if kind == "secret" and (val in allowed or not fork_reachable):
                continue  # tag/dispatch-only workflow, or the vetted CLA token
            bad.append(f"{where}: {ref}")
    assert not bad, (
        f"{wf}::{name} needs private access but is not guarded with `if: {PRIVATE_GUARD}`:\n  "
        + "\n  ".join(bad)
    )


# ---- (b) no runs-on can reach a self-hosted runner in the public repo ---------


def _runs_on_text(job: dict) -> str:
    ro = job.get("runs-on")
    return json.dumps(ro) if not isinstance(ro, str) else ro


@pytest.mark.parametrize("wf,name,job,doc", JOBS, ids=[_id(j) for j in JOBS])
def test_b_runs_on_cannot_resolve_to_self_hosted_in_the_public_repo(wf, name, job, doc):
    ro = job.get("runs-on")
    text = _runs_on_text(job)
    assert "self-hosted" not in text, f"{wf}::{name} runs in the public repo but is pinned self-hosted: {ro!r}"
    if "vars." not in text:
        return  # a literal hosted label
    expr = _strip_expr(text)
    alternatives = _split_top(expr, "||")
    head = _split_top(alternatives[0], "&&")[0]
    assert head == PRIVATE_GUARD, (
        f"{wf}::{name}: a runs-on that reads a variable must start with `{PRIVATE_GUARD} &&` so the "
        f"variable is ignored elsewhere, got: {expr}"
    )
    fallback = alternatives[-1]
    assert "vars." not in fallback and "fromJSON" not in fallback, (
        f"{wf}::{name}: the public fallback of runs-on must be a hosted literal, got: {fallback}"
    )
    assert "self-hosted" not in fallback


# ---- (c) the public repo has coverage for every language ----------------------


def _public_jobs():
    return [(wf, n, j) for wf, n, j, _ in JOBS if not _guarded(j.get("if"))]


def _job_text(job: dict) -> str:
    return json.dumps(job, default=str)


@pytest.mark.parametrize(
    "language,needle",
    [
        ("python", re.compile(r"pytest tests/")),
        ("rust gateway", re.compile(r"CARGO_DOCKER_CRATE=.{0,3}\$PWD/gateway-rust")),
        ("rust noo-cli", re.compile(r"CARGO_DOCKER_CRATE=.{0,3}\$PWD/noo-cli")),
        ("go", re.compile(r"go test \./\.\.\.")),
        ("ui", re.compile(r"npm (ci|test)")),
    ],
)
def test_c_the_public_repo_runs_a_job_for_each_language(language, needle):
    hits = [f"{wf}::{n}" for wf, n, j in _public_jobs() if wf == "ci.yml" and needle.search(_job_text(j))]
    assert hits, f"no job that runs in the public repository covers {language}"


def test_c_the_python_job_needs_no_token():
    """`test-core` is the only Python job: no secret, no minted token, and trellion is
    installed only when an anonymous `git ls-remote` can reach it."""
    ci = _load("ci.yml")["jobs"]
    job = ci["test-core"]
    assert not _guarded(job.get("if")), "test-core must run in the public repository"
    text = _job_text(job)
    assert "PAI_REPOS_PAT" not in text and "SIBLING_TOKEN" not in text and "sibling-token" not in text
    assert not MINT_RE.search(text)
    assert not _refs(job), _refs(job)
    steps = job["steps"]
    probe = [s for s in steps if s.get("id") == "trellion"]
    assert len(probe) == 1 and "git ls-remote" in probe[0]["run"] and "token" not in probe[0]["run"].lower().replace("no token", "")
    install = next(s for s in steps if s.get("name") == "Install dependencies")
    assert 'TRELLION_PUBLIC" = "true"' in install["run"], "the [trellion] install must be conditional on the probe"


def test_c_the_ignore_lists_name_real_tests_in_the_private_tree():
    if not SYNC.exists():
        return  # the public tree has neither the sync script nor private-only test files to compare
    cmd = "\n".join(s.get("run", "") for s in _load("ci.yml")["jobs"]["test-core"]["steps"])
    for path in re.findall(r"--(?:ignore|deselect)[= ]([^\s:]+\.py)", cmd):
        assert (REPO / path).exists(), f"test-core names {path}, which does not exist: drop the stale entry"


# ---- (d) fork code gets no secret or write token ------------------------------


def test_d_ci_never_uses_pull_request_target():
    assert "pull_request_target" not in _triggers(_load("ci.yml"))


@pytest.mark.parametrize("wf", [w for w in _shipped_workflow_names() if "pull_request_target" in _triggers(_load(w))])
def test_d_a_pull_request_target_workflow_checks_out_no_code(wf):
    doc = _load(wf)
    for name, job in (doc.get("jobs") or {}).items():
        assert _guarded(job.get("if"), PUBLIC_GUARD) or _guarded(job.get("if")), f"{wf}::{name} must be repository-guarded"
        assert "self-hosted" not in _runs_on_text(job)
        for step in job.get("steps") or []:
            assert "actions/checkout" not in str(step.get("uses", "")), (
                f"{wf}::{name} runs with the base repo's secrets on a fork-triggered event and must not check out code"
            )
        text = _job_text(job)
        assert "github.event.pull_request.head" not in text and "github.head_ref" not in text


def test_d_ci_grants_no_write_permission():
    for name, job in (_load("ci.yml").get("jobs") or {}).items():
        perms = job.get("permissions") or {}
        if isinstance(perms, dict):
            assert "write" not in set(perms.values()), f"ci.yml::{name} grants a write permission"
    top = _load("ci.yml").get("permissions") or {}
    if isinstance(top, dict):
        assert "write" not in set(top.values())


def test_d_the_leak_gate_is_skipped_not_failed_when_absent():
    """The sync aborts if a shipped file calls leak-check.sh unguarded."""
    steps = _load("ci.yml")["jobs"]["preflight"]["steps"]
    run = [s for s in steps if "leak-check.sh" in s.get("run", "")]
    assert len(run) == 1
    body = run[0]["run"]
    calls = [ln for ln in body.splitlines() if "leak-check.sh" in ln]
    assert all("[ -x scripts/leak-check.sh ]" in ln for ln in calls), calls
    assert "not present" in body and "SKIPPED, not failed" in body


# ---- (e) no workflow mints an app token --------------------------------------

MINT_RE = re.compile(r"create-github-app-token|PAI_CI_APP_(?:ID|KEY)")
PR_TRIGGERS = {"pull_request", "pull_request_target"}


def _all_mint_jobs():
    out = []
    for p in sorted(WORKFLOWS_DIR.glob("*.yml")) if WORKFLOWS_DIR.exists() else []:
        doc = _load(p.name)
        for name, job in (doc.get("jobs") or {}).items():
            if MINT_RE.search(json.dumps(job, default=str)):
                out.append((p.name, name, job, doc))
    return out


MINT_JOBS = _all_mint_jobs()


def test_e_no_job_mints_an_app_token():
    assert not [(w, n) for w, n, _, _ in MINT_JOBS], MINT_JOBS


# What the add-on repositories run now (their own stack-contract.yml / ci.yml) and what the
# public CI therefore must not carry.
MOVED_OUT_JOBS = ("sibling-overlay-parity", "sibling-intel-overlay-parity", "intel-graph-context", "test", "promotion-gate")
ADDON_NAMES = ("trellion-intel", "trellion-evolve", "trellion_intel")


def _workflow_texts():
    return {p.name: p.read_text() for p in sorted(WORKFLOWS_DIR.glob("*.yml"))} if WORKFLOWS_DIR.exists() else {}


@pytest.mark.parametrize("wf", sorted(_workflow_texts()))
def test_no_workflow_depends_on_the_private_switch_a_sibling_token_or_an_addon_repo(wf):
    """The private-only jobs moved into the add-on repositories. Nothing here may switch on a
    repository variable, read a stored sibling token, or name an add-on (comments included)."""
    text = _workflow_texts()[wf]
    for needle in ("PRIVATE_UPSTREAM", "PAI_REPOS_PAT", *ADDON_NAMES):
        assert needle not in text, f"{wf} mentions {needle!r}"
    for needle in ("PAI_CI_APP", "create-github-app-token", "personifai-ci-reader", "SIBLING_TOKEN"):
        assert needle not in text, f"{wf} mentions {needle!r}: no shipped workflow mints an app token (the siblings are public)"


def test_the_private_only_jobs_are_gone_from_ci():
    if not WORKFLOWS_DIR.exists():
        return
    jobs = _load("ci.yml")["jobs"]
    for name in MOVED_OUT_JOBS:
        assert name not in jobs, f"ci.yml::{name} moved out (add-on repos / the Python suite is test-core)"
    for name, job in jobs.items():
        for dep in [job.get("needs")] if isinstance(job.get("needs"), str) else (job.get("needs") or []):
            assert dep in jobs, f"ci.yml::{name} needs {dep}, which is not a job"
    for name in ("sqlx-drift", "build"):
        assert name in jobs
        assert "PRIVATE_UPSTREAM" not in json.dumps(jobs[name])
        assert "runs-on" in jobs[name] and _runs_on_text(jobs[name]) == "ubuntu-latest"


def test_the_image_builds_log_in_to_dhi_only_for_a_same_repo_run():
    """build and llamacpp-image run on GitHub-hosted runners and use the DHI org credentials only
    where a fork pull request cannot reach them."""
    if not WORKFLOWS_DIR.exists():
        return
    jobs = _load("ci.yml")["jobs"]
    same_repo = "github.event.pull_request.head.repo.full_name == github.repository"
    for name in ("build", "llamacpp-image"):
        job = jobs[name]
        assert _runs_on_text(job) == "ubuntu-latest"
        logins = [s for s in job["steps"] if "secrets.DHI_TOKEN" in json.dumps(s)]
        assert logins, f"ci.yml::{name} lost its DHI login"
        for s in logins:
            cond = str(s.get("if", "")) + str(job.get("if", ""))
            assert PRIVATE_GUARD in cond and same_repo in cond, f"ci.yml::{name}: DHI login without the same-repo guard"
    assert not _refs(jobs["build"]) - {"secret:DHI_USERNAME", "secret:DHI_TOKEN"}


def test_sqlx_drift_reads_trellion_anonymously_and_skips_cleanly():
    if not WORKFLOWS_DIR.exists():
        return
    job = _load("ci.yml")["jobs"]["sqlx-drift"]
    steps = job["steps"]
    probe = [s for s in steps if s.get("id") == "trellion"]
    assert len(probe) == 1 and "git ls-remote" in probe[0]["run"]
    gated = [s for s in steps if "steps.trellion.outputs.public == 'true'" in str(s.get("if", ""))]
    assert any(s.get("name") == "Install noomesh" for s in gated), "the install must wait for the probe"
    assert any("migration-replay-check.sh" in s.get("run", "") for s in gated), "the replay must wait for the probe"
    assert not _refs(job), _refs(job)


def test_e_the_public_required_checks_are_jobs_that_run_in_the_public_repo():
    """Required checks come from scripts/oss/apply-repo-rulesets.sh. A variable-gated job is skipped
    in the public repository, so requiring it there asserts a check nothing reports."""
    sh = REPO / "scripts" / "oss" / "apply-repo-rulesets.sh"
    if not sh.exists() or not WORKFLOWS_DIR.exists():
        return
    m = re.search(r"^checks=\(([^)]*)\)", sh.read_text(), re.M)
    assert m
    jobs = _load("ci.yml")["jobs"]
    for check in m.group(1).split():
        assert check in jobs, f"required check {check} is not a ci.yml job"
        assert "vars.PRIVATE_UPSTREAM" not in str(jobs[check].get("if"))


def _probe_steps():
    jobs = _load("ci.yml")["jobs"]
    return {n: next(s for s in jobs[n]["steps"] if s.get("id") == "trellion") for n in ("test-core", "sqlx-drift")}


def test_the_trellion_switch_is_one_declared_constant():
    """TRELLION_PUBLIC is a literal in the workflow (not a repo variable, not the network): the one
    line the cutover flips."""
    env = _load("ci.yml").get("env") or {}
    assert env.get("TRELLION_PUBLIC") in ("false", "true"), env
    text = (WORKFLOWS_DIR / "ci.yml").read_text()
    assert "vars.TRELLION_PUBLIC" not in text
    assert len(re.findall(r"^  TRELLION_PUBLIC:", text, re.M)) == 1


@pytest.mark.parametrize("job", ["test-core", "sqlx-drift"])
def test_once_the_switch_is_set_no_step_can_skip_on_probe_failure(job, tmp_path):
    """Run the real probe step with a git that always fails. Switch off: skips with public=false and
    never touches the network. Switch on: the step FAILS and never writes public=false."""
    run = _probe_steps()[job]["run"]
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "git").write_text("#!/bin/sh\necho called >> \"$GIT_CALLS\"\nexit 128\n")
    (fake / "git").chmod(0o755)

    def go(switch):
        out, calls = tmp_path / f"out-{switch}", tmp_path / f"calls-{switch}"
        env = {"PATH": f"{fake}:/usr/bin:/bin", "TRELLION_PUBLIC": switch, "GITHUB_OUTPUT": str(out), "GIT_CALLS": str(calls)}
        r = subprocess.run(["bash", "-c", run], env=env, capture_output=True, text=True)
        return r, (out.read_text() if out.exists() else ""), calls.exists()

    r, out, called = go("false")
    assert r.returncode == 0 and "public=false" in out and not called, "before the flip: a notice, no network"
    r, out, _ = go("true")
    assert r.returncode != 0 and "public=false" not in out and "public=true" not in out, "after the flip an unreachable trellion fails"


@pytest.mark.parametrize("job", ["test-core", "sqlx-drift"])
def test_nothing_else_decides_the_trellion_skip_from_the_network(job):
    text = json.dumps(_load("ci.yml")["jobs"][job], default=str)
    assert text.count("git ls-remote") == 1, "only the probe loop touches the network"


def test_hub_mirror_off_fails_loud_on_a_public_repository():
    """The bridge flag cannot become steady state: every job that pulls a Hub
    image through the mirror refuses to run with it set on the public repository."""
    jobs = _load("ci.yml")["jobs"]
    guarded = []
    for name, job in jobs.items():
        steps = job.get("steps", [])
        for i, s in enumerate(steps):
            if "HUB_MIRROR_OFF" in str(s.get("env", {})):
                prev = steps[i - 1]
                cond = str(prev.get("if", ""))
                assert "github.repository == 'noomesh/noomesh'" in cond and "HUB_MIRROR_OFF" in cond, name
                assert "exit 1" in prev["run"], name
                guarded.append(name)
    assert {"rust-gateway", "sqlx-drift", "noo-cli", "standalone-smoke", "build"} <= set(guarded), guarded


DEPENDABOT = REPO / ".github" / "dependabot.yml"


def test_every_dependabot_update_targets_dev():
    """Update PRs go where every PR goes: `dev`. Without a target-branch,
    Dependabot opens them against the default branch (main), which changes by
    promotion only."""
    doc = yaml.safe_load(DEPENDABOT.read_text())
    assert doc.get("version") == 2
    updates = doc.get("updates") or []
    assert updates, "dependabot.yml declares no update entries — the parse found nothing to check"
    off = [f"{u.get('package-ecosystem')} {u.get('directory')}: {u.get('target-branch')!r}"
           for u in updates if u.get("target-branch") != "dev"]
    assert not off, "update entries not targeting dev:\n" + "\n".join(off)
    ecosystems = {u.get("package-ecosystem") for u in updates}
    assert {"npm", "pip", "gomod", "cargo", "github-actions"} <= ecosystems, ecosystems


def test_every_dependabot_directory_holds_a_manifest():
    """A directory that names nothing is an entry that silently checks nothing."""
    manifests = {"npm": ["package.json"], "pip": ["pyproject.toml", "requirements.txt", "setup.py"],
                 "gomod": ["go.mod"], "cargo": ["Cargo.toml"]}
    for u in yaml.safe_load(DEPENDABOT.read_text())["updates"]:
        eco, d = u["package-ecosystem"], REPO / u["directory"].lstrip("/")
        if eco == "github-actions":
            assert (REPO / ".github" / "workflows").is_dir()
            continue
        assert any((d / m).is_file() for m in manifests[eco]), f"{eco} {u['directory']}: no manifest"


# ---- user-visible strings name only paths that exist (followup i16) ----------

_STRING_SCAN_SUFFIXES = {".rs", ".go", ".sh", ".py"}
_STRING_SCAN_SKIP = {"target", "node_modules", ".git", ".worktrees", "tests"}
_DOC_PATH = re.compile(r"(?<![\w/.-])(docs/[A-Za-z0-9_./-]*[A-Za-z0-9_-]\.md)\b")
# scripts/docs-check.py validates an optional internal/proposals/ directory and
# names it in its own errors; that check only runs where the directory exists.
_RECORDS_ALLOWED = {"scripts/docs-check.py"}
_REMOVED_RECORDS = re.compile(
    r"(?<![\w/.-])internal/(?:followups|compliance|proposals|plans)/[\w.-]+"
    r"|(?<![\w/.-])internal/[A-Z][A-Z0-9_]+\.md"
)


def _scan_files():
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in _STRING_SCAN_SKIP]
        for f in files:
            p = Path(root) / f
            if p.suffix in _STRING_SCAN_SUFFIXES:
                yield p


def test_user_visible_strings_name_only_existing_paths():
    """A string an operator can read must not point at a file that is absent.

    Comment-only lines are skipped (harmless); everything else, multi-line
    strings and shell heredocs included, is checked line by line: a `docs/*.md`
    reference must exist in the tree and a removed-records path (`internal/
    followups/...`, `internal/CLI_AUTH_PLAN.md`, ...) is never allowed.
    """
    bad = []
    for p in _scan_files():
        try:
            lines = p.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            if line.lstrip().startswith(("//", "#", "*", "///")):
                continue
            rel = p.relative_to(REPO)
            for m in _REMOVED_RECORDS.finditer(line):
                if str(rel) in _RECORDS_ALLOWED:
                    continue
                bad.append(f"{rel}:{n}: removed records path {m.group(0)}")
            for m in _DOC_PATH.finditer(line):
                if not (REPO / m.group(1)).exists():
                    bad.append(f"{rel}:{n}: {m.group(1)} does not exist")
    assert not bad, "user-visible strings point at missing paths:\n" + "\n".join(bad)


def test_path_guard_catches_a_removed_records_path():
    assert _REMOVED_RECORDS.search('println!("see internal/followups/78-x.md");')
    assert _REMOVED_RECORDS.search("see internal/CLI_AUTH_PLAN.md")
    assert not _REMOVED_RECORDS.search("node-agent-go/internal/docker/x.go")
