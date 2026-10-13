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
import sys
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
    """The stack release is core-only: no add-on job,
    no add-on repo name, no add-on image, and the app token reads only the open
    library. The add-ons release from their own repos with their own lock."""
    if not (WORKFLOWS_DIR / "images-release.yml").exists():
        pytest.skip("images-release.yml not present")
    doc = _load("images-release.yml")
    assert set(doc["jobs"]) == {"release-line", "static-ffmpeg", "deps-core", "deps-base", "images", "lock"}, sorted(doc["jobs"])
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


GATES_PY = REPO / "scripts" / "snapshot_gates.py"
if GATES_PY.exists():  # absent from the public tree: the rule lives in the snapshot tooling
    import importlib.util

    _spec = importlib.util.spec_from_file_location("snapshot_gates", GATES_PY)
    GATES = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(GATES)  # type: ignore[union-attr]
else:
    GATES = None

needs_gates = pytest.mark.skipif(GATES is None, reason="scripts/snapshot_gates.py (the one implementation of the rule) is not in this tree")


def _reads_private_source(job: dict) -> bool:
    """A secret other than GITHUB_TOKEN, PAI_REPOS_PAT, the app mint, a non-self checkout, a self-hosted
    runner or vars.CI_RUNNER (the shared rule, scripts/snapshot_gates.py::wf_reaches)."""
    return bool(GATES.wf_reaches(job))


def _snapshot_allow(tmp_path) -> "Path":
    """The reviewed exceptions, read from snapshot.sh's own noomesh-pv configuration."""
    snap = REPO / "scripts" / "snapshot.sh"
    out = subprocess.run(["bash", "-c", f'source "{snap}"; snap_config noomesh-pv; printf "%s\\n" "${{SNAP_WORKFLOWS_ALLOW[@]}}"'],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    allow = tmp_path / "workflows.allow"
    allow.write_text(out.stdout)
    # Five waivers remain (CLA bot, the DHI-using ci.yml jobs, the release base images, the mirrors, the darwin agents),
    # two separators each: fewer means the parse found nothing and the checks below would pass on an empty list.
    assert allow.read_text().count("::") >= 10, "could not read SNAP_WORKFLOWS_ALLOW from snapshot.sh"
    return allow


@needs_gates
def test_e_the_shipped_workflows_obey_the_rule_the_snapshot_gate_enforces(tmp_path):
    """The same function the `workflow-guards` snapshot gate runs on the staged tree, run here on the
    source tree (plus the private-only gateway-image.yml). The exceptions are the reviewed list in
    scripts/snapshot.sh; every entry must still match something (no stale waivers)."""
    allow = GATES.load_allow(str(_snapshot_allow(tmp_path)))
    left = GATES.wf_scan(WORKFLOWS_DIR, allow)
    assert not left, "\n".join(f"{r}: {j}: {e}" for r, j, e in left)
    used = {i for i, (pr, lr, _) in enumerate(allow)
            for r, j, e in GATES.wf_scan(WORKFLOWS_DIR, []) if pr.search(r) and lr.search(f"{j}: {e}")}
    assert used == set(range(len(allow))), "a SNAP_WORKFLOWS_ALLOW entry matches nothing: drop it"


def _job(**kw):
    return {"runs-on": "ubuntu-latest", "steps": [{"run": "true"}], **kw}


@needs_gates
def test_the_rule_negative_controls():
    pr = {"on": {"pull_request": {}}}
    tag = {"on": {"push": {"tags": ["v*"]}}}
    canon = "github.repository == 'noomesh/noomesh'"

    def bad(job, doc=pr):
        return bool(GATES.wf_job_violations("w.yml", "j", job, doc))

    secret = _job(steps=[{"env": {"T": "${{ secrets.SOME_TOKEN }}"}}])
    assert bad({**secret, "if": canon}), "an ungated job naming a secret must fail"
    assert bad(secret)
    assert bad(_job(**{"runs-on": ["self-hosted", "linux"]})), "a self-hosted runner must fail"
    assert bad(_job(**{"runs-on": "${{ fromJSON(vars.CI_RUNNER || '\"ubuntu-latest\"') }}"}))
    assert bad(_job(steps=[{"env": {"PAI_REPOS_PAT": "x"}}]))
    assert bad(_job(steps=[{"uses": "actions/create-github-app-token@x"}]))
    assert bad(_job(steps=[{"uses": "actions/checkout@x", "with": {"repository": "somebody/else"}}]))
    # the org rewrite turned a private literal into the public repo name: that guard is TRUE publicly
    assert bad({**secret, "if": "${{ github.repository == 'noomesh/noomesh' && !cancelled() }}"})
    # no repository variable exempts a job any more
    assert bad({**secret, "if": "vars.PRIVATE_UPSTREAM == 'true'"}), "a variable gate is no exemption"
    assert bad({**secret, "if": "${{ vars.PRIVATE_UPSTREAM == 'true' && !cancelled() }}"})
    # a tag-only release-environment job passes; the same on a fork-reachable trigger does not
    assert not bad({**secret, "environment": "release"}, tag)
    assert bad({**secret, "environment": "release"}, pr)
    # GITHUB_TOKEN and a core job are fine
    assert not bad(_job(steps=[{"env": {"T": "${{ secrets.GITHUB_TOKEN }}"}}]))
    assert not bad(_job())


@needs_gates
def test_the_allow_list_waives_exact_occurrences_only(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "cla.yml").write_text("on: {pull_request_target: {}}\njobs:\n  cla:\n    runs-on: ubuntu-latest\n    steps:\n    - env: {T: '${{ secrets.CLA_PAT }}'}\n")
    allow = tmp_path / "a"
    allow.write_text("\\.github/workflows/cla\\.yml$ :: ^cla: names secrets\\.CLA_PAT; :: the CLA bot\n")
    assert GATES.wf_scan(wf, GATES.load_allow(str(allow))) == []
    assert GATES.wf_scan(wf, []), "without the entry the CLA job fails"
    # a second secret in the same job changes the evidence and is NOT waived
    (wf / "cla.yml").write_text((wf / "cla.yml").read_text() + "    - env: {U: '${{ secrets.OTHER }}'}\n")
    assert GATES.wf_scan(wf, GATES.load_allow(str(allow)))


@needs_gates
def test_the_workflow_guards_gate_runs_on_the_staged_tree(tmp_path):
    """Run the real sync (org rewrite included) into a temp repo and hold the STAGED workflows to the
    rule, with the reviewed allow list from snapshot.sh: a rewrite that flips a guard cannot pass."""
    sync = REPO / "scripts" / "sync-to-oss.sh"
    snap = REPO / "scripts" / "snapshot.sh"
    if not sync.exists() or not snap.exists():
        pytest.skip("sync or snapshot script not present")
    target = tmp_path / "pub"
    subprocess.run(["git", "init", "-q", str(target)], check=True)
    env = {**os.environ, "NOO_SYNC_SKIP_BUILD": "1"}
    env.pop("OSS_ORG_STRICT", None)
    r = subprocess.run(["bash", str(sync), "--yes", str(target)], stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, f"the sync itself failed:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}"
    assert list((target / ".github" / "workflows").glob("*.yml")), "the parse found no staged workflows"
    allow = _snapshot_allow(tmp_path)
    g = subprocess.run([sys.executable, str(GATES_PY), "workflows", "--tree", str(target), "--allow", str(allow)],
                       capture_output=True, text=True)
    assert g.returncode == 0, g.stdout + g.stderr
    # negative control on the real staged tree: a job pinned to a self-hosted runner is caught
    ci = target / ".github" / "workflows" / "ci.yml"
    ci.write_text(ci.read_text().replace("runs-on: ubuntu-latest", "runs-on: [self-hosted, linux]", 1))
    g = subprocess.run([sys.executable, str(GATES_PY), "workflows", "--tree", str(target), "--allow", str(allow)],
                       capture_output=True, text=True)
    assert g.returncode == 1 and "ci.yml" in g.stdout, g.stdout + g.stderr


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


def test_e2_every_release_matrix_dockerfile_exists_in_the_public_tree(tmp_path):
    """The release builds from the PUBLIC tree. Sync into a temp git repo
    (non-strict, build check skipped) and require every Dockerfile the images
    matrix names to be there: a Dockerfile left under an excluded path would
    pass in the private tree and break the first public release."""
    sync = REPO / "scripts" / "sync-to-oss.sh"
    if not sync.exists() or not (WORKFLOWS_DIR / "images-release.yml").exists():
        pytest.skip("sync script or release workflow not present")
    include = _load("images-release.yml")["jobs"]["images"]["strategy"]["matrix"]["include"]
    named = {m["name"]: m["dockerfile"] for m in include}
    assert named, "the parse found no matrix entries"
    target = tmp_path / "pub"
    subprocess.run(["git", "init", "-q", str(target)], check=True)
    env = {**os.environ, "NOO_SYNC_SKIP_BUILD": "1"}
    env.pop("OSS_ORG_STRICT", None)
    r = subprocess.run(["bash", str(sync), "--yes", str(target)], stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, f"the sync itself failed:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}"
    missing = {n: d for n, d in named.items() if not (target / d).is_file()}
    assert not missing, f"matrix Dockerfiles absent from the synced public tree: {missing}"


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
