# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CI on the public repository is GitHub-hosted only, and the supply chain of
the workflows that hold secrets is pinned.

By design, once the repo is public, a pull request from a
fork must never reach maintainer hardware, and outside contributors need a
founder's approval. These pin the SHAPE in the workflow files; the review
ruleset, the fork-approval policy and the runner list live in repo/org settings
and are applied by scripts/oss/apply-repo-rulesets.sh.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WF_DIR = ROOT / ".github/workflows"
# Private-only workflows (never synced to the public tree). None today: the
# add-on image builds live in the add-on repos.
PRIVATE_ONLY: set[str] = set()
WORKFLOWS = sorted(p for p in WF_DIR.glob("*.yml") if p.name not in PRIVATE_ONLY)
SHA = re.compile(r"^[0-9a-f]{40}$")


def _doc(p: Path) -> dict:
    return yaml.safe_load(p.read_text())


def _triggers(doc: dict) -> dict:
    # PyYAML reads a bare `on:` key as the boolean True (YAML 1.1).
    t = doc.get("on") or doc.get(True) or {}
    return t if isinstance(t, dict) else {k: None for k in (t if isinstance(t, list) else [t])}


def test_the_parse_found_the_workflows():
    names = {p.name for p in WORKFLOWS}
    assert {"ci.yml", "images-release.yml", "noo-cli-release.yml", "cla.yml"} <= names, names


def test_no_workflow_mentions_self_hosted_runners():
    """Not a runs-on label, not a CI_RUNNER switch, not an approval environment
    for a box: none of it exists any more, and a comment that names it is how it
    comes back."""
    bad = []
    for p in WORKFLOWS:
        for i, ln in enumerate(p.read_text().splitlines(), 1):
            if re.search(r"self-hosted|CI_RUNNER|selfhosted", ln, re.I):
                bad.append(f"{p.name}:{i}: {ln.strip()[:90]}")
    assert not bad, "\n".join(bad)


def test_every_job_runs_on_a_github_hosted_image():
    hosted = re.compile(r"^(ubuntu-(latest|2\d\.04)(-arm)?|macos-\d+|windows-latest)$")
    bad = []
    for p in WORKFLOWS:
        for name, job in (_doc(p).get("jobs") or {}).items():
            ro = job.get("runs-on")
            if isinstance(ro, str) and "${{" in ro:
                # an expression is fine only if every quoted literal in it is hosted
                # drop `== 'x'` comparisons (matrix kinds), keep the values the expression can yield
                lits = re.findall(r"'([^']+)'", re.sub(r"==\s*'[^']*'", "", ro))
                ok = bool(lits) and all(hosted.match(x) for x in lits) and "vars." not in ro
            else:
                ok = isinstance(ro, str) and bool(hosted.match(ro))
            if not ok:
                bad.append(f"{p.name}:{name}: {ro!r}")
    assert not bad, "\n".join(bad)


def test_every_action_is_pinned_by_sha():
    bad = []
    for p in WORKFLOWS:
        for ln_no, ln in enumerate(p.read_text().splitlines(), 1):
            m = re.match(r"\s*(?:-\s*)?uses:\s*([^\s#]+)", ln)
            if not m or m.group(1).startswith("./"):
                continue
            ref = m.group(1).rpartition("@")[2]
            if not SHA.match(ref):
                bad.append(f"{p.name}:{ln_no}: {m.group(1)}")
    assert not bad, "actions pinned by tag/branch (a moved tag runs new code with our secrets):\n" + "\n".join(bad)


def _pr_target_workflows():
    return [p for p in WORKFLOWS if "pull_request_target" in _triggers(_doc(p))]


def test_there_is_a_pull_request_target_workflow_to_check():
    assert [p.name for p in _pr_target_workflows()] == ["cla.yml"]


def test_every_pull_request_target_workflow_is_fork_guarded_and_never_checks_out_code():
    for p in _pr_target_workflows():
        doc = _doc(p)
        for name, job in doc["jobs"].items():
            assert "github.repository ==" in str(job.get("if", "")), f"{p.name}:{name} lacks the fork guard"
            for step in job.get("steps") or []:
                uses = str(step.get("uses", ""))
                assert not uses.startswith("actions/checkout"), (
                    f"{p.name}:{name} checks out code in a pull_request_target job: it runs with "
                    "secrets and a write token, and the checkout would be the fork's"
                )
                assert "head.sha" not in str(step) and "head.ref" not in str(step), f"{p.name}:{name} reads the PR head"


# (The CLA workflow's own shape is pinned by tests/test_cla_workflow_declarations.py.)


def test_codeowners_names_at_least_two_owners():
    co = (ROOT / ".github/CODEOWNERS").read_text()
    rules = [ln.split() for ln in co.splitlines() if ln.strip() and not ln.startswith("#")]
    assert rules and rules[0][0] == "*", rules
    assert len(rules[0][1:]) >= 2 and all(o.startswith("@") for o in rules[0][1:]), rules[0]


def test_the_ruleset_script_is_dry_run_by_default_and_covers_the_rules():
    """Mirrors the noomesh reference: the ORG rulesets already give main /
    staging / dev their PR-only shape, so the repo script adds only the CI gates
    and the outside-contributor review, both on dev."""
    script = ROOT / "scripts/oss/apply-repo-rulesets.sh"
    if not script.exists():
        return  # move-day tooling is not part of the public tree (no skip: the CI skip guard)
    sh = script.read_text()
    assert 'apply=0; [ "${2:-}" = "--apply" ] && apply=1' in sh
    for needle in ('"require_code_owner_review": true', '"dismiss_stale_reviews_on_push": true',
                   '"required_approving_review_count": 1', '"allowed_merge_methods": ["rebase"]',
                   '"actor_type": "Team", "bypass_mode": "pull_request"',
                   '"actor_type": "OrganizationAdmin", "bypass_mode": "always"',
                   '"type": "required_status_checks"',
                   "all_external_contributors", "fork-pr-contributor-approval", "maintainers"):
        assert needle in sh, needle
    # exactly two bypass actors, both on the review ruleset; the CI gates have none
    assert sh.count('"bypass_mode"') == 2
    assert '"bypass_actors": []' in sh
    # both rulesets target dev only; nothing is added on main or staging, and no
    # unverified RepositoryRole id is used
    assert sh.count('"include": ["refs/heads/dev"]') == 2
    assert "~DEFAULT_BRANCH" not in sh.split("set -euo pipefail", 1)[1]
    assert '"actor_type": "RepositoryRole"' not in sh
    # the required checks are real ci.yml jobs
    jobs = set(_doc(WF_DIR / "ci.yml")["jobs"])
    m = re.search(r"^checks=\(([^)]*)\)", sh, re.M)
    assert m
    missing = set(m.group(1).split()) - jobs
    assert not missing, f"required checks that are not ci.yml jobs: {sorted(missing)}"


# ---- sibling read access: none needed --------------------------------------------
# trellion and trellion-protocols are public: every checkout of them is anonymous.
# No shipped workflow mints an app token or names the retired credentials.

RETIRED = ("PAI_CI_APP", "personifai-ci-reader", "create-github-app-token", "PAI_REPOS_PAT", "SIBLING_TOKEN", "sibling-token")


def test_no_shipped_workflow_mints_an_app_token_or_names_a_retired_credential():
    for p in WORKFLOWS:
        text = p.read_text()
        for needle in RETIRED:
            assert needle not in text, f"{p.name} names {needle!r}: the siblings are public, no token is minted or passed"


def test_sibling_checkouts_are_anonymous():
    seen = 0
    for p in WORKFLOWS:
        for jid, job in (_doc(p).get("jobs") or {}).items():
            for step in job.get("steps") or []:
                w = step.get("with") or {}
                if "actions/checkout" in str(step.get("uses", "")) and w.get("repository") and "github.repository" not in str(w["repository"]):
                    seen += 1
                    assert "token" not in w, f"{p.name}:{jid} checks out {w['repository']} with a token"
    assert seen >= 2, f"expected the trellion and trellion-protocols checkouts; found {seen}"
