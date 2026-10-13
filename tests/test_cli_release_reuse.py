# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A final CLI release re-publishes the rc's gateway binaries only when it can prove them.

noo-cli-release.yml asks scripts/cli-release-reuse.py "re-publish the rc's
noo-gateway-<target>, or build?" A wrong "reuse" ships bytes built from a
tree nobody compared, or a binary that says it is an rc; a wrong "build"
costs ~20 minutes. So:

  * the decision compares TREES (final tag vs the NEWEST rc tag), and needs
    the rc's own release run to have succeeded with every asset present;
  * only tag-neutral binaries are reusable: the CLI and the Go agents stamp
    the tag and always build, and nothing may start feeding the tag into the
    gateway build unnoticed;
  * the bytes must match the rc's .sha256 AND its manifest row, and the rc
    manifest's signature must verify before anything is published;
  * CLI_RETAG=off builds everything.
"""
from __future__ import annotations

import hashlib
import importlib.util
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WF_PATH = ROOT / ".github/workflows/noo-cli-release.yml"


def _load():
    spec = importlib.util.spec_from_file_location("cli_release_reuse", ROOT / "scripts/cli-release-reuse.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P = _load()
WF = yaml.safe_load(WF_PATH.read_text())
JOBS = WF["jobs"]

FINAL = "noo-cli-v1.2.3"
RC1, RC2 = f"{FINAL}-rc.1", f"{FINAL}-rc.2"


def _api(run=None, assets=None, draft=False, runs=None):
    run = run or {"id": 7, "head_branch": RC2, "head_sha": "C-" + RC2, "status": "completed",
                  "conclusion": "success", "created_at": "2026-10-10T00:00:00Z", "run_number": 3}
    names = P.required_assets() if assets is None else assets

    def api(path, token):
        if "/actions/workflows/" in path:
            return {"workflow_runs": runs if runs is not None else [run]}
        if "/releases/tags/" in path:
            return {"draft": draft, "assets": [{"name": n, "state": "uploaded"} for n in names]}
        raise AssertionError(path)
    return api


def _plan(tag=FINAL, trees=None, rcs=(RC2, RC1), api=None):
    trees = trees or {FINAL: "T", RC2: "T", RC1: "T"}
    return P.plan(tag, "o/r", "t", tree_of=lambda ref: trees[ref], commit_of=lambda ref: "C-" + ref,
                  list_rcs=lambda final: list(rcs), api=api or _api())


# ── the plan decision ────────────────────────────────────────────────────

def test_equal_tree_and_a_green_rc_reuse_the_newest_rc():
    p = _plan()
    assert p["reuse"] is True and p["rc_tag"] == RC2, p["why"]


def test_an_rc_tag_and_a_dispatch_always_build():
    for tag in (RC2, "dev", "noo-cli-v1.2", "stack-v1.2.3"):
        p = _plan(tag=tag)
        assert p["reuse"] is False and "not a final" in p["why"], (tag, p)


def test_no_rc_builds():
    p = _plan(rcs=())
    assert p["reuse"] is False and "no " in p["why"]


def test_a_tree_that_differs_from_the_newest_rc_builds_even_if_an_older_rc_matches():
    """The final is promoted from the NEWEST rc; an older equal-tree rc was
    not what was tested last, so it is never the source."""
    p = _plan(trees={FINAL: "T", RC2: "T-hotfix", RC1: "T"})
    assert p["reuse"] is False and RC2 in p["why"] and "tree" in p["why"]


def test_the_rcs_run_must_have_succeeded():
    for status, concl in (("completed", "failure"), ("in_progress", None), ("completed", "cancelled")):
        run = {"id": 1, "head_branch": RC2, "head_sha": "C-" + RC2, "status": status, "conclusion": concl,
               "created_at": "2026-10-10T00:00:00Z", "run_number": 1}
        p = _plan(api=_api(run=run))
        assert p["reuse"] is False, (status, concl, p)


def test_the_newest_rc_run_decides_not_an_older_green_one():
    old = {"id": 1, "head_branch": RC2, "head_sha": "C-" + RC2, "status": "completed",
           "conclusion": "success", "created_at": "2026-10-09T00:00:00Z", "run_number": 1}
    new = {**old, "id": 2, "conclusion": "failure", "created_at": "2026-10-10T00:00:00Z", "run_number": 2}
    assert _plan(api=_api(runs=[old, new]))["reuse"] is False
    assert _plan(api=_api(runs=[new, {**old, "head_branch": "other"}]))["reuse"] is False


def test_no_run_or_a_run_of_another_commit_builds():
    assert _plan(api=_api(runs=[]))["reuse"] is False
    run = {"id": 1, "head_branch": RC2, "head_sha": "C-elsewhere", "status": "completed",
           "conclusion": "success", "created_at": "x", "run_number": 1}
    assert _plan(api=_api(run=run))["reuse"] is False


@pytest.mark.parametrize("drop", ["noo-gateway-x86_64-unknown-linux-musl",
                                  "noo-gateway-aarch64-apple-darwin.sha256",
                                  "sha256sums.txt", "sha256sums.txt.sig"])
def test_a_missing_rc_asset_builds(drop):
    p = _plan(api=_api(assets=[n for n in P.required_assets() if n != drop]))
    assert p["reuse"] is False and drop in p["why"]


def test_a_draft_rc_release_builds():
    assert _plan(api=_api(draft=True))["reuse"] is False


def test_the_kill_switch_builds(monkeypatch):
    monkeypatch.setenv("CLI_RETAG", "off")
    p = _plan()
    assert p["reuse"] is False and "CLI_RETAG=off" in p["why"]
    monkeypatch.setenv("CLI_RETAG", "OFF ")
    assert _plan()["reuse"] is False
    monkeypatch.delenv("CLI_RETAG")
    assert _plan()["reuse"] is True, "the same fixture must reuse with the switch unset"


def test_a_planning_exception_answers_build(monkeypatch, tmp_path, capsys):
    out = tmp_path / "out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

    def boom(*a, **k):
        raise RuntimeError("api down")
    monkeypatch.setattr(P, "plan", boom)
    assert P.main(["plan", "--tag", FINAL, "--repo", "o/r"]) == 0
    assert "reuse=false" in out.read_text()
    assert "FULL BUILD" in capsys.readouterr().out


def test_rc_tags_sort_numerically(monkeypatch):
    monkeypatch.setattr(P, "git", lambda *a: f"{FINAL}-rc.2\n{FINAL}-rc.10\n{FINAL}-rc.1\n{FINAL}-rc.3x")
    assert P.rc_tags(FINAL) == [f"{FINAL}-rc.10", f"{FINAL}-rc.2", f"{FINAL}-rc.1"]


def test_tree_equality_is_read_from_git_tags(tmp_path, monkeypatch):
    """The real tree_of/rc_tags on a real repo: a final on a different commit
    with the same tree reuses; one more file does not."""
    def g(*a):
        return subprocess.run(["git", *a], cwd=tmp_path, check=True, capture_output=True, text=True).stdout.strip()
    g("init", "-q")
    g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "base")
    (tmp_path / "f").write_text("x")
    g("add", "f")
    g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "staging")
    g("tag", RC1)
    g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "main merge")
    g("tag", FINAL)
    monkeypatch.chdir(tmp_path)
    p = P.plan(FINAL, "o/r", "t", api=_api(run={"id": 1, "head_branch": RC1, "head_sha": g("rev-parse", RC1),
                                                  "status": "completed", "conclusion": "success",
                                                  "created_at": "x", "run_number": 1}))
    assert p["reuse"] is True and p["rc_tag"] == RC1, p["why"]
    (tmp_path / "g").write_text("y")
    g("add", "g")
    g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "drift")
    g("tag", "-f", FINAL)
    assert P.plan(FINAL, "o/r", "t", api=_api())["reuse"] is False


# ── fetch: the bytes must match the rc's two digests ─────────────────────

NAME = "noo-gateway-x86_64-unknown-linux-musl"


def _assets(blob=b"ELF", side=None, row=None):
    d = hashlib.sha256(blob).hexdigest()
    return {NAME: blob,
            f"{NAME}.sha256": f"{side or d}  {NAME}\n".encode(),
            "sha256sums.txt": f"{'0' * 64}  noo-x86_64-unknown-linux-gnu\n{row or d}  {NAME}\n".encode()}


def test_fetch_publishes_matching_bytes(tmp_path):
    d = P.fetch("o/r", RC1, NAME, tmp_path / "dist", "t", get=_assets().__getitem__)
    assert (tmp_path / "dist" / NAME).read_bytes() == b"ELF"
    assert d == hashlib.sha256(b"ELF").hexdigest()


@pytest.mark.parametrize("kw", [{"side": "f" * 64}, {"row": "e" * 64}])
def test_fetch_refuses_a_digest_disagreement(tmp_path, kw):
    with pytest.raises(ValueError):
        P.fetch("o/r", RC1, NAME, tmp_path / "dist", "t", get=_assets(**kw).__getitem__)
    assert not (tmp_path / "dist" / NAME).exists(), "nothing may land in dist/ unproven"


def test_fetch_refuses_a_manifest_without_the_row(tmp_path):
    a = _assets()
    a["sha256sums.txt"] = b"abc  something-else\n"
    with pytest.raises(ValueError):
        P.fetch("o/r", RC1, NAME, tmp_path / "dist", "t", get=a.__getitem__)


def test_a_failed_fetch_exits_nonzero_so_the_lane_builds(monkeypatch, tmp_path):
    out = tmp_path / "out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))

    def boom(*a, **k):
        raise LookupError("gone")
    monkeypatch.setattr(P, "fetch", boom)
    assert P.main(["fetch", "--rc-tag", RC1, "--asset", NAME, "--repo", "o/r"]) == 1
    assert not out.exists() or "reused=true" not in out.read_text()


# ── verify: the rc manifest's signature, then reused vs rebuilt ──────────

def _verify(tmp_path, rc_text, sig_ok=True, local=b"ELF"):
    dist = tmp_path / "dist"
    dist.mkdir()
    for n in P.REUSABLE:
        (dist / n).write_bytes(local if n == NAME else b"other")
    calls = []

    def run(argv, **k):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0 if sig_ok else 1, "", "" if sig_ok else "bad sig")
    files = {"sha256sums.txt": rc_text.encode(), "sha256sums.txt.sig": b"noo-sig1.x"}
    res = P.verify(RC1, dist, "./noo", files.__getitem__, run=run)
    assert calls and calls[0][1:3] == ["security", "release-verify"]
    return res


def test_verify_reports_reused_and_rebuilt(tmp_path):
    rows = f"{hashlib.sha256(b'ELF').hexdigest()}  {NAME}\n"
    reused, rebuilt = _verify(tmp_path, rows)
    assert reused == [NAME] and set(rebuilt) == set(P.REUSABLE) - {NAME}


def test_verify_fails_on_a_bad_signature(tmp_path):
    with pytest.raises(ValueError):
        _verify(tmp_path, "x  y\n", sig_ok=False)


# ── what may be reused: the workflow and the binaries' inputs ────────────

def _steps(job):
    return JOBS[job]["steps"]


def test_reusable_assets_are_exactly_the_gateway_matrix():
    targets = [m["target"] for m in JOBS["gateway"]["strategy"]["matrix"]["include"]]
    assert set(P.REUSABLE) == {f"noo-gateway-{t}" for t in targets}


def test_only_the_gateway_job_reuses_and_the_stamped_jobs_always_build():
    for name, job in JOBS.items():
        text = yaml.safe_dump(job)
        if name in ("gateway", "release", "reuse-plan"):
            continue
        assert "cli-release-reuse" not in text and "REUSE" not in text, f"{name} must always build"
    assert set(P.TAG_STAMPED) <= set(JOBS)


def test_the_gateway_build_takes_no_tag_input():
    """Reuse is sound only while the gateway bits do not depend on the tag.
    No gateway step may hand the tag, ref, commit or paired stack tag to the
    build, and the crate may not read one at build time."""
    for s in _steps("gateway"):
        if s.get("id") == "reuse":
            continue
        blob = yaml.safe_dump({k: v for k, v in s.items() if k != "name"})
        assert not re.search(r"GITHUB_REF|github\.ref|GITHUB_SHA|github\.sha|NOO_STACK_TAG|RC_TAG", blob), s.get("name")
    build_rs = (ROOT / "gateway-rust/build.rs").read_text()
    assert "rustc-env" not in build_rs, "gateway-rust/build.rs now stamps something into the binary"
    offenders = []
    for f in (ROOT / "gateway-rust/src").rglob("*.rs"):
        for m in re.finditer(r"\b(option_env|env)!\(\s*\"([A-Z0-9_]+)\"", f.read_text()):
            if not m.group(2).startswith("CARGO_"):
                offenders.append(f"{f.relative_to(ROOT)}: {m.group(0)}")
    assert not offenders, offenders


def test_the_stamped_jobs_really_stamp():
    """If these stop stamping, they could be reused too; if this test is
    stale the TAG_STAMPED reasons are wrong."""
    build = yaml.safe_dump(JOBS["build"])
    assert "NOO_STACK_TAG" in build and "stamped noo-cli" in build
    assert "git describe --tags" in (ROOT / "node-agent-go/build-cross.sh").read_text()


def test_gateway_lane_reuses_xor_builds_and_falls_back():
    steps = _steps("gateway")
    assert "reuse-plan" in JOBS["gateway"]["needs"]
    reuse = next(s for s in steps if s.get("id") == "reuse")
    assert reuse["if"] == "env.REUSE == 'true'"
    assert reuse.get("continue-on-error") is True, "a failed fetch must fall back to building"
    assert "cli-release-reuse.py fetch" in reuse["run"]
    names = [s.get("name", "") for s in steps]
    assert names.index(reuse["name"]) < names.index("Build (${{ matrix.kind }})")
    for s in steps:
        if s.get("name", "").startswith(("Build", "Cache cargo")):
            assert s["if"] == "steps.reuse.outputs.reused != 'true'", s["name"]
    for n in ("Verify artifact", "Upload artifact"):
        assert "if" not in next(s for s in steps if s.get("name") == n), f"{n} must run on both paths"


def test_the_plan_job_reads_the_kill_switch_and_can_see_runs():
    job = JOBS["reuse-plan"]
    plan = next(s for s in job["steps"] if s.get("id") == "plan")
    assert "vars.CLI_RETAG" in str(plan["env"])
    assert "cli-release-reuse.py plan" in plan["run"]
    assert job["permissions"].get("actions") == "read"
    assert job["steps"][0]["with"]["fetch-depth"] == 0, "tag trees need the history"


def test_release_verifies_reused_bytes_before_signing_and_publishing():
    steps = _steps("release")
    names = [s.get("name", "") for s in steps]
    v = next(s for s in steps if s.get("id") == "reuse")
    assert v["if"] == "env.REUSE == 'true'" and "continue-on-error" not in v
    assert "cli-release-reuse.py verify" in v["run"] and "--noo dist/noo-x86_64-unknown-linux-gnu" in v["run"]
    sign = next(i for i, n in enumerate(names) if n.startswith("Sign the checksum manifest"))
    create = names.index("Create GitHub Release")
    assert names.index(v["name"]) < sign < create
    assert "reuse-plan" in JOBS["release"]["needs"]
    assert "steps.reuse.outputs.note" in str(steps[create]["env"])


def test_release_checks_the_cli_version_against_the_tag():
    smoke = next(s for s in _steps("release") if s.get("name") == "Smoke + bundle export")
    assert '"$b" --version' in smoke["run"] and 'want="${GITHUB_REF_NAME#noo-cli-v}"' in smoke["run"]
    script = re.search(r"case \"\$\{GITHUB_REF_NAME\}\" in noo-cli-v\*\)\n(.*?)esac", smoke["run"], re.S).group(1)

    def run(ref, version_line):
        fake = f"#!/bin/sh\necho '{version_line}'\n"
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            for b in ("noo-x86_64-unknown-linux-musl", "noo-x86_64-unknown-linux-gnu"):
                p = Path(d) / b
                p.write_text(fake)
                p.chmod(0o755)
            return subprocess.run(["bash", "-c", f'set -eu\ncase "${{GITHUB_REF_NAME}}" in noo-cli-v*)\n{script}esac'],
                                  cwd=d, env={"PATH": "/usr/bin:/bin", "GITHUB_REF_NAME": ref},
                                  capture_output=True, text=True).returncode

    assert run("noo-cli-v1.2.3", "noo (noomesh CLI, alias: pai) 1.2.3") == 0
    assert run("noo-cli-v1.2.3", "noo (noomesh CLI, alias: pai) 1.2.3-rc.1") != 0
    assert run("noo-cli-v1.2.3-rc.1", "noo (noomesh CLI, alias: pai) 1.2.3-rc.1") == 0
    assert run("noo-cli-v1.2.3-rc.2", "noo (noomesh CLI, alias: pai) 1.2.3-rc.1") != 0


def test_the_published_asset_list_is_unchanged():
    """Reuse changes where three binaries come from, never what is published:
    the same 29 assets, the same manifest and signature."""
    create = next(s for s in _steps("release") if s.get("name") == "Create GitHub Release")
    assets = re.findall(r"dist/(\S+)", create["run"].split("gh release create", 1)[1])
    assert len(assets) == 29, assets
    for n in P.REUSABLE:
        assert n in assets and f"{n}.sha256" in assets
    assert "sha256sums.txt" in assets and "sha256sums.txt.sig" in assets


def test_the_script_names_only_public_orgs():
    """noo-cli-release.yml ships to the OSS repo, and this script with it:
    every github.com/<org>/ it names is one of the public orgs."""
    text = (ROOT / "scripts/cli-release-reuse.py").read_text()
    orgs = set(re.findall(r"(?<![\w.])github\.com/([\w.-]+)/", text))
    assert orgs <= {"noomesh", "personifAI"}, orgs
