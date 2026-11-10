# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A final (or an rc re-cut on an earlier rc's tree) re-tags that rc's images
only when every input provably matches.

images-release.yml asks scripts/release-retag-plan.py, per image, "re-tag the
rc's digest, or build?" A wrong "re-tag" ships an image built from inputs
nobody compared; a wrong "build" costs minutes. So:

  * the decision compares TREES — this repo's final tag vs the rc tag, and
    each sibling's resolved SHA vs the source SHA the rc lock recorded;
  * an image that stamps the tag into its bits (gateway, node-agent) is
    always rebuilt, and no OTHER image may start stamping it unnoticed;
  * every image the workflow publishes has a plan entry;
  * the workflow wires it the way the plan assumes: re-tag XOR build per job,
    sibling checkouts by the SHA resolved once per run, and
    the signed lock still signed.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WF_PATH = ROOT / ".github/workflows/images-release.yml"


def _load():
    spec = importlib.util.spec_from_file_location("release_retag_plan", ROOT / "scripts/release-retag-plan.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P = _load()
WF = yaml.safe_load(WF_PATH.read_text())
MATRIX = WF["jobs"]["images"]["strategy"]["matrix"]["include"]

LOCK = """gateway@sha256:g
llamacpp@sha256:l
ollama@sha256:o
node-agent@sha256:n
nvidia-exporter@sha256:x
piper@sha256:p
postgres-pgvector@sha256:q
sandbox@sha256:s
source:trellion@TRE_RC
stunnel@sha256:t
trellion@sha256:r
whisper@sha256:w
worker@sha256:k
"""
SIB_TREES = {"TRE_RC": "T-tre", "TRE_MAIN": "T-tre", "TRE_MOVED": "T-tre-2"}
MAINS = {"trellion": "TRE_MAIN"}


def _plan(tag="stack-v1.2.3", trees=None, rcs=("stack-v1.2.3-rc.2", "stack-v1.2.3-rc.1"),
          sibs=None, lock=LOCK, bases=None, changed=None):
    trees = trees or {"stack-v1.2.3": "T", "stack-v1.2.3-rc.2": "T", "stack-v1.2.3-rc.1": "T"}
    return P.plan(tag, "o/r", sibs or MAINS, "t", "t", lock_text=lock, bases_text=bases,
                  tree_of=lambda ref: trees[ref], commit_of=lambda ref: "C-" + ref,
                  list_rcs=lambda final: list(rcs),
                  sib_tree=lambda repo, sha, tok: SIB_TREES[sha],
                  changed_of=lambda prev, new: changed)


def test_equal_trees_retag_everything_but_the_tag_stamped_images():
    p = _plan()
    assert p["rc_tag"] == "stack-v1.2.3-rc.2", "the highest equal-tree rc must win"
    built = {i for i, r in p["retag"].items() if not r}
    assert built == {"gateway", "node-agent"}, p["why"]
    assert p["rc_digests"]["whisper"] == "sha256:w"


def test_an_rc_on_a_new_tree_builds():
    p = _plan(tag="stack-v1.2.3-rc.3", trees={"stack-v1.2.3-rc.3": "T3", "stack-v1.2.3-rc.2": "T", "stack-v1.2.3-rc.1": "T"})
    assert not any(p["retag"].values()) and p["rc_tag"] == "", p["why"]
    assert "no earlier rc of stack-v1.2.3 has this tree" in p["why"]["whisper"]


def test_an_rc_recut_on_an_earlier_rcs_tree_retags_it():
    """2026-10-22: rc.N+1 on the commit rc.N built (an add-on-only or
    lane-only re-cut) re-tags rc.N's images; only the tag-stamped ones build."""
    trees = {"stack-v1.2.3-rc.3": "T", "stack-v1.2.3-rc.2": "T", "stack-v1.2.3-rc.1": "T0"}
    p = _plan(tag="stack-v1.2.3-rc.3", trees=trees)
    assert p["rc_tag"] == "stack-v1.2.3-rc.2", p["why"]
    assert {i for i, r in p["retag"].items() if not r} == {"gateway", "node-agent"}, p["why"]
    assert p["rc_digests"]["worker"] == "sha256:k"


def test_an_rc_never_retags_from_itself_or_a_later_rc():
    """A re-run of rc.2 must not re-tag from its own (maybe half-published)
    images, and rc.2 cannot take rc.3's."""
    trees = {"stack-v1.2.3-rc.2": "T", "stack-v1.2.3-rc.3": "T", "stack-v1.2.3-rc.1": "T0"}
    p = _plan(tag="stack-v1.2.3-rc.2", trees=trees, rcs=("stack-v1.2.3-rc.3", "stack-v1.2.3-rc.2", "stack-v1.2.3-rc.1"))
    assert p["rc_tag"] == "" and not any(p["retag"].values()), p["why"]
    assert P.candidates("stack-v1.2.3-rc.2", lambda v: ["stack-v1.2.3-rc.3", "stack-v1.2.3-rc.2", "stack-v1.2.3-rc.1"]) == ["stack-v1.2.3-rc.1"]
    assert P.candidates("stack-v1.2.3", lambda v: ["stack-v1.2.3-rc.2", "stack-v1.2.3-rc.1"]) == ["stack-v1.2.3-rc.2", "stack-v1.2.3-rc.1"]


def test_an_rc_recut_with_a_moved_sibling_rebuilds_what_it_feeds():
    trees = {"stack-v1.2.3-rc.3": "T", "stack-v1.2.3-rc.2": "T", "stack-v1.2.3-rc.1": "T"}
    p = _plan(tag="stack-v1.2.3-rc.3", trees=trees, sibs={**MAINS, "trellion": "TRE_MOVED"})
    assert {i for i, r in p["retag"].items() if not r} == {"gateway", "node-agent", "deps-base", "trellion"}, p["why"]


def test_no_equal_tree_rc_builds_everything():
    p = _plan(trees={"stack-v1.2.3": "T2", "stack-v1.2.3-rc.2": "T", "stack-v1.2.3-rc.1": "T"})
    assert not any(p["retag"].values()), p["why"]


def test_an_older_rc_with_the_equal_tree_is_used():
    p = _plan(trees={"stack-v1.2.3": "T", "stack-v1.2.3-rc.2": "T-hotfix", "stack-v1.2.3-rc.1": "T"})
    assert p["rc_tag"] == "stack-v1.2.3-rc.1" and p["retag"]["whisper"] is True


def test_a_moved_sibling_rebuilds_exactly_what_it_feeds():
    p = _plan(sibs={**MAINS, "trellion": "TRE_MOVED"})
    rebuilt = {i for i, r in p["retag"].items() if not r}
    assert rebuilt == {"gateway", "node-agent", "deps-base", "trellion"}, p["why"]
    assert "!=" in p["why"]["trellion"]


def test_a_sibling_with_no_resolved_sha_builds_what_it_feeds():
    p = _plan(sibs={"unrelated": "X"})
    assert p["retag"]["trellion"] is False and p["retag"]["whisper"] is True


def test_the_plan_knows_no_addon_image():
    p = _plan()
    assert "trellion-intel" not in p["retag"] and "evolve" not in p["retag"], sorted(p["retag"])


def test_an_image_missing_from_the_rc_lock_is_built():
    lock = "\n".join(ln for ln in LOCK.splitlines() if not ln.startswith("whisper@"))
    p = _plan(lock=lock)
    assert p["retag"]["whisper"] is False and p["retag"]["piper"] is True


def test_the_plan_covers_every_image_the_workflow_publishes():
    """An image missing here would get RETAG='' and build — safe — but the
    plan would no longer describe the release. Keep them equal."""
    published = {m["image"] for m in MATRIX} | {"deps-core", "deps-base"}
    assert set(P.SIBLING_INPUTS) == published, (
        f"plan: {sorted(P.SIBLING_INPUTS)} vs workflow: {sorted(published)}"
    )


def test_only_the_declared_images_stamp_the_tag():
    """Re-tagging is sound only for an image whose bits do not depend on the
    tag. A matrix entry that passes the tag, the ref name or the commit into
    its build must be listed as TAG_STAMPED (always rebuilt). References to
    our OWN bases by $TAG are fine: those bases are re-tagged together."""
    stamping = set()
    for m in MATRIX:
        args = re.sub(r"\$REGISTRY/\$(?:DHI_)?OWNER/(deps-core|deps-base):\$TAG", "", m.get("extra_args", ""))
        if re.search(r"\$TAG|github\.ref_name|github\.sha", args):
            stamping.add(m["image"])
    assert stamping == set(P.TAG_STAMPED), (
        f"images whose build reads the tag: {sorted(stamping)}; declared: {sorted(P.TAG_STAMPED)}"
    )


def _steps(job: str) -> list[dict]:
    return WF["jobs"][job]["steps"]


def test_every_build_job_retags_xor_builds():
    for job in ("deps-core", "deps-base", "images"):
        steps = _steps(job)
        build = [s for s in steps if str(s.get("name", "")).startswith("Build + push")]
        retag = [s for s in steps if str(s.get("name", "")).startswith("Re-tag")]
        assert len(build) == 1 and len(retag) == 1, f"{job}: {len(build)} build, {len(retag)} re-tag steps"
        assert "env.RETAG != 'true'" in build[0]["if"], f"{job} builds even when re-tagging"
        assert "env.RETAG == 'true'" in retag[0]["if"], f"{job} re-tags without a plan"
        assert "scripts/release-retag-image.sh" in retag[0]["run"]
        assert "fromJSON(needs.release-line.outputs.retag)" in str(WF["jobs"][job].get("env")), job
        assert "release-line" in WF["jobs"][job]["needs"], f"{job} cannot read the plan"


def test_lock_images_retag_against_the_rc_lock_digest():
    """Only deps-core/deps-base (not in the lock) may re-tag without the
    lock's digest to check the rc tag against."""
    for job in ("images",):
        retag = next(s for s in _steps(job) if str(s.get("name", "")).startswith("Re-tag"))
        assert '"$RC_DIGEST"' in retag["run"], job


def test_the_retag_script_proves_the_digest_survived():
    sh = (ROOT / "scripts/release-retag-image.sh").read_text()
    assert "imagetools create" in sh
    assert re.search(r'\[ "\$now" != "\$got" \]', sh), "no post-retag digest equality check"
    assert re.search(r'\[ "\$got" != "\$want" \]', sh), "no rc-tag-vs-lock digest check"


def test_siblings_resolve_once_and_jobs_check_out_the_sha():
    """an earlier change: a re-run must not build newer sibling code."""
    line = WF["jobs"]["release-line"]
    outs = line["outputs"]
    for k in ("trellion_sha",):
        assert k in outs, k
    for k in ("intel_sha", "evolve_sha"):
        assert k not in outs, k
    resolve = next(s for s in line["steps"] if s.get("id") == "siblings")
    assert 'scripts/sibling-refs.py resolve "$LINE"' in resolve["run"]
    # Inside the checkout, the GITHUB_TOKEN header actions/checkout persists
    # overrides the PAT in the URL and every private sibling is "not found"
    # (stack-v0.2.100-rc.1). The resolution must leave the workspace first
    # (the shared script runs ls-remote in a temp dir, extraheader cleared).
    script = (Path(__file__).resolve().parents[1] / "scripts/sibling-refs.py").read_text()
    assert '"ls-remote"' in script and "cwd=tmp" in script, "ls-remote must run outside the checkout"
    assert '"http.extraheader="' in script and '"http.https://github.com/.extraheader="' in script
    sibling_checkouts = []
    for name, job in WF["jobs"].items():
        for s in job.get("steps", []):
            repo = (s.get("with") or {}).get("repository", "")
            if repo.startswith("personifAI/trellion") and not repo.endswith("-protocols"):  # protocols is pinned by trellion, not release-line
                sibling_checkouts.append((name, repo, s["with"]["ref"]))
    # Only trellion (deps-base build): the stack release is core-only.
    assert len(sibling_checkouts) == 1, sibling_checkouts
    for name, repo, ref in sibling_checkouts:
        assert re.search(r"needs\.release-line\.outputs\.trellion_sha", ref), (
            f"{name} checks out {repo} at {ref!r} — a branch is re-resolved on every re-run"
        )


def test_the_lock_is_still_signed_and_checks_the_resolved_shas():
    lock = WF["jobs"]["lock"]
    runs = "\n".join(str(s.get("run", "")) for s in lock["steps"])
    assert "release-sign" in runs and "release-verify" in runs
    assert "release-line" in lock["needs"]
    assert any(s.get("name") == "Sibling sources are the SHAs this run resolved" for s in lock["steps"])


def test_dry_run_publishes_nothing():
    """Every job that pushes must be downstream of a job skipped on dry_run."""
    on = WF.get("on", WF.get(True))  # YAML 1.1 reads a bare `on:` key as True
    assert on["workflow_dispatch"]["inputs"]["dry_run"]["type"] == "boolean"

    def needs(j):
        n = j.get("needs", [])
        return {n} if isinstance(n, str) else set(n)

    roots = {n for n, j in WF["jobs"].items() if needs(j) <= {"release-line"} and n != "release-line"}
    assert roots == {"static-ffmpeg", "deps-core"}, roots
    for n in roots:
        assert "github.event.inputs.dry_run != 'true'" in WF["jobs"][n].get("if", ""), n


def test_the_retag_kill_switch_builds_everything(monkeypatch):
    monkeypatch.setenv("RELEASE_RETAG", "off")
    assert not any(_plan()["retag"].values())
    monkeypatch.delenv("RELEASE_RETAG")
    assert any(_plan()["retag"].values()), "the same fixture must re-tag with the switch unset"
    plan_step = next(s for s in WF["jobs"]["release-line"]["steps"] if s.get("id") == "plan")
    assert "vars.RELEASE_RETAG" in str(plan_step.get("env"))


def test_base_digests_come_from_the_rc_bases_file():
    """deps-core/deps-base are not in the lock (the launcher would pin them);
    the rc attaches stack-<rc>.bases so a final can check the rc tag still
    resolves to the digest the rc built."""
    p = _plan(bases="deps-base@sha256:bb\ndeps-core@sha256:cc\n")
    assert p["rc_digests"]["deps-core"] == "sha256:cc" and p["rc_digests"]["deps-base"] == "sha256:bb"
    assert "not cross-checked" not in p["why"]["deps-core"]
    old = _plan(bases=None)
    assert old["retag"]["deps-core"] is True and "not cross-checked" in old["why"]["deps-core"]


def test_base_retags_pass_the_recorded_digest():
    for job, img in (("deps-core", "deps-core"), ("deps-base", "deps-base")):
        retag = next(s for s in _steps(job) if str(s.get("name", "")).startswith("Re-tag"))
        assert '"$RC_DIGEST"' in retag["run"], job
        assert "rc_digests" in str(WF["jobs"][job]["env"]["RC_DIGEST"]), job
        rec = next(s for s in _steps(job) if s.get("name") == f"Record {img} digest")
        assert f"bases/{img}" in rec["run"]


def test_the_rc_publishes_a_signed_bases_file():
    runs = "\n".join(str(s.get("run", "")) for s in WF["jobs"]["lock"]["steps"])
    assert 'release-sign "stack-$TAG.bases"' in runs
    assert '"stack-$TAG.bases.sig"' in runs


def test_a_resolved_sibling_with_no_source_row_fails_the_lock():
    step = next(s for s in WF["jobs"]["lock"]["steps"]
                if s.get("name") == "Sibling sources are the SHAs this run resolved")
    assert "[ -f \"$1\" ] || return 0" not in step["run"], "a missing row passes silently"
    assert "no job recorded" in step["run"]


def test_the_source_row_check_executes(tmp_path):
    """Run the lock job's real check: equal passes, a different SHA fails,
    a resolved SHA with no row fails, nothing resolved passes."""
    import subprocess
    step = next(s for s in WF["jobs"]["lock"]["steps"]
                if s.get("name") == "Sibling sources are the SHAs this run resolved")
    d = tmp_path / "digests"
    d.mkdir()
    (d / "source-trellion").write_text("source:trellion@aaa\n")

    def run(**env):
        base = {"PATH": "/usr/bin:/bin", "WANT_TRELLION": ""}
        return subprocess.run(["bash", "-c", step["run"]], cwd=tmp_path, env={**base, **env},
                              capture_output=True, text=True).returncode

    assert run(WANT_TRELLION="aaa") == 0
    assert run(WANT_TRELLION="zzz") != 0
    (d / "source-trellion").unlink()
    assert run(WANT_TRELLION="aaa") != 0, "a resolved SHA with no recorded row passed"
    assert run() == 0


def _push_owner(job, image):
    """The owner var the job's build step pushes <image> under."""
    text = "\n".join(str(s.get("run", "")) for s in WF["jobs"][job]["steps"])
    m = re.search(r'-t "\$REGISTRY/\$\{?(\w+)\}?/(?:%s|\$\{\{ matrix\.image \}\}):\$TAG"' % re.escape(image), text)
    assert m, f"{job} has no build step pushing {image}"
    return m.group(1)


def test_every_retag_passes_the_owner_the_build_step_pushes_to():
    """stack-v0.6.0: deps-core is pushed under $DHI_OWNER but the re-tag looked
    under $OWNER ('ghcr.io/noomesh/deps-core:...-rc.4: not found')."""
    seen = 0
    for job, spec in WF["jobs"].items():
        for s in spec.get("steps", []):
            run = str(s.get("run", ""))
            m = re.search(r"release-retag-image\.sh\s+(\S+)", run)
            if not m:
                continue
            seen += 1
            img = m.group(1).strip('"')
            owner = _push_owner(job, img)
            got = (s.get("env") or {}).get("IMAGE_OWNER")
            assert got == "${{ env.%s }}" % owner, f"{job}: re-tag of {img} passes IMAGE_OWNER={got!r}, build pushes under ${owner}"
    assert seen == 3


def test_retag_script_builds_its_ref_from_image_owner(tmp_path):
    import os
    import subprocess

    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "log"
    (bindir / "docker").write_text(
        '#!/usr/bin/env bash\necho "$*" >> "$STUB_LOG"\n'
        'case "$*" in *inspect*) echo "\\"${STUB_DIGEST}\\"";; esac\n'
    )
    (bindir / "docker").chmod(0o755)

    def run(env_extra, want="sha256:aa"):
        env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "STUB_LOG": str(log),
               "STUB_DIGEST": "sha256:aa", "REGISTRY": "ghcr.io", "OWNER": "noomesh", **env_extra}
        env.pop("IMAGE_OWNER", None) if "IMAGE_OWNER" not in env_extra else None
        log.write_text("")
        r = subprocess.run(["bash", str(ROOT / "scripts/release-retag-image.sh"), "deps-core", "v1-rc.1", "v1", want],
                           env=env, capture_output=True, text=True)
        return r, log.read_text()

    r, calls = run({"IMAGE_OWNER": "noomesh/dhi"})
    assert r.returncode == 0, r.stderr
    assert "ghcr.io/noomesh/dhi/deps-core:v1-rc.1" in calls and "--tag ghcr.io/noomesh/dhi/deps-core:v1" in calls
    r, calls = run({})
    assert r.returncode == 0 and "ghcr.io/noomesh/deps-core:v1-rc.1" in calls
    # a registry digest that differs from the rc lock's is a hard failure, before any create
    r, calls = run({"IMAGE_OWNER": "noomesh/dhi"}, want="sha256:bb")
    assert r.returncode != 0 and "imagetools create" not in calls


# ------------------------------------------------- staged infra images (i567)
#
# infra-staged.yml builds, scans and stages the infra images daily; the plan
# re-tags `<image>:staged` for any of them it would otherwise build, only when
# every platform's fingerprint label equals this commit's and the copy is at
# most 3 days old. Everything else builds.

from datetime import datetime, timedelta, timezone

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
FP = "sha256:" + "f" * 64
SDIG = "sha256:" + "5" * 64
DAILY = ("llamacpp", "ollama", "stunnel", "postgres-pgvector", "whisper", "piper", "nvidia-exporter")
NEW_VERSION = {"stack-v1.3.0-rc.1": "N"}   # a new version's rc.1: no lower rc, everything would build


def _labels(fp=FP, created="2026-11-20T03:17:00Z", plats=("linux/amd64", "linux/arm64")):
    lab = {}
    if fp is not None:
        lab[P_LABEL] = fp
    if created is not None:
        lab[P_CREATED] = created
    return {p: dict(lab) for p in plats}


P_LABEL, P_CREATED = "org.noomesh.build-fingerprint", "org.opencontainers.image.created"


def _staged_plan(staged=None, fps=None, tag="stack-v1.3.0-rc.1", trees=None, rcs=(), now=NOW, raise_for=()):
    staged = staged if staged is not None else {img: (SDIG, _labels()) for img in DAILY}
    looked = []

    def staged_of(img):
        looked.append(img)
        if img in raise_for or img not in staged:
            raise LookupError(f"{img}:staged: not found")
        return staged[img]

    def fingerprint_of(img, bases=None):
        v = (fps or {}).get(img, FP)
        if callable(v):
            v = v(bases)
        if isinstance(v, Exception):
            raise v
        return v

    p = P.plan(tag, "o/r", MAINS, "t", "t", lock_text=LOCK, bases_text=None,
               tree_of=lambda ref: (trees or NEW_VERSION)[ref], commit_of=lambda ref: "C-" + ref,
               list_rcs=lambda final: list(rcs), sib_tree=lambda repo, sha, tok: SIB_TREES[sha],
               changed_of=lambda prev, new: None,
               staged_of=staged_of, fingerprint_of=fingerprint_of, now=now)
    return p, looked


def test_a_matching_staged_copy_is_retagged_by_its_exact_digest():
    p, _ = _staged_plan()
    for img in DAILY:
        assert p["retag"][img] is True, p["why"][img]
        assert p["source_tags"][img] == "@" + SDIG and p["rc_digests"][img] == SDIG
        assert p["staged"][img] == "2026-11-20T03:17:00Z"
    built = {i for i, r in p["retag"].items() if not r}
    assert built == {"gateway", "node-agent", "worker", "sandbox", "trellion", "deps-core", "deps-base"}, p["why"]


def test_a_changed_input_or_one_differing_platform_builds():
    p, _ = _staged_plan(fps={"llamacpp": "sha256:" + "0" * 64})
    assert p["retag"]["llamacpp"] is False and "fingerprint differs" in p["why"]["llamacpp"]
    one = _labels()
    one["linux/arm64"][P_LABEL] = "sha256:" + "1" * 64
    p, _ = _staged_plan(staged={**{i: (SDIG, _labels()) for i in DAILY}, "ollama": (SDIG, one)})
    assert p["retag"]["ollama"] is False and "linux/arm64" in p["why"]["ollama"]
    assert p["retag"]["llamacpp"] is True, "one image's mismatch must not touch the others"


def test_a_missing_staged_tag_or_label_builds():
    p, _ = _staged_plan(raise_for=("whisper",))
    assert p["retag"]["whisper"] is False and "unreadable" in p["why"]["whisper"]
    p, _ = _staged_plan(staged={**{i: (SDIG, _labels()) for i in DAILY}, "piper": (SDIG, _labels(fp=None))})
    assert p["retag"]["piper"] is False and p["why"]["piper"].startswith("BUILD (no usable :staged copy)")
    p, _ = _staged_plan(staged={**{i: (SDIG, _labels()) for i in DAILY}, "stunnel": ("sha256:short", _labels())})
    assert p["retag"]["stunnel"] is False


def test_an_old_or_undated_staged_copy_builds():
    old = NOW - timedelta(days=3, hours=1)
    p, _ = _staged_plan(staged={**{i: (SDIG, _labels()) for i in DAILY},
                                "llamacpp": (SDIG, _labels(created=old.strftime("%Y-%m-%dT%H:%M:%SZ")))})
    assert p["retag"]["llamacpp"] is False and "is infra-staged.yml failing" in p["why"]["llamacpp"]
    fresh = NOW - timedelta(days=2, hours=23)
    p, _ = _staged_plan(staged={**{i: (SDIG, _labels()) for i in DAILY},
                                "llamacpp": (SDIG, _labels(created=fresh.strftime("%Y-%m-%dT%H:%M:%SZ")))})
    assert p["retag"]["llamacpp"] is True, "inside 3 days is fresh"
    for created in (None, "yesterday", (NOW + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")):
        p, _ = _staged_plan(staged={**{i: (SDIG, _labels()) for i in DAILY},
                                    "ollama": (SDIG, _labels(created=created))})
        assert p["retag"]["ollama"] is False, created


def test_no_fingerprint_at_this_commit_builds():
    p, looked = _staged_plan(fps={"postgres-pgvector": ValueError("FROM x:1 is not pinned by digest")})
    assert p["retag"]["postgres-pgvector"] is False and "no fingerprint" in p["why"]["postgres-pgvector"]
    assert "postgres-pgvector" not in looked, "no fingerprint: nothing to compare, the registry is not asked"


def test_an_equal_input_rc_wins_over_staged():
    p, looked = _staged_plan(tag="stack-v1.2.3", trees={"stack-v1.2.3": "T", "stack-v1.2.3-rc.2": "T"},
                             rcs=("stack-v1.2.3-rc.2",))
    assert p["rc_tag"] == "stack-v1.2.3-rc.2"
    assert p["source_tags"]["llamacpp"] == "v1.2.3-rc.2" and p["rc_digests"]["llamacpp"] == "sha256:l"
    assert looked == [] and p["staged"] == {}


def test_the_kill_switch_also_turns_off_staged(monkeypatch):
    monkeypatch.setenv("RELEASE_RETAG", "off")
    p, looked = _staged_plan()
    assert looked == [] and not any(p["retag"].values())


def test_only_the_daily_set_is_ever_taken_from_staged():
    p, looked = _staged_plan(staged={i: (SDIG, _labels()) for i in list(P.SIBLING_INPUTS)})
    assert set(looked) == set(DAILY)
    for img in ("gateway", "node-agent", "worker", "sandbox", "trellion", "deps-core", "deps-base"):
        assert p["retag"][img] is False


def test_main_looks_up_staged_unless_told_not_to(monkeypatch, tmp_path):
    seen = []

    def fake_plan(*a, **kw):
        seen.append(kw.get("staged_of"))
        return {"rc_tag": "", "rc_commit": "", "rc_digests": {}, "source_tags": {"llamacpp": "@" + SDIG},
                "staged": {"llamacpp": "2026-11-20T03:17:00Z"}, "retag": {"llamacpp": True}, "why": {"llamacpp": "x"}}
    monkeypatch.setattr(P, "plan", fake_plan)
    out = tmp_path / "out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    P.main(["--tag", "v1.3.0-rc.1"])
    P.main(["--tag", "v1.3.0-rc.1", "--no-staged"])
    assert seen == [P.staged_image, None]
    text = out.read_text()
    assert f'source_tags={{"llamacpp":"@{SDIG}"}}' in text and 'staged={"llamacpp":"2026-11-20T03:17:00Z"}' in text


def test_the_workflow_copies_the_planned_source_and_records_staged_provenance():
    line = WF["jobs"]["release-line"]
    assert line["outputs"]["source_tags"] == "${{ steps.plan.outputs.source_tags }}"
    assert line["outputs"]["staged"] == "${{ steps.plan.outputs.staged }}"
    env = WF["jobs"]["images"]["env"]
    assert env["RC_TAG"] == "${{ fromJSON(needs.release-line.outputs.source_tags)[matrix.image] }}"
    lock_steps = WF["jobs"]["lock"]["steps"]
    rec = [s for s in lock_steps if s.get("name") == "Record the staged infra images a release reuses"]
    assert len(rec) == 1 and "staged-from:{img}@{created}" in rec[0]["run"] and "digests/staged-from-" in rec[0]["run"]
    names = [s.get("name") for s in lock_steps]
    sign = next(i for i, s in enumerate(lock_steps) if "release-sign" in str(s.get("run", "")))
    assert names.index("Record the staged infra images a release reuses") < sign, "provenance must be inside the signed lock"
    # the provenance row is no image row for the plan's own lock reader either
    images, _ = P.parse_lock(f"staged-from:llamacpp@2026-11-20T03:17:00Z\nllamacpp@{SDIG}\n")
    assert images == {"llamacpp": SDIG}


def test_retag_script_copies_an_exact_staged_digest_and_nothing_else(tmp_path):
    import os
    import subprocess

    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "log"
    (bindir / "docker").write_text(
        '#!/usr/bin/env bash\necho "$*" >> "$STUB_LOG"\n'
        'case "$*" in *inspect*) echo "\\"${STUB_DIGEST}\\"";; esac\n'
    )
    (bindir / "docker").chmod(0o755)

    def run(src, want):
        env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "STUB_LOG": str(log),
               "STUB_DIGEST": SDIG, "REGISTRY": "reg.example", "OWNER": "own"}
        env.pop("IMAGE_OWNER", None)
        log.write_text("")
        r = subprocess.run(["bash", str(ROOT / "scripts/release-retag-image.sh"), "llamacpp", src, "v1.3.0-rc.1", want],
                           env=env, capture_output=True, text=True)
        return r, log.read_text()

    r, calls = run("@" + SDIG, SDIG)
    assert r.returncode == 0, r.stderr
    assert f"inspect reg.example/own/llamacpp@{SDIG}" in calls and ":staged" not in calls
    assert f"--tag reg.example/own/llamacpp:v1.3.0-rc.1 reg.example/own/llamacpp@{SDIG}" in calls
    for want in ("sha256:" + "6" * 64, ""):
        r, calls = run("@" + SDIG, want)
        assert r.returncode != 0 and "imagetools create" not in calls, want
