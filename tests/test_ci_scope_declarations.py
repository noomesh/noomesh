# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CI may narrow what it BUILDS. It may not narrow what it CHECKS.

`scope` decides, from the diff, which of the three expensive jobs do real
work — `rust-gateway`, `noo-cli`, `sqlx-drift`. That is a wall-clock win worth
having: on a run where all three are skipped the pipeline finishes in about a
quarter of the time, because those three ARE the critical path.

It is also the most dangerous kind of change in this tree, for a reason worth
stating plainly: getting the mapping wrong does not make CI slow, it makes CI
green. A narrowing rule that skips the wrong job lets a change ship without
the check that would have caught it, and nothing about the run looks unusual.

So this file holds the shape of the rule rather than trusting a reading of it:

  * the jobs that carry the cross-language parity guards are never narrowed —
    those guards are the ONLY thing comparing a Rust grant with a Go client,
    a Rust ladder with a Python fixture, a posture list with its twin;
  * a job may be gated on its OWN crate and nothing else;
  * every output a job reads is one `scope` actually declares — a typo in an
    `if:` expression is not an error in Actions, it is a permanently false
    condition, i.e. a step that silently never runs again;
  * an unrecognised path turns every gate back on.

Static parse of .github/workflows/ci.yml. Same technique, and the same
reason, as test_posture_key_parity.py: the fact is in the source, so the
source is what to check.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github/workflows/ci.yml"

# The outputs that narrow a single tree's job. `code` is NOT one of them: it
# is the docs-only switch, and it applies to a job as a whole.
#
# `ui` is not a crate, but it is the same shape: one job, one tree, nothing
# else compiles it. It joined when the console's CI was folded in from
# ui/.github/, where the import had left it silently inert.
# `llamacpp` is one Dockerfile, not a crate, and the same shape again: one
# job compiles it and nothing else does. It joined after stack-v0.2.38 shipped
# no release because the first compile of the pinned llama.cpp ref happened on
# the release tag.
PER_CRATE = {"gateway", "cli", "sqlx", "ui", "llamacpp"}

# job -> the one output it may be gated on.
OWNS = {
    "rust-gateway": "gateway",
    "noo-cli": "cli",
    "sqlx-drift": "sqlx",
    "router-harness": "gateway",
    "ui": "ui",
    "llamacpp-image": "llamacpp",
}


def _workflow() -> dict:
    return yaml.safe_load(CI.read_text())


def _scope_refs(job: dict) -> set[str]:
    """Every `needs.scope.outputs.X` this job's conditions read."""
    blob = yaml.safe_dump(job)
    return set(re.findall(r"needs\.scope\.outputs\.(\w+)", blob))


def _scope_script() -> str:
    """The scope job's raw text.

    Read from the file, not from `yaml.safe_dump` of the parsed job: dumping
    re-wraps long lines and would make these assertions fail on formatting
    rather than on meaning.
    """
    text = CI.read_text()
    start = text.index("\n  scope:\n")
    end = re.search(r"\n  [a-z0-9-]+:\n", text[start + 1 :])
    return text[start : start + 1 + end.start()] if end else text[start:]


def _jobs_running_pytest(wf: dict) -> set[str]:
    out = set()
    for name, job in wf["jobs"].items():
        for step in job.get("steps") or []:
            if "pytest" in str(step.get("run", "")):
                out.add(name)
    return out


def test_the_parity_guards_are_never_narrowed() -> None:
    """Whatever runs `pytest tests/` runs on every PR, whole.

    This is the load-bearing assertion. The guards that make a multi-language
    tree survivable — subject parity, posture parity, the tier ladder, the
    declaration guards — are Python tests, and they check trees their own job
    does not compile. Narrowing them by the diff would disable exactly the
    check that a cross-tree change needs.
    """
    wf = _workflow()
    pytest_jobs = _jobs_running_pytest(wf)
    assert pytest_jobs, "no job runs pytest — this guard has stopped guarding"
    for name in sorted(pytest_jobs):
        narrowed = _scope_refs(wf["jobs"][name]) & PER_CRATE
        assert not narrowed, (
            f"job {name!r} runs the parity guards but is narrowed by "
            f"{sorted(narrowed)}. A cross-language guard that only runs when "
            f"one crate changed cannot catch two trees disagreeing — which is "
            f"the only thing it exists to catch."
        )


def test_preflight_is_never_narrowed() -> None:
    """Six textual guardrails, tenths of a second. There is nothing to win."""
    narrowed = _scope_refs(_workflow()["jobs"]["preflight"]) & PER_CRATE
    assert not narrowed, f"preflight is narrowed by {sorted(narrowed)}"


def test_a_job_is_gated_only_on_its_own_crate() -> None:
    """`noo-cli` gated on `gateway` would be green on every CLI change."""
    wf = _workflow()
    for name, job in wf["jobs"].items():
        refs = _scope_refs(job) & PER_CRATE
        if not refs:
            continue
        assert name in OWNS, (
            f"job {name!r} is narrowed by {sorted(refs)} but owns no crate. "
            f"Add it to OWNS here — deliberately — or drop the gate."
        )
        assert refs == {OWNS[name]}, (
            f"job {name!r} may only be gated on {OWNS[name]!r}, not {sorted(refs)}"
        )


def test_every_gate_reads_an_output_scope_declares() -> None:
    """A misspelt `if:` is not an error in Actions — it is always false.

    A step gated on `needs.scope.outputs.gatewy` does not fail the run. It
    stops running, forever, and reports success.
    """
    wf = _workflow()
    declared = set(wf["jobs"]["scope"].get("outputs", {}))
    assert PER_CRATE <= declared, f"scope declares {sorted(declared)}"
    for name, job in wf["jobs"].items():
        if name == "scope":
            continue
        unknown = _scope_refs(job) - declared
        assert not unknown, (
            f"job {name!r} gates on scope output(s) {sorted(unknown)} that "
            f"scope does not declare; the condition is permanently false"
        )


def test_an_unrecognised_path_turns_every_gate_back_on() -> None:
    """Fail open. A new top-level directory may cost minutes, never coverage."""
    script = _scope_script()
    assert re.search(r"\*\)\s+unknown=", script), (
        "the classifier's catch-all branch is gone — an unrecognised path now "
        "falls through as 'nothing to run' instead of running everything"
    )
    assert "gateway=true; cli=true; sqlx=true" in script, (
        "nothing re-arms the gates for an unrecognised path"
    )
    # Every gated output must have a rule that can set it. An output nothing
    # sets is a job that only ever runs by the fail-open path.
    for out in PER_CRATE:
        assert re.search(rf"\b{out}=true", script), f"nothing ever sets {out}=true"


def test_the_parse_found_what_it_claims_to_check() -> None:
    """Guard the guard: these assertions all pass against an empty parse."""
    wf = _workflow()
    gated = {n for n, j in wf["jobs"].items() if _scope_refs(j) & PER_CRATE}
    assert gated == set(OWNS), (
        f"expected exactly {sorted(OWNS)} to be crate-gated, found {sorted(gated)}. "
        f"If a job was added or removed, update OWNS deliberately."
    )
    assert "test-core" in _jobs_running_pytest(wf)


def _classify(changed: list[str], **env: str) -> dict[str, str]:
    """Run the REAL classifier from ci.yml against a fixture file list.

    Reading a shell script and believing it is how the `grep -qv` bug got in
    (see the comment in the step itself: a predicate that meant the opposite
    of what it looked like, validated on a box whose grep disagreed with the
    runner's). So this executes the step's own text with `git diff` swapped
    for the fixture, and reads what it writes to $GITHUB_OUTPUT.
    """
    import subprocess
    import tempfile

    wf = _workflow()
    run = next(
        s["run"] for s in wf["jobs"]["scope"]["steps"] if s.get("id") == "diff"
    )
    run = run.replace(
        'changed="$(git diff --name-only "$BASE...HEAD")"', 'changed="$FIXTURE"'
    )
    # The llamacpp switch diffs the same range on its own (it also runs on
    # pushes); feed it the same fixture.
    lc = 'lc_changed="$(git diff --name-only "$lc_range" 2>/dev/null)" || lc_range=""'
    assert lc in run, "the llamacpp diff line moved; update this harness"
    run = run.replace(lc, 'lc_changed="$FIXTURE"')
    with tempfile.NamedTemporaryFile("w+", suffix=".out") as out:
        subprocess.run(
            ["bash", "-c", "set -eu\n" + run],
            env={
                "PATH": "/usr/bin:/bin",
                "BASE": "fixture",
                "FIXTURE": "\n".join(changed),
                "GITHUB_OUTPUT": out.name,
                **env,
            },
            check=True,
            capture_output=True,
        )
        out.seek(0)
        return dict(
            line.strip().split("=", 1) for line in out if "=" in line
        )


def test_the_classifier_narrows_and_fails_open() -> None:
    """What the rule actually does, per diff shape."""
    docs = _classify(["docs/a.md", "internal/b.md"])
    assert docs == {"code": "false", "gateway": "false", "cli": "false",
                    "sqlx": "false", "ui": "false", "llamacpp": "false",
                    "deferred": "false"}

    cli = _classify(["noo-cli/src/main.rs"])
    assert cli["cli"] == "true" and cli["gateway"] == "false" and cli["sqlx"] == "false"
    assert cli["ui"] == "false", "a CLI change must not run the console job"
    assert cli["llamacpp"] == "false", "a CLI change must not compile llama-server"

    # The llamacpp Dockerfile switches its own build on AND, being routed to
    # "unknown" rather than a docs bucket, still re-arms
    # everything else — both halves are load-bearing.
    lc = _classify(["docker/Dockerfile.llamacpp"])
    assert lc["llamacpp"] == "true", "a docker/Dockerfile.llamacpp change must compile llama-server"
    assert lc["gateway"] == "true" and lc["cli"] == "true", (
        "docker/Dockerfile.llamacpp must stay an unrecognised path (fail open)"
    )

    # The console: its own job, and no Rust.
    ui = _classify(["ui/apps/web/src/App.tsx"])
    assert ui["ui"] == "true"
    assert ui["gateway"] == "false" and ui["cli"] == "false" and ui["sqlx"] == "false"

    # The gateway owns the sqlx offline data and the migrations sqlx-drift
    # diffs, so it arms both.
    gw = _classify(["gateway-rust/src/x.rs"])
    assert gw["gateway"] == "true" and gw["sqlx"] == "true" and gw["cli"] == "false"
    # ... and the console job too: the contract audit's router half diffs
    # `.route(...)` in gateway-rust, so a route change can break it.
    assert gw["ui"] == "true", "a gateway route change must re-run the contract audit"

    mig = _classify(["src/noomesh/db/migrations/versions/047_x.py"])
    assert mig["sqlx"] == "true" and mig["gateway"] == "false"

    # A path no rule recognises arms every CHECK — including a file at the
    # repository root, which is the easy one to forget.
    for unknown in (["Cargo.toml"], ["noomesh.yaml"], ["some-new-tree/x.py"]):
        got = _classify(unknown)
        assert all(got[k] == "true" for k in ("code", "gateway", "cli", "sqlx", "ui")), (
            f"{unknown} did not re-arm every gate: {got}"
        )
        # ...but not the llama-server compile: that image's only input in this
        # tree is docker/Dockerfile.llamacpp (it COPYs nothing from the
        # context — test_the_llamacpp_image_reads_nothing_else_from_the_tree),
        # so an unrelated path cannot change what it builds (2026-10-09).
        assert got["llamacpp"] == "false", f"{unknown} compiled llama-server: {got}"

    # Its own inputs, and the workflow that builds it, do arm it.
    for own in (["docker/Dockerfile.llamacpp"], [".github/workflows/ci.yml"]):
        assert _classify(own)["llamacpp"] == "true", f"{own} must compile llama-server"

    # Docs mixed with code is code. This is the exact case the `grep -qv`
    # bug got backwards.
    mixed = _classify(["docs/a.md", "noo-cli/src/main.rs"])
    assert mixed["code"] == "true" and mixed["cli"] == "true"



def test_a_pr_into_dev_defers_the_rust_builds_to_the_queue() -> None:
    """One full Rust build per change, in the merge queue, not two.

    A PR into dev merges only through the queue, which re-runs every check
    on the merge group. So the PR itself skips the Rust builds; everything
    else, above all the Python parity guards, still runs on it.
    """
    rust = ["gateway-rust/src/x.rs", "noo-cli/src/main.rs"]
    pr = _classify(rust, EVENT="pull_request", PR_BASE_REF="dev", FULL_CI="false")
    assert pr["deferred"] == "true"
    assert pr["gateway"] == pr["cli"] == pr["sqlx"] == "false", pr
    assert pr["code"] == "true", "deferral must not turn the change into docs-only"
    assert pr["ui"] == "true", "the console job is not Rust; it still runs on the PR"

    # The label opts back in; a promotion PR into staging/main never defers
    # (no queue there); a merge group or push never defers (EVENT differs).
    for env in (
        dict(EVENT="pull_request", PR_BASE_REF="dev", FULL_CI="true"),
        dict(EVENT="pull_request", PR_BASE_REF="staging", FULL_CI="false"),
        dict(EVENT="pull_request", PR_BASE_REF="main", FULL_CI="false"),
        dict(EVENT="merge_group", PR_BASE_REF="", FULL_CI="false"),
    ):
        got = _classify(rust, **env)
        assert got["deferred"] == "false", env
        assert got["gateway"] == got["cli"] == got["sqlx"] == "true", (env, got)


def test_standalone_smoke_builds_only_when_not_deferred() -> None:
    """standalone-smoke compiles noo-cli, so it defers with the Rust jobs."""
    text = CI.read_text()
    start = text.index("\n  standalone-smoke:\n")
    end = text.index("\n  build:\n")
    block = text[start:end]
    gated = re.findall(r"if: needs\.scope\.outputs\.code == 'true'(.*)", block)
    assert gated, "no code-gated step in standalone-smoke — this guard parsed the wrong block"
    for rest in gated:
        assert "needs.scope.outputs.deferred != 'true'" in rest, rest


# ---------------------------------------------------------------------------
# The console artifact and the gateway that embeds it must agree on the tag.
# ---------------------------------------------------------------------------

def test_the_console_artifact_tag_matches_what_the_gateway_pulls():
    """`publish-web` and `images-release` must derive the same string.

    The gateway builds with `--build-arg UI_IMAGE=…/mesh-ui-web:$TAG`, and
    `images-release` sets `TAG=${GITHUB_REF_NAME#stack-}`. If `publish-web`
    published the raw ref instead, the console would exist at
    `stack-v0.2.25` while the gateway looked for `v0.2.25`, and the release
    would die at `FROM ${UI_IMAGE}` — after the tag was already pushed.

    Both are triggered by the SAME tag, so nothing else compares them.
    """
    root = CI.parent
    pub = (root / "publish-web.yml").read_text()
    rel = (root / "images-release.yml").read_text()

    # Match the CODE, not the prose. A first draft of this asserted
    # `"#stack-" in pub`, which the explanatory COMMENT above the code
    # satisfies — so it passed with the stripping deleted. A guard that reads
    # a comment is a guard that reads nothing.
    # EVERY resolve site, not just the push path. images-release has five,
    # one per job, and the dispatch branch used to take its input verbatim —
    # so dispatching `stack-v0.2.25` (the git tag; the obvious thing to type)
    # tagged every image `:stack-v0.2.25` while the launcher looked for
    # `:v0.2.25`. The first draft of this guard only checked the push path,
    # which is exactly the half that was already right.
    resolves = rel.count("${raw#stack-}")
    assert resolves >= 5, (
        f"only {resolves} resolve site(s) in images-release strip the prefix; "
        "a site that does not turns a dispatched release into images nobody "
        "can pull"
    )
    assert "${{ github.event.inputs.tag }}" not in rel.replace(
        "${{ github.event.inputs.tag || github.ref_name }}", ""
    ), (
        "a resolve site uses the dispatch input directly instead of the "
        "stripped `raw` — the two entry points would disagree again"
    )
    assert "${raw#stack-}" in pub, (
        "publish-web does not strip the `stack-` prefix that images-release "
        "strips — the console artifact and the gateway's UI_IMAGE would "
        "resolve to different tags, and the release would die at FROM ${UI_IMAGE}"
    )

    # And the gateway must pull it by $TAG rather than a literal, or the pin
    # can drift the way it did at v0.1.7 for months.
    assert "--build-arg UI_IMAGE=$REGISTRY/$OWNER/mesh-ui-web:$TAG" in rel, (
        "the gateway no longer pins the console by $TAG — a literal here is "
        "how UI_IMAGE sat at v0.1.7 through every release"
    )


# (The self-hosted-runner topology guards that lived here were retired when CI
# went GitHub-hosted only: see tests/test_ci_cloud_only.py.)


def test_the_llamacpp_image_reads_nothing_else_from_the_tree() -> None:
    """The narrow llamacpp switch is only sound while this holds.

    scope compiles llama-server when docker/Dockerfile.llamacpp or ci.yml changed,
    and on nothing else. That is correct only because the Dockerfile takes no
    input from the build context: every COPY is `--from=` a stage. A COPY of
    a repo path would make that path an input the switch does not watch.
    """
    df = (ROOT / "docker/Dockerfile.llamacpp").read_text()
    copies = [ln.strip() for ln in df.splitlines() if re.match(r"\s*(COPY|ADD)\b", ln)]
    assert copies, "no COPY in docker/Dockerfile.llamacpp — this guard parsed the wrong file"
    from_context = [c for c in copies if "--from=" not in c]
    assert not from_context, (
        f"docker/Dockerfile.llamacpp now reads the build context ({from_context}); "
        "add those paths to the llamacpp switch in ci.yml's scope step"
    )


def _scope_on_push(tmp: Path, history: list[tuple[dict[str, str], str | None]]) -> dict[str, str]:
    """Run the REAL scope step as a push event in a throwaway git repo.

    `history` is a list of (files to write, tag to put on that commit or None);
    the push is the last commit.
    """
    import subprocess

    def sh(*a: str) -> str:
        return subprocess.run(a, cwd=tmp, check=True, capture_output=True, text=True).stdout.strip()

    tmp.mkdir(parents=True, exist_ok=True)
    sh("git", "init", "-q")
    sh("git", "config", "user.email", "t@example.invalid")
    sh("git", "config", "user.name", "t")
    for n, (files, tag) in enumerate(history):
        for rel, body in files.items():
            (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
            (tmp / rel).write_text(body)
        (tmp / "n").write_text(str(n))
        sh("git", "add", "-A")
        sh("git", "commit", "-qm", f"c{n}")
        if tag:
            sh("git", "tag", tag)
    run = next(s["run"] for s in _workflow()["jobs"]["scope"]["steps"] if s.get("id") == "diff")
    out = tmp / "out"
    env = {"PATH": "/usr/bin:/bin", "BASE": "", "GITHUB_OUTPUT": str(out)}
    subprocess.run(["bash", "-c", "set -eu\n" + run], cwd=tmp, env=env, check=True,
                   capture_output=True)
    return dict(line.strip().split("=", 1) for line in out.read_text().splitlines() if "=" in line)


DF = "docker/Dockerfile.llamacpp"


def test_a_push_compiles_llamacpp_only_when_it_differs_from_the_last_release(tmp_path: Path) -> None:
    """A push used to compile llama-server on every merge to dev (~5 min of a
    self-hosted runner). It now compares the pushed tree with the last FINAL
    release — and still runs every OTHER check, whole, as the integration
    point always has."""
    released = ({DF: "FROM x\n", "src/a.py": "a\n"}, "stack-v1.0.0")
    unrelated = _scope_on_push(tmp_path / "u", [released, ({"src/a.py": "b\n"}, None)])
    assert unrelated["llamacpp"] == "false", unrelated
    assert all(unrelated[k] == "true" for k in ("code", "gateway", "cli", "sqlx", "ui")), (
        f"a push must never narrow the checks: {unrelated}"
    )
    touched = _scope_on_push(tmp_path / "t", [released, ({DF: "FROM y\n"}, None)])
    assert touched["llamacpp"] == "true", touched


def test_an_unrelated_push_after_a_llamacpp_change_still_compiles_it(tmp_path: Path) -> None:
    """The hidden-breakage case: push A changes (breaks) the Dockerfile, push B
    is unrelated. Diffing B against its parent would skip the compile, B would
    go green, and the promotion gate would prove the release from B. Against
    the last release, B still compiles — until a FINAL ships the change (an
    rc tag is not a release point)."""
    hist = [({DF: "FROM x\n"}, "stack-v1.0.0"), ({DF: "FROM broken\n"}, None),
            ({"src/a.py": "b\n"}, "stack-v1.1.0-rc.1"), ({"src/a.py": "c\n"}, None)]
    assert _scope_on_push(tmp_path / "b", hist)["llamacpp"] == "true"
    shipped = hist + [({"src/a.py": "d\n"}, "stack-v1.1.0"), ({"src/a.py": "e\n"}, None)]
    assert _scope_on_push(tmp_path / "s", shipped)["llamacpp"] == "false"


def test_a_push_with_no_release_to_diff_against_fails_open(tmp_path: Path) -> None:
    """No final tag and no origin/main: compile."""
    got = _scope_on_push(tmp_path / "z", [({"src/a.py": "a\n"}, None), ({"src/a.py": "b\n"}, None)])
    assert got["llamacpp"] == "true", got
