#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The harness of .github/workflows/mutants.yml: plan, run, judge, summary.

A mutant is a branch whose ONE commit removes or breaks a check on top of a
fix (its parent). It is proven when a test fails on it while the same tests
pass on its parent. Verdicts, as ops/batch/noo-batch.sh prints them:

  red       a test FAILED on the mutant and the parent was green: caught
  green     every test passed on the mutant: SURVIVED, nothing caught it
  error     the mutant did not build, or no test ran: proves nothing
  base-red  the parent itself failed (or ran no test): NO VERDICT

The workflow runs this file from its OWN commit (a sparse checkout of the
workflow ref), never from the mutant's tree, so a mutant cannot change how its
verdict is read. Every input arrives through the environment and is validated
here before it reaches git or a command line; commands are argv lists, never a
shell string.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

LANES = ("gateway-rust", "noo-cli", "node-agent-go", "python")
# A branch name as this repo's mutants are named: no leading '-', no '..', no
# '//', no '@{', nothing a shell or git would read as more than a name.
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
# One test filter: a cargo name (a::b), a go test name, a pytest node id or
# file, or a pytest -k word. No spaces, quotes, $, `, ; or globs.
FILTER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_:./-]{0,199}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# A PUSHED mutant branch (mutants.yml `on.push.branches`): wt/<…>-mut-<…> or
# wt/<…>-mutant-<…>, the shapes in use. Held again here, not only by the trigger.
PUSH_BRANCH_RE = re.compile(r"^wt/[A-Za-z0-9._-]+-(mut|mutant)-[A-Za-z0-9._-]+$")
# A mutant commit may not edit its own judge: the workflows, or this harness.
JUDGE_PATHS = (".github/",)
JUDGE_FILES = ("scripts/ci-mutants.py",)
MAX_MUTANTS = 32


class Refused(Exception):
    pass


def git(*args: str, cwd: str | None = None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def valid_branch(b: str) -> bool:
    return bool(BRANCH_RE.match(b)) and ".." not in b and "//" not in b and not b.endswith((".lock", "/", ".")) \
        and "/." not in b


def parse_mutants(spec: str) -> list[tuple[str, list[str]]]:
    """`branch[:filter[,filter…]]`, space-separated. Refuses anything else."""
    out: list[tuple[str, list[str]]] = []
    seen: set[str] = set()
    for tok in spec.split():
        branch, _, rest = tok.partition(":")
        if not valid_branch(branch):
            raise Refused(f"not a branch name this workflow accepts: {branch!r}")
        filters = [f for f in rest.split(",") if f] if rest else []
        for f in filters:
            if not FILTER_RE.match(f):
                raise Refused(f"{branch}: not a test filter this workflow accepts: {f!r}")
        if branch in seen:
            raise Refused(f"{branch} is listed twice")
        seen.add(branch)
        out.append((branch, filters))
    if not out:
        raise Refused("no mutants given")
    if len(out) > MAX_MUTANTS:
        raise Refused(f"{len(out)} mutants: at most {MAX_MUTANTS} per run")
    return out


LANE_PREFIX_RE = re.compile(r"^(" + "|".join(re.escape(lane) for lane in LANES) + r"):\s+(.*)$")


def trailer_filters(sha: str, cwd: str | None = None) -> list[tuple[str | None, str]]:
    """The expected-red tests of a PUSHED mutant: its head commit's
    `Mutant-Test:` trailers (one or more lines, each one filter or a comma
    list), never free text. A line may name its lane first,
    `Mutant-Test: gateway-rust: <filter>[, <filter>]`; the filter then
    belongs to that lane only (see resolve_lanes). None at all is a refusal:
    a mutant whose tests are not named cannot be judged red-as-expected."""
    out = git("log", "-1", "--format=%(trailers:key=Mutant-Test,valueonly,separator=%x0a)", sha, cwd=cwd)
    filters: list[tuple[str | None, str]] = []
    for line in out.splitlines():
        lane: str | None = None
        m = LANE_PREFIX_RE.match(line.strip())
        if m:
            lane, line = m.group(1), m.group(2)
        for f in line.split(","):
            f = f.strip()
            if not f:
                continue
            if not FILTER_RE.match(f):
                raise Refused(f"Mutant-Test: not a test filter this workflow accepts: {f!r}")
            if (lane, f) not in filters:
                filters.append((lane, f))
    if not filters:
        raise Refused("the mutant commit has no `Mutant-Test: <test>` trailer: name the test(s) it must turn red")
    return filters


def resolve_lanes(diff_lanes: list[str], filters: list[tuple[str | None, str]]) -> tuple[list[str], list[str]]:
    """(lanes to run, filters) for a pushed mutant.

    Any filter without a lane: every lane the diff reaches runs, as before.
    Every filter names its lane: only those lanes run. A lane the diff reaches
    but no filter names is skipped for this mutant. Example: a mutant of
    gateway-rust/src/auth.rs also reaches noo-cli (it include_str!s that
    file), where a gateway test filter matches nothing and the lane could
    only ever say "no test ran". A named lane the diff does not reach is
    refused: the mutant cannot change what it runs. Each lane that runs must
    still run a test (lane_state), so zero tests anywhere is never a verdict."""
    names = [f for _, f in filters]
    if any(lane is None for lane, _ in filters):
        return list(diff_lanes), names
    named = [lane for lane in LANES if any(lane == x for x, _ in filters)]
    outside = [lane for lane in named if lane not in diff_lanes]
    if outside:
        raise Refused(f"Mutant-Test names lane(s) {' '.join(outside)} that this commit does not reach "
                      f"(its lanes: {' '.join(diff_lanes) or 'none'})")
    return named, names


def judge_edits(changed: list[str]) -> list[str]:
    """The files of a mutant commit that are its judge (it may not edit them)."""
    return [f for f in changed if f.startswith(JUDGE_PATHS) or f in JUDGE_FILES]


def parse_lanes(spec: str) -> list[str]:
    lanes = spec.split()
    for lane in lanes:
        if lane not in LANES:
            raise Refused(f"unknown lane {lane!r} (known: {' '.join(LANES)})")
    return lanes


def include_inputs(sha: str, crate: str) -> set[str]:
    """Repo files a crate embeds with include_str!/include_bytes! (noo-batch crate_inputs)."""
    try:
        out = git("grep", "-noE", r'include_(str|bytes)!\("[^"]+"\)', sha, "--", f"{crate}/*.rs")
    except subprocess.CalledProcessError:
        return set()
    found = set()
    for line in out.splitlines():
        # <sha>:<path>:<line>:<match>
        parts = line.split(":", 3)
        if len(parts) < 4:
            continue
        src, m = parts[1], parts[3]
        rel = m.split('("', 1)[1].rsplit('")', 1)[0]
        p = os.path.normpath(os.path.join(os.path.dirname(src), rel))
        if not p.startswith(crate + "/") and not p.startswith(".."):
            found.add(p)
    return found


def lanes_for(changed: list[str], gw_in: set[str], cli_in: set[str]) -> list[str]:
    """noo-batch's crates_for, plus the Go and Python lanes, over one commit's diff."""
    lanes: list[str] = []

    def add(lane: str) -> None:
        if lane not in lanes:
            lanes.append(lane)

    for f in changed:
        if f.startswith("gateway-rust/") or f in gw_in:
            add("gateway-rust")
        if f.startswith("noo-cli/") or f in cli_in:
            add("noo-cli")
        if f.startswith("crates/"):
            add("gateway-rust")
            add("noo-cli")
        if f.startswith("node-agent-go/"):
            add("node-agent-go")
        if f.endswith(".py") or f.startswith(("tests/", "noomesh/")):
            add("python")
    return [lane for lane in LANES if lane in lanes]


def cmd_plan() -> int:
    spec = os.environ.get("MUTANTS", "")
    override = os.environ.get("LANES", "")
    # A push of one mutant branch: the mutant is that branch, its filters come
    # from its commit's `Mutant-Test:` trailers (below), and dispatch input is
    # not read.
    push_ref = os.environ.get("PUSH_REF", "").strip()
    if push_ref:
        if not PUSH_BRANCH_RE.match(push_ref) or not valid_branch(push_ref):
            print(f"::error::a pushed branch this workflow does not judge: {push_ref!r}")
            return 2
        spec = push_ref
    try:
        mutants = parse_mutants(spec)
        forced = parse_lanes(override) if override.strip() else []
    except Refused as e:
        print(f"::error::{e}")
        return 2
    matrix = []
    for i, (branch, filters) in enumerate(mutants):
        try:
            git("fetch", "--quiet", "--depth=2", "origin", f"+refs/heads/{branch}:refs/mutants/{i}")
        except subprocess.CalledProcessError as e:
            print(f"::error::origin has no branch {branch} ({e.stderr.strip()[:200]})")
            return 2
        sha = git("rev-parse", f"refs/mutants/{i}").strip()
        parents = git("rev-list", "--parents", "-n", "1", sha).split()[1:]
        if len(parents) != 1:
            print(f"::error::{branch} ({sha[:8]}) has {len(parents)} parents: a mutant is ONE commit on top of its fix")
            return 2
        parent = parents[0]
        if not (SHA_RE.match(sha) and SHA_RE.match(parent)):
            print(f"::error::{branch}: unexpected object names {sha!r} {parent!r}")
            return 2
        changed = git("diff", "--name-only", parent, sha).split()
        if judge_edits(changed):
            print(f"::error::{branch}: its commit edits its own judge ({' '.join(judge_edits(changed))}); a mutant "
                  "changes the code under test only")
            return 2
        lanes = forced or lanes_for(changed, include_inputs(sha, "gateway-rust"), include_inputs(sha, "noo-cli"))
        if push_ref:
            try:
                lanes, filters = resolve_lanes(lanes, trailer_filters(sha))
            except Refused as e:
                print(f"::error::{branch}: {e}")
                return 2
        if not lanes:
            print(f"::error::{branch}: its commit touches no lane ({' '.join(changed)[:300]}); pass `lanes` to choose one")
            return 2
        matrix.append({
            "branch": branch, "sha": sha, "parent": parent, "lanes": " ".join(lanes),
            "filters": " ".join(filters), "addon_manifest": any(f.startswith("crates/addon-manifest/") for f in changed),
            "migrations": any("/migrations/" in f or f.startswith("migrations/") or "/alembic/" in f for f in changed),
        })
        if matrix[-1]["migrations"] and "gateway-rust" in lanes:
            print(f"::warning::{branch} changes a migration: the catalogue is replayed at the PARENT only, so the "
                  "DSN-gated suites judge the mutant against the parent's schema")
        print(f"{branch} {sha[:8]} (parent {parent[:8]}) lanes: {' '.join(lanes)}"
              + (f" filters: {' '.join(filters)}" if filters else " (whole lanes)"))
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as fh:
            fh.write(f"matrix={json.dumps({'include': matrix})}\n")
            fh.write(f"count={len(matrix)}\n")
    return 0


# ---- running a lane -------------------------------------------------------

def strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def tally_cargo(log: str) -> tuple[int, int, list[str]]:
    ran = failed = 0
    for m in re.finditer(r"^test result: \w+\. (\d+) passed; (\d+) failed", log, re.M):
        ran += int(m.group(1)) + int(m.group(2))
        failed += int(m.group(2))
    names = re.findall(r"^test (\S+) \.\.\. FAILED$", log, re.M)
    return ran, failed, names


def tally_go(log: str) -> tuple[int, int, list[str]]:
    passed = re.findall(r"^\s*--- PASS: (\S+)", log, re.M)
    fails = re.findall(r"^\s*--- FAIL: (\S+)", log, re.M)
    return len(passed) + len(fails), len(fails), fails


def tally_pytest(log: str) -> tuple[int, int, list[str]]:
    tail = log.strip().splitlines()[-1] if log.strip() else ""
    n = {k: int(v) for v, k in re.findall(r"(\d+) (passed|failed|errors?)", tail)}
    failed = n.get("failed", 0) + n.get("error", 0) + n.get("errors", 0)
    names = re.findall(r"^(?:FAILED|ERROR) (\S+)", log, re.M)
    return n.get("passed", 0) + failed, failed, names


def lane_commands(lane: str, filters: list[str], addon_manifest: bool) -> list[tuple[str, list[str], dict[str, str], str]]:
    """(cwd, argv, extra env, tally kind) per command of a lane."""
    dsn = "postgresql://noo:noo@localhost:5432/noomesh"
    if lane == "gateway-rust":
        cmds = [("gateway-rust", ["cargo", "test", "--locked", "--", *filters], {"SQLX_OFFLINE": "true"}, "cargo")]
        if addon_manifest:
            cmds.append(("gateway-rust", ["cargo", "test", "--locked", "-p", "addon-manifest", "--", *filters],
                         {"SQLX_OFFLINE": "true"}, "cargo"))
        # sqlx-drift's DSN-gated pass: the gated suites SKIP silently without
        # their DSNs, so they are set; single-threaded because they set
        # process-wide env vars; router harness has its own job in ci.yml.
        cmds.append(("gateway-rust", ["cargo", "test", "--locked", "--bin", "noo-gateway", "--", "--test-threads=1",
                                      "--skip", "router_harness_tests", *filters],
                     {"SQLX_OFFLINE": "true", "NOO_BROKER_TEST_DSN": dsn, "NOO_TEST_DSN": dsn,
                      "NOO_REQUIRE_GOOGLE_REHEARSAL": "1"}, "cargo"))
        return cmds
    if lane == "noo-cli":
        return [(".", ["scripts/cargo-docker.sh", "test", "--locked", "--", *filters],
                 {"CARGO_DOCKER_CRATE": str(Path.cwd() / "noo-cli")}, "cargo")]
    if lane == "node-agent-go":
        argv = ["go", "test", "-count=1", "-v", "./..."]
        if filters:
            argv += ["-run", "|".join(re.escape(f) for f in filters)]
        return [("node-agent-go", argv, {}, "go")]
    if lane == "python":
        argv = [sys.executable, "-m", "pytest", "tests/", "-q", "-rfE", "-p", "no:cacheprovider"]
        paths = [f for f in filters if f.startswith("tests/")]
        words = [f for f in filters if not f.startswith("tests/")]
        if paths:
            argv = [sys.executable, "-m", "pytest", *paths, "-q", "-rfE", "-p", "no:cacheprovider"]
        if words:
            argv += ["-k", " or ".join(words)]
        return [(".", argv, {"NOO_STRICT_SKIPS": "0", "TRELLION_PUBLIC": "true",
                             "NOO_KB_AUDIENCE_TEST_DSN": dsn,
                             "PAI_TRELLION_CHECKOUT": str(Path.cwd() / "_no_sibling_checkout")}, "pytest")]
    raise Refused(f"unknown lane {lane}")


TALLY = {"cargo": tally_cargo, "go": tally_go, "pytest": tally_pytest}


def run_phase(phase: str, lanes: list[str], filters: list[str], addon_manifest: bool, logdir: Path) -> dict:
    """Run every lane at the current checkout. Per lane: ran, failed, names, rc."""
    result: dict = {"phase": phase, "lanes": {}}
    for lane in lanes:
        ran = failed = 0
        names: list[str] = []
        rcs: list[int] = []
        log_path = logdir / f"{phase}-{lane}.log"
        with open(log_path, "w") as log:
            for cwd, argv, extra, kind in lane_commands(lane, filters, addon_manifest):
                print(f"::group::{phase} {lane}: {' '.join(argv)[:200]}", flush=True)
                env = {**os.environ, **extra}
                p = subprocess.run(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                   errors="replace")
                text = strip_ansi(p.stdout)
                sys.stdout.write(text[-20000:])
                print("::endgroup::", flush=True)
                log.write(text)
                r, f, n = TALLY[kind](text)
                ran, failed = ran + r, failed + f
                names += [x for x in n if x not in names]
                rcs.append(p.returncode)
        result["lanes"][lane] = {"ran": ran, "failed": failed, "names": names, "rcs": rcs, "log": str(log_path)}
    return result


def lane_state(r: dict) -> str:
    """failed = a test failed; error = non-zero with no failed test, or nothing ran; passed."""
    if r["failed"] > 0:
        return "failed"
    if any(rc != 0 for rc in r["rcs"]) or r["ran"] == 0:
        return "error"
    return "passed"


def judge(base: dict | None, mutant: dict | None) -> tuple[str, str]:
    """The verdict and its detail, from the two phases."""
    if base is None:
        return "error", "the parent was not run"
    bad = {lane: lane_state(r) for lane, r in base["lanes"].items() if lane_state(r) != "passed"}
    if bad:
        detail = "; ".join(f"{lane} {st}" + (f": {', '.join(base['lanes'][lane]['names'][:6])}" if base["lanes"][lane]["names"] else
                                               " (no test ran or it did not build)") for lane, st in bad.items())
        return "base-red", f"NO VERDICT, the parent is not green: {detail}"
    if mutant is None:
        return "error", "the mutant was not run"
    states = {lane: lane_state(r) for lane, r in mutant["lanes"].items()}
    if any(st == "failed" for st in states.values()):
        names = [n for r in mutant["lanes"].values() for n in r["names"]]
        return "red", ", ".join(names[:12]) + (f" (+{len(names) - 12} more)" if len(names) > 12 else "")
    if any(st == "error" for st in states.values()):
        lanes = ", ".join(lane for lane, st in states.items() if st == "error")
        return "error", f"NO TEST FAILED: {lanes} did not build or ran no test; this proves nothing"
    ran = sum(r["ran"] for r in mutant["lanes"].values())
    return "green", f"SURVIVED: {ran} tests passed, none caught this change"


def env_list(name: str, check) -> list[str]:
    vals = os.environ.get(name, "").split()
    for v in vals:
        if not check(v):
            raise Refused(f"{name}: refused value {v!r}")
    return vals


def cmd_run(phase: str) -> int:
    if phase not in ("base", "mutant"):
        raise Refused(f"phase {phase!r}")
    lanes = env_list("LANES", lambda v: v in LANES)
    filters = env_list("FILTERS", lambda v: bool(FILTER_RE.match(v)))
    addon = os.environ.get("ADDON_MANIFEST", "false") == "true"
    out = Path(os.environ["RESULT_DIR"])
    out.mkdir(parents=True, exist_ok=True)
    res = run_phase(phase, lanes, filters, addon, out)
    (out / f"{phase}.json").write_text(json.dumps(res, indent=1))
    states = {lane: lane_state(r) for lane, r in res["lanes"].items()}
    print(f"{phase}: " + ", ".join(f"{lane} {st} ({res['lanes'][lane]['ran']} ran)" for lane, st in states.items()))
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a") as fh:
            fh.write(f"green={'true' if all(st == 'passed' for st in states.values()) else 'false'}\n")
    return 0


def cmd_judge() -> int:
    out = Path(os.environ["RESULT_DIR"])
    load = lambda n: json.loads((out / n).read_text()) if (out / n).exists() else None  # noqa: E731
    verdict, detail = judge(load("base.json"), load("mutant.json"))
    branch = os.environ.get("BRANCH", "?")
    sha = os.environ.get("SHA", "?")[:8]
    if not (valid_branch(branch) and re.match(r"^[0-9a-f]{1,8}$", sha)):
        raise Refused("BRANCH/SHA")
    line = f"  {branch} {sha} {verdict}  {detail}"
    print(line)
    (out / "verdict.json").write_text(json.dumps({"branch": branch, "sha": sha, "verdict": verdict, "detail": detail}))
    return 0 if verdict == "red" else 1


def cmd_summary(results_dir: str) -> int:
    expected = int(os.environ.get("EXPECTED", "0"))
    rows = []
    for p in sorted(Path(results_dir).rglob("verdict.json")):
        rows.append(json.loads(p.read_text()))
    lines = ["| mutant | sha | verdict | detail |", "|---|---|---|---|"]
    icon = {"red": "🔴 red (caught)", "green": "🟢 green (SURVIVED)", "error": "⚠️ error", "base-red": "⛔ base-red"}
    for r in rows:
        detail = r["detail"].replace("|", "\\|")
        lines.append(f"| `{r['branch']}` | `{r['sha']}` | {icon.get(r['verdict'], r['verdict'])} | {detail} |")
    caught = sum(r["verdict"] == "red" for r in rows)
    lines.append("")
    lines.append(f"**{caught} of {expected} caught.**" + ("" if len(rows) == expected else
                 f" {expected - len(rows)} mutant(s) reported no result (their job did not finish)."))
    lines.append("")
    lines.append("```")
    lines += [f"  {r['branch']} {r['sha']} {r['verdict']}  {r['detail']}" for r in rows]
    lines.append("```")
    text = "\n".join(lines) + "\n"
    print(text)
    s = os.environ.get("GITHUB_STEP_SUMMARY")
    if s:
        with open(s, "a") as fh:
            fh.write("## Mutants\n\n" + text)
    return 0 if caught == expected and len(rows) == expected and expected > 0 else 1


def main(argv: list[str]) -> int:
    try:
        if argv[:1] == ["plan"]:
            return cmd_plan()
        if argv[:1] == ["run"] and len(argv) == 2:
            return cmd_run(argv[1])
        if argv[:1] == ["judge"]:
            return cmd_judge()
        if argv[:1] == ["summary"] and len(argv) == 2:
            return cmd_summary(argv[1])
    except Refused as e:
        print(f"::error::{e}")
        return 2
    print("usage: ci-mutants.py plan | run base|mutant | judge | summary <dir>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
