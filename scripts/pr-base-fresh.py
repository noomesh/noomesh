#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Did this PR's CI test the base it is about to merge onto?

GitHub does not re-run a PR's checks when its base branch moves, and the dev
ruleset does not require branches to be up to date (strict status checks are
off). So a PR can be green against a base that no longer exists: #859 passed
CI on a dev without ced944e7's `spdx.py --check`, was merged after it, and
turned dev red (2026-10-09) — and a red dev newest run is exactly what the
promotion gate reads as "not proven".

Run this immediately before `gh pr merge`. It lists the commits on the base
branch that are not in the PR head and compares their committer dates (for a
rebase-merged commit, the time it landed) with the creation time of the PR's
newest CI run on its current head. A base commit that landed AFTER that run
started was not in the merge ref CI tested.

  exit 0  fresh: every base commit the PR lacks was there when CI started
  exit 1  stale: names the commits; rebase onto the base (`gh pr
          update-branch <N> --rebase`, or a fresh branch + PR where
          force-pushing is not allowed), wait for green, then merge
  exit 2  cannot tell (no CI run on this head, API error): treat as stale

Usage:  scripts/pr-base-fresh.py <PR number> [--repo owner/name] [--workflow ci.yml]

The structural fix is the ruleset setting "Require branches to be up to date
before merging" (strict_required_status_checks_policy) on the dev CI-gates
ruleset; this script is the guard that works without it.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")


class Unknown(Exception):
    pass


def _token() -> str:
    tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    if not tok:
        try:
            tok = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True,
                                 check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            tok = ""
    if not tok:
        raise Unknown("no GH_TOKEN/GITHUB_TOKEN and `gh auth token` gave none")
    return tok


def _get(path: str, token: str):
    req = urllib.request.Request(f"{API}{path}", headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise Unknown(f"GET {path}: HTTP {e.code}") from e
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        raise Unknown(f"GET {path}: {e}") from e


def check(repo: str, pr: int, workflow: str, token: str) -> tuple[int, str]:
    p = _get(f"/repos/{repo}/pulls/{pr}", token)
    if isinstance(p, dict) and p.get("merged"):
        raise Unknown(f"#{pr} is already merged — this check is for BEFORE the merge")
    try:
        head, base = p["head"]["sha"], p["base"]["ref"]
    except (KeyError, TypeError) as e:
        raise Unknown(f"unexpected PR payload: {e}") from e
    runs = _get(f"/repos/{repo}/actions/workflows/{workflow}/runs"
                f"?head_sha={head}&event=pull_request&per_page=20", token)
    runs = [r for r in (runs.get("workflow_runs") or []) if r.get("head_sha") == head]
    if not runs:
        raise Unknown(f"no {workflow} pull_request run on the PR head {head[:8]}")
    started = max(r.get("created_at") or "" for r in runs)
    cmp = _get(f"/repos/{repo}/compare/{head}...{base}", token)
    missing = cmp.get("commits") if isinstance(cmp, dict) else None
    if missing is None:
        raise Unknown("compare payload has no commits")
    if cmp.get("ahead_by", 0) > len(missing):
        raise Unknown(f"{base} is {cmp['ahead_by']} commits ahead, more than the API listed")
    late = []
    for c in missing:
        when = ((c.get("commit") or {}).get("committer") or {}).get("date") or ""
        if not when or when >= started:
            late.append(f"{c.get('sha', '?')[:8]} {when or '?'} "
                        f"{((c.get('commit') or {}).get('message') or '').splitlines()[0][:72]}")
    if late:
        return 1, (f"STALE: #{pr}'s newest {workflow} run started {started}; {len(late)} commit(s) "
                   f"landed on {base} after it and were never tested with this PR:\n  "
                   + "\n  ".join(late)
                   + f"\nRebase onto {base} (gh pr update-branch {pr} --rebase, or a fresh branch and PR "
                     "where force-pushing is not allowed), wait for green, then merge.")
    return 0, (f"fresh: #{pr} lacks {len(missing)} commit(s) of {base}, all landed before its "
               f"newest {workflow} run started ({started})")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("pr", type=int)
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"),
                    help="owner/name (default: $GITHUB_REPOSITORY, else the gh repo of the cwd)")
    ap.add_argument("--workflow", default="ci.yml")
    a = ap.parse_args(argv)
    if not a.repo:
        try:
            a.repo = subprocess.run(["gh", "repo", "view", "--json", "nameWithOwner", "-q",
                                     ".nameWithOwner"], capture_output=True, text=True,
                                    check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            a.repo = ""
    if not a.repo:
        print("pr-base-fresh: CANNOT TELL (no --repo, $GITHUB_REPOSITORY or gh repo) — treat as stale",
              file=sys.stderr)
        return 2
    try:
        rc, msg = check(a.repo, a.pr, a.workflow, _token())
    except Unknown as e:
        print(f"pr-base-fresh: CANNOT TELL ({e}) — treat as stale", file=sys.stderr)
        return 2
    print(f"pr-base-fresh: {msg}", file=sys.stderr if rc else sys.stdout)
    return rc


if __name__ == "__main__":
    sys.exit(main())
