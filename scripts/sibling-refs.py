#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Which sibling commits go with this branch of the stack repo?

The promotion line runs dev -> staging -> main in every repo at once: an rc
(cut on staging) builds the siblings from THEIR staging, a final (cut on
main) from their main, and dev tracks their dev. Anything that tests this
tree against a sibling must use the same mapping, or it tests code the
release does not ship: a job that installed trellion from its dev branch (pyproject's `@dev`) went
red on a staging->main promotion after a trellion dev merge added a
dependency. The release tree and the pinned sibling had not changed.

Two subcommands, one implementation for ci.yml and images-release.yml:

  line BASE        print the sibling branch for a stack-repo branch:
                   dev|develop -> dev, staging -> staging, main -> main;
                   anything else exits 1.
  resolve LINE [KEY ...]
                   resolve each sibling's LINE branch to a commit SHA, ONCE
                   (job outputs are fixed for a run, so a re-run uses
                   the same commits). KEYs: trellion (the
                   default). Writes `<key>_sha=<sha>` to
                   $GITHUB_OUTPUT (when set) and prints `<repo> <line> = <sha>`.

The trellion sibling is public: no token is needed. An optional $SIBLING_TOKEN
is used only if set, for a private fork. Run OUTSIDE any checkout (this script cds to a
temp dir and clears http.extraheader): actions/checkout persists
`AUTHORIZATION: basic <GITHUB_TOKEN>` in the workspace's .git/config, git
sends it in place of the PAT in the URL, and GITHUB_TOKEN cannot see
repositories outside this one. --url-template lets tests serve
local repos.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile

ORG = "personifAI"
SIBLINGS = {
    "trellion": "trellion",
}
LINES = {"dev": "dev", "develop": "dev", "staging": "staging", "main": "main"}
DEFAULT_URL = "https://github.com/{org}/{repo}"
TOKEN_URL = "https://x-access-token:{token}@github.com/{org}/{repo}"
SHA_RE = re.compile(r"[0-9a-f]{40}")


def line_for(base: str) -> str:
    try:
        return LINES[base]
    except KeyError:
        raise SystemExit(f"::error::no sibling branch for base '{base}' (expected dev, staging or main)")


def resolve(line: str, keys: list[str], url_template: str, token: str) -> dict[str, str]:
    if line not in ("dev", "staging", "main"):
        raise SystemExit(f"::error::'{line}' is not a sibling line (dev, staging or main)")
    out: dict[str, str] = {}
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    with tempfile.TemporaryDirectory() as tmp:
        for key in keys:
            if key not in SIBLINGS:
                raise SystemExit(f"::error::unknown sibling '{key}' (expected {', '.join(SIBLINGS)})")
            repo = SIBLINGS[key]
            url = url_template.format(token=token, org=ORG, repo=repo)
            p = subprocess.run(
                ["git", "-c", "http.extraheader=", "-c", "http.https://github.com/.extraheader=",
                 "ls-remote", url, f"refs/heads/{line}"],
                cwd=tmp, env=env, capture_output=True, text=True)
            fields = p.stdout.split()
            sha = fields[0] if p.returncode == 0 and fields else ""
            if not SHA_RE.fullmatch(sha):
                err = p.stderr.strip().replace(token, "***") if token else p.stderr.strip()
                raise SystemExit(f"::error::could not resolve {ORG}/{repo} {line} to a commit "
                                 f"(got '{sha}'; git said: {err})")
            out[key] = sha
            print(f"{repo} {line} = {sha}")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_line = sub.add_parser("line")
    p_line.add_argument("base")
    p_res = sub.add_parser("resolve")
    p_res.add_argument("line")
    p_res.add_argument("keys", nargs="*")
    p_res.add_argument("--url-template", default=DEFAULT_URL)
    a = ap.parse_args(argv)

    if a.cmd == "line":
        print(line_for(a.base))
        return 0

    token = "".join((os.environ.get("SIBLING_TOKEN") or "").split())
    if token and a.url_template == DEFAULT_URL:
        a.url_template = TOKEN_URL
    shas = resolve(a.line, a.keys or list(SIBLINGS), a.url_template, token)
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a") as f:
            for key, sha in shas.items():
                f.write(f"{key}_sha={sha}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
