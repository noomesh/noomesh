#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Refuse a CLI tag whose window since the paired stack tag holds stack code.

A release is a pair: `stack-vX.Y.Z` (images) cut first, then `noo-cli-vA.B.C`
(binary; it bakes the stack tag it pairs with). A commit merged between the
two tags is in the CLI tag's history but NOT in the stack tag's, so:

  - it touches `noo-cli/`  -> ships (the CLI tag builds it);
  - it touches code that goes into an image (gateway, UI, node-agent, ...)
    -> ships in NEITHER artifact: the stack images predate it and the CLI
    binary carries no image. Nothing else notices.

This script lists exactly those commits: `<stack-tag>..<cli-ref>` that touch
a stack-shipping path. Direction matters: only commits in the CLI ref and not
in the stack tag are lost; the reverse (stack tag newer than the CLI ref)
loses nothing, the CLI just pairs with a later stack.

Exit 0: clean (or nothing to compare). Exit 1: stack code in the window.
Exit 2: cannot answer (bad ref, no git) - never reported as clean.

Acknowledging a commit ("it rides the next stack tag", stated plainly): pass
`--ack <sha-prefix>` (repeatable). An ack that matches no window commit is an
error, so a stale ack cannot linger.

Usage: check-tag-window.py [--stack-tag stack-vX] [--cli-ref noo-cli-vY|HEAD]
       [--repo DIR] [--ack SHA]...
Defaults: newest `stack-v*` tag (sort -V, as noo-cli-release.yml pairs it),
cli-ref HEAD.
"""
import argparse
import re
import subprocess
import sys

# Paths whose contents are baked into a published image (see the COPY lines
# in docker/Dockerfile.* and images-release.yml). Editable: add a path here
# when an image starts consuming it. `noo-cli/` and the compose files are NOT
# here - the CLI binary ships those itself. `configs/` stays listed although
# the CLI ships some of it too (configs/grafana etc. are standalone assets the
# CLI materialises - stack-v0.2.85's Grafana hole came through that path):
# listing it can only raise a false alarm, which is the safe direction.
STACK_PATHS = (
    "ui/",
    "gateway-rust/",
    "node-agent-go/",
    "docker/",
    "src/",
    "config/",
    "configs/",
    "pyproject.toml",
)


class GitError(Exception):
    pass


def git(repo, *args):
    p = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise GitError(f"git {' '.join(args)}: {p.stderr.strip()}")
    return p.stdout


def newest_stack_tag(repo):
    # A release candidate (`stack-vX.Y.Z-rc.N`, cut on staging) is never what
    # a CLI release pairs with, and its numeric key would outrank the final
    # `stack-vX.Y.Z` it precedes. Only final tags compete.
    tags = [t for t in git(repo, "tag", "-l", "stack-v*").split() if "-rc." not in t]

    def key(t):
        return [int(x) for x in re.findall(r"\d+", t)]

    return max(tags, key=key) if tags else None


def window_commits(repo, stack_tag, cli_ref):
    """[(sha, subject, [stack paths touched])] for commits in the CLI ref and
    not in the stack tag, restricted to those touching a stack path."""
    out = git(repo, "log", "--no-merges", "--format=%x00%H %s", "--name-only",
              f"{stack_tag}..{cli_ref}")
    found = []
    for block in out.split("\x00")[1:]:
        head, _, files = block.partition("\n")
        sha, _, subject = head.partition(" ")
        hit = [f for f in files.split("\n") if f and f.startswith(STACK_PATHS)]
        if hit:
            found.append((sha, subject, hit))
    return found


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--stack-tag")
    ap.add_argument("--cli-ref", default="HEAD")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--ack", action="append", default=[])
    a = ap.parse_args(argv)
    try:
        stack_tag = a.stack_tag or newest_stack_tag(a.repo)
        if stack_tag is None:
            print("tag-window: no stack-v* tag exists; nothing to compare")
            return 0
        git(a.repo, "rev-parse", "--verify", "--quiet", f"{stack_tag}^{{commit}}")
        git(a.repo, "rev-parse", "--verify", "--quiet", f"{a.cli_ref}^{{commit}}")
        window = window_commits(a.repo, stack_tag, a.cli_ref)
    except (GitError, OSError) as e:
        print(f"tag-window: cannot determine the window: {e}", file=sys.stderr)
        return 2

    stale = [x for x in a.ack if not any(sha.startswith(x) for sha, _, _ in window)]
    if stale:
        print(f"tag-window: --ack matches no window commit: {', '.join(stale)}. "
              "A stale ack is an error so it cannot linger: in the release workflow, "
              "clear or update the repo variable TAG_WINDOW_ACK "
              "(gh variable set TAG_WINDOW_ACK --body '' to clear it).",
              file=sys.stderr)
        return 2
    lost = [c for c in window if not any(c[0].startswith(x) for x in a.ack)]
    if not lost:
        print(f"tag-window: {stack_tag}..{a.cli_ref} holds no unacknowledged stack code")
        return 0
    print(f"tag-window: {len(lost)} commit(s) in {stack_tag}..{a.cli_ref} touch "
          f"stack-shipping paths and are in neither artifact:", file=sys.stderr)
    for sha, subject, files in lost:
        extra = f" (+{len(files) - 3} more)" if len(files) > 3 else ""
        print(f"  {sha[:10]} {subject}\n      {', '.join(files[:3])}{extra}",
              file=sys.stderr)
    print("Either cut the stack tag again from the later commit, or state that "
          "they ride the next stack tag and re-run with --ack <sha> per commit "
          "(in the release workflow: set the repo variable TAG_WINDOW_ACK to the "
          "sha prefixes, space-separated, then re-run the job).",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
