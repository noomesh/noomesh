#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Plan a stack release: which images to RE-TAG from an earlier rc, which to build.

A final `stack-vX.Y.Z` is cut on main from a tree that is byte-identical to a
release candidate `stack-vX.Y.Z-rc.N` cut on staging — that is the promotion
model. Rebuilding every image for the final (12-23 min) re-ran work whose
result already existed, and produced DIFFERENT bits from the ones the rc
proved: builds are not reproducible, so every digest in the v0.2.99 final lock
differed from rc.1's. Re-tagging ships exactly what the candidate shipped.

The same holds for a release candidate cut again on an unchanged tree
(2026-10-22): `stack-vX.Y.Z-rc.N+1` tagged on the commit rc.N already built
(a re-cut for an add-on, a lane that failed after the images, a sibling-only
fix) re-tags rc.N's images instead of rebuilding them. For an rc tag the
candidates are the LOWER rc.M of the same version; everything below applies
unchanged (equal trees, equal sibling trees, the tag-stamped images rebuilt),
and the new tag still gets its own signed lock.

An image is RE-TAGGED from the rc only when every input it is built from is
provably the same:

  * this repo: the final tag's commit tree == the rc tag's commit tree
    (`git rev-parse <tag>^{tree}`). The highest rc.N with an equal tree wins;
  * a sibling repo (trellion): the tree of
    the SHA this run resolved from the sibling's main == the tree of the SHA
    the rc's signed lock recorded (`source:<repo>@<sha>`), compared through
    the GitHub API. Equal trees, not equal SHAs: the sibling's main is a merge
    commit of the staging commit the rc built;
  * the image's build does not stamp the TAG into its bits. Two do, and are
    always rebuilt:
      gateway     embeds mesh-ui-web:$TAG, whose console is built with
                  NOO_CONSOLE_BUILD=stack-$TAG — an rc gateway reports rc.N;
      node-agent  --build-arg NODE_AGENT_VERSION / NODE_AGENT_COMMIT are the
                  tag and its commit.

Anything else — no earlier rc with an equal tree, the rc lock missing or
unreadable, a sibling tree that differs, an image missing from the rc lock —
answers BUILD for the affected image(s). Failing open costs a rebuild; failing
closed would ship an image whose inputs nobody compared.

Output (JSON on stdout, and to $GITHUB_OUTPUT when set):

    rc_tag        "stack-vX.Y.Z-rc.N" or ""
    rc_commit     the rc tag's commit, or ""
    retag         {"image": true|false, ...} for every image the release makes
    rc_digests    {"image": "sha256:..."} from the rc lock (lock images only)

Kill switch, no PR needed: `gh variable set RELEASE_RETAG --body off` makes
every image BUILD (the previous behaviour); delete the variable to
re-enable.

Dry run against real data (read-only; `gh auth token` must reach the siblings):

    scripts/release-retag-plan.py --tag stack-v0.2.99 \\
        --sibling-sha trellion=c8cdeb38...
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
# Sibling identifiers (the `source:<id>` rows of the lock; kept stable so rc
# locks stay readable) -> the GitHub repo that holds that source today.
SIBLING_REPOS = {
    "trellion": "personifAI/trellion",
}
DEFAULT_REPO = "noomesh/noomesh"

# image -> the sibling repos whose source it is built from (beyond this tree).
# deps-base COPYs trellion; trellion FROMs deps-base. The stack release is
# core-only: add-on images are not built or locked here.
SIBLING_INPUTS: dict[str, tuple[str, ...]] = {
    "deps-core": (),
    "deps-base": ("trellion",),
    "trellion": ("trellion",),
    "sandbox": (),
    "worker": (),
    "whisper": (),
    "piper": (),
    "postgres-pgvector": (),
    "llamacpp": (),
    "stunnel": (),
    "nvidia-exporter": (),
    "gateway": (),
    "node-agent": (),
}
# Built with the tag stamped into the bits — never re-tagged (see docstring).
TAG_STAMPED = {"gateway": "embeds the console built as stack-$TAG",
               "node-agent": "NODE_AGENT_VERSION/COMMIT build args are the tag"}
# Base images the lock does not list; re-tagged by their rc TAG, not a lock digest.
NOT_IN_LOCK = {"deps-core", "deps-base"}


def git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout.strip()


def _token(env: str) -> str:
    tok = os.environ.get(env) or os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    if not tok:
        try:
            tok = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True,
                                 check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            tok = ""
    return tok


def _get(url: str, token: str, accept: str = "application/vnd.github+json") -> bytes:
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}", "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def rc_tags(final: str) -> list[str]:
    """`stack-vX.Y.Z-rc.N` tags for this final, highest N first."""
    out = git("tag", "--list", f"{final}-rc.*")
    tags = [t for t in out.splitlines() if re.fullmatch(re.escape(final) + r"-rc\.\d+", t)]
    return sorted(tags, key=lambda t: int(t.rsplit(".", 1)[1]), reverse=True)


def rc_number(tag: str) -> int:
    return int(tag.rsplit(".", 1)[1])


def candidates(tag: str, list_rcs=rc_tags) -> list[str]:
    """The rc tags a release may re-tag from, highest first: every rc of a
    final; for an rc, only the LOWER rcs of the same version (never itself:
    a re-run of rc.N must not re-tag from its own, possibly half-published,
    images)."""
    if "-rc." not in tag:
        return list(list_rcs(tag))
    version, n = tag.rsplit("-rc.", 1)
    return [t for t in list_rcs(version) if rc_number(t) < int(n)]


def fetch_asset(repo: str, rc_tag: str, suffix: str, token: str) -> str:
    rel = json.loads(_get(f"{API}/repos/{repo}/releases/tags/{rc_tag}", token))
    name = f"{rc_tag}{suffix}"
    asset = next((a for a in rel.get("assets", []) if a.get("name") == name), None)
    if asset is None:
        raise LookupError(f"release {rc_tag} has no {name}")
    return _get(asset["url"], token, accept="application/octet-stream").decode()


def fetch_lock(repo: str, rc_tag: str, token: str) -> str:
    return fetch_asset(repo, rc_tag, ".lock", token)


def fetch_bases(repo: str, rc_tag: str, token: str) -> str | None:
    """stack-<rc>.bases (deps-core/deps-base digests), or None for an rc cut
    before the workflow attached one."""
    try:
        return fetch_asset(repo, rc_tag, ".bases", token)
    except (urllib.error.URLError, LookupError, KeyError, json.JSONDecodeError):
        return None


def parse_lock(text: str) -> tuple[dict[str, str], dict[str, str]]:
    """(image -> sha256 digest, sibling repo -> source sha)."""
    images, sources = {}, {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "@" not in line:
            continue
        name, ref = line.split("@", 1)
        if name.startswith("source:"):
            sources[name[len("source:"):]] = ref
        elif ref.startswith("sha256:"):
            images[name] = ref
    return images, sources


def sibling_tree(repo: str, sha: str, token: str) -> str:
    return json.loads(_get(f"{API}/repos/{SIBLING_REPOS.get(repo, repo)}/git/commits/{sha}", token))["tree"]["sha"]


def plan(final_tag: str, repo: str, sibling_shas: dict[str, str],
         gh_token: str, sibling_token: str, lock_text: str | None = None,
         bases_text: str | None = "fetch",
         tree_of=lambda ref: git("rev-parse", f"{ref}^{{tree}}"),
         commit_of=lambda ref: git("rev-parse", f"{ref}^{{commit}}"),
         list_rcs=rc_tags, sib_tree=sibling_tree) -> dict:
    build_all = {img: False for img in SIBLING_INPUTS}
    result = {"rc_tag": "", "rc_commit": "", "retag": build_all, "rc_digests": {}, "why": {}}

    def everything(reason: str) -> dict:
        result["why"] = {img: reason for img in SIBLING_INPUTS}
        return result

    if os.environ.get("RELEASE_RETAG", "").strip().lower() == "off":
        return everything("re-tagging disabled by the repo variable RELEASE_RETAG=off")
    final_tree = tree_of(final_tag)
    rc = next((t for t in candidates(final_tag, list_rcs) if tree_of(t) == final_tree), None)
    if rc is None:
        if "-rc." in final_tag:
            return everything(f"no earlier rc of {final_tag.rsplit('-rc.', 1)[0]} has this tree ({final_tree[:12]})")
        return everything(f"no {final_tag}-rc.N has this tree ({final_tree[:12]})")
    result["rc_tag"], result["rc_commit"] = rc, commit_of(rc)
    try:
        text = lock_text if lock_text is not None else fetch_lock(repo, rc, gh_token)
    except (urllib.error.URLError, LookupError, KeyError, json.JSONDecodeError) as e:
        return everything(f"could not read {rc}.lock ({e})")
    digests, sources = parse_lock(text)
    if bases_text == "fetch":
        bases_text = fetch_bases(repo, rc, gh_token)
    bases = parse_lock(bases_text)[0] if bases_text else {}
    digests = {**digests, **{k: v for k, v in bases.items() if k in NOT_IN_LOCK}}
    result["rc_digests"] = digests

    sib_equal: dict[str, tuple[bool, str]] = {}
    for sib in sorted({s for v in SIBLING_INPUTS.values() for s in v}):
        now, then = sibling_shas.get(sib), sources.get(sib)
        if not now or not then:
            sib_equal[sib] = (False, f"{sib}: no {'resolved SHA' if not now else 'source row in the rc lock'}")
            continue
        try:
            a, b = sib_tree(sib, then, sibling_token), sib_tree(sib, now, sibling_token)
        except (urllib.error.URLError, KeyError, json.JSONDecodeError) as e:
            sib_equal[sib] = (False, f"{sib}: tree lookup failed ({e})")
            continue
        sib_equal[sib] = (a == b, f"{sib} {then[:8]}->{now[:8]} tree {'==' if a == b else '!='} "
                                  f"({a[:12]}{'' if a == b else ' vs ' + b[:12]})")

    retag, why = {}, {}
    for img, sibs in SIBLING_INPUTS.items():
        if img in TAG_STAMPED:
            retag[img], why[img] = False, f"rebuild: {TAG_STAMPED[img]}"
            continue
        if img not in NOT_IN_LOCK and img not in digests:
            retag[img], why[img] = False, f"rebuild: {rc}.lock has no {img} digest"
            continue
        bad = [sib_equal[s][1] for s in sibs if not sib_equal[s][0]]
        if bad:
            retag[img], why[img] = False, "rebuild: " + "; ".join(bad)
            continue
        retag[img] = True
        why[img] = f"re-tag from {rc}" + (": " + "; ".join(sib_equal[s][1] for s in sibs) if sibs else "")
        if img in NOT_IN_LOCK and img not in digests:
            # An rc cut before stack-<rc>.bases existed: the re-tag is checked
            # only against the rc TAG (it must still resolve), not a recorded
            # digest. Transitional; every rc cut with this workflow has it.
            why[img] += f" (no {rc}.bases: digest not cross-checked)"
    result["retag"], result["why"] = retag, why
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--tag", required=True, help="the git tag being released (stack-vX.Y.Z[-rc.N])")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPO))
    ap.add_argument("--sibling-sha", action="append", default=[], metavar="REPO=SHA",
                    help="the SHA this run resolved for a sibling (repeatable)")
    ap.add_argument("--lock-file", help="read the rc lock from a file instead of the release")
    a = ap.parse_args(argv)
    tag = "stack-" + a.tag.removeprefix("stack-")
    sibs = dict(s.split("=", 1) for s in a.sibling_sha)
    lock_text = open(a.lock_file).read() if a.lock_file else None
    try:
        p = plan(tag, a.repo, sibs, _token("GITHUB_TOKEN"), _token("SIBLING_TOKEN"), lock_text)
    except Exception as e:  # noqa: BLE001 — any surprise means BUILD, never a guess
        reason = f"planning failed ({type(e).__name__}: {e}) — building everything"
        p = {"rc_tag": "", "rc_commit": "", "rc_digests": {},
             "retag": {img: False for img in SIBLING_INPUTS},
             "why": {img: reason for img in SIBLING_INPUTS}}
    print(json.dumps(p, indent=2))
    n = sum(p["retag"].values())
    print(f"release-retag-plan: {tag}: re-tag {n} image(s) from {p['rc_tag'] or '-'}, "
          f"build {len(p['retag']) - n}", file=sys.stderr)
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            f.write(f"rc_tag={p['rc_tag']}\n")
            f.write(f"rc_commit={p['rc_commit']}\n")
            f.write(f"retag={json.dumps(p['retag'], separators=(',', ':'))}\n")
            f.write(f"rc_digests={json.dumps(p['rc_digests'], separators=(',', ':'))}\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(f"### Release plan for {tag}\n\n| image | plan |\n|---|---|\n")
            for img in sorted(p["why"]):
                f.write(f"| {img} | {p['why'][img]} |\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
