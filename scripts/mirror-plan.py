#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Read-only plan for mirror-images.yml: what a `mode=copy` dispatch would do.

The copy (`docker buildx imagetools create --tag <dest> <source@digest>`)
re-points the destination TAG at whatever digest the workflow file names. A
lane whose file digest differs from what the GHCR tag holds today would
silently move a tag someone may pull by tag. The copy job therefore only ever
ADDS or FAILS (its "Refuse to move an existing mirror tag" step), and this
plan shows, before anything runs, which it will be for every lane:

  dest ref | source ref | pinned source digest | mirror tag now | action
    absent      the tag does not exist                     -> copy (add)
    same        the tag already holds the source digest    -> skip (no-op)
    DIFFERENT   the tag holds another digest               -> FAIL (never moved)
    unreadable  401/403 anonymously: a private package, or one that does not
                exist yet (GHCR answers both the same way to an anonymous
                reader); re-read with $GHCR_TOKEN when it is set, else the
                copy job's own guard decides
    error       the registry could not be read            -> the guard decides
  A lane that copies a moving tag (no @sha256 source) or a destination two
  lanes copy is FAIL whatever the registry says.

The lanes are parsed from the workflow file itself (one source of truth);
the registry is read with GET/HEAD only (an anonymous pull token, or a
read-only $GHCR_TOKEN). Exit 0 when no lane would FAIL, 1 when one would,
2 when the workflow cannot be parsed.

  mirror-plan.py [--workflow FILE] [--owner ORG] [--summary FILE]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/mirror-images.yml"
REGISTRY = "ghcr.io"
ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class PlanError(Exception):
    pass


def lanes(text: str) -> list[dict[str, str]]:
    """The `matrix.include` lanes of mirror-images.yml, in file order:
    {source, dest, dest_org?, auth?}. Read with a line parser (no YAML
    dependency on the release runner); tests hold it equal to yaml.safe_load."""
    out: list[dict[str, str]] = []
    cur: dict[str, str] | None = None
    indent = -1
    for line in text.splitlines():
        m = re.match(r"^(\s*)- source:\s*(\S+)\s*$", line)
        if m:
            cur = {"source": m.group(2)}
            indent = len(m.group(1))
            out.append(cur)
            continue
        if cur is None:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if len(line) - len(line.lstrip()) <= indent:
            cur = None          # the lane ended: next list item, or `steps:`
            continue
        f = re.match(r"^\s*(dest|dest_org|auth):\s*(\S+)\s*$", line)
        if f:
            cur[f.group(1)] = f.group(2)
    for ln in out:
        if "dest" not in ln:
            raise PlanError(f"mirror-images.yml lane {ln['source']} has no dest")
    return out


def source_digest(source: str) -> str | None:
    """The digest a lane's source is pinned to; None for a moving tag."""
    m = re.fullmatch(r"[^@\s]+@(sha256:[0-9a-f]{64})", source)
    return m.group(1) if m else None


def dest_repo(lane: dict[str, str], owner: str) -> tuple[str, str]:
    """(`<org>/<name>`, tag) of the GHCR destination, as the copy step spells
    it: `ghcr.io/${dest_org || repository_owner}/${dest}`."""
    name, _, tag = lane["dest"].rpartition(":")
    if not name or not tag:
        raise PlanError(f"lane dest {lane['dest']!r} is not <name>:<tag>")
    return f"{lane.get('dest_org') or owner}/{name}", tag


def _http(url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, b""


def fetch_digest(repo: str, tag: str, token: str | None = None) -> tuple[str, str]:
    """(state, digest) of ghcr.io/<repo>:<tag>, read-only.
    state: present (digest = sha256 of the manifest bytes) | absent |
    unreadable | error:<why>."""
    auth = {}
    if token:
        auth["Authorization"] = "Basic " + base64.b64encode(f"x:{token}".encode()).decode()
    code, _, body = _http(f"https://{REGISTRY}/token?scope=repository:{repo}:pull&service={REGISTRY}", auth)
    if code in (401, 403):
        return "unreadable", ""
    if code != 200:
        return f"error:token HTTP {code}", ""
    bearer = json.loads(body or b"{}").get("token")
    if not bearer:
        return "error:no token in the token answer", ""
    code, hdrs, body = _http(f"https://{REGISTRY}/v2/{repo}/manifests/{tag}",
                             {"Authorization": f"Bearer {bearer}", "Accept": ACCEPT})
    if code == 404:
        return "absent", ""
    if code in (401, 403):
        return "unreadable", ""
    if code != 200:
        return f"error:manifest HTTP {code}", ""
    got = "sha256:" + hashlib.sha256(body).hexdigest()
    hdr = hdrs.get("docker-content-digest")
    if hdr and hdr != got:
        return f"error:registry says {hdr}, the bytes hash to {got}", ""
    return "present", got


def classify(want: str | None, state: str, have: str) -> tuple[str, str]:
    """(mirror column, action) for one lane."""
    if want is None:
        return (state if state != "present" else have), "FAIL (source is a moving tag, not a digest)"
    if state == "absent":
        return "absent", "copy (add)"
    if state == "present":
        if have == want:
            return "same", "skip (already the source digest)"
        return f"DIFFERENT (mirror {have})", "FAIL (would move the tag; refused)"
    if state == "unreadable":
        return "unreadable anonymously (private, or not created yet)", "guard decides at copy time"
    return state, "guard decides at copy time"


def plan(text: str, owner: str, fetch=None, token: str | None = None) -> list[dict[str, str]]:
    fetch = fetch or fetch_digest
    rows = []
    ls = lanes(text)
    seen: dict[tuple[str, str], int] = {}
    for ln in ls:
        key = dest_repo(ln, owner)
        seen[key] = seen.get(key, 0) + 1
    for ln in ls:
        repo, tag = dest_repo(ln, owner)
        want = source_digest(ln["source"])
        state, have = fetch(repo, tag)
        note = ""
        if state == "unreadable" and token:
            state, have = fetch(repo, tag, token)
            note = " [read with token: the package is not public]" if state in ("present", "absent") else ""
        mirror, action = classify(want, state, have)
        if seen[(repo, tag)] > 1:
            action = f"FAIL ({seen[(repo, tag)]} lanes copy this destination)"
        rows.append({"dest": f"{REGISTRY}/{repo}:{tag}", "source": ln["source"].split("@")[0],
                     "digest": want or "(none)", "mirror": mirror + note, "action": action})
    return rows


def render(rows: list[dict[str, str]]) -> str:
    lines = ["| dest | source | pinned source digest | mirror tag now | action |",
             "|---|---|---|---|---|"]
    for r in rows:
        mark = "**" if r["action"].startswith("FAIL") else ""
        lines.append(f"| `{r['dest']}` | `{r['source']}` | `{r['digest']}` | {mark}{r['mirror']}{mark} "
                     f"| {mark}{r['action']}{mark} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--workflow", type=Path, default=WORKFLOW)
    ap.add_argument("--owner", default=os.environ.get("GITHUB_REPOSITORY_OWNER") or "noomesh",
                    help="the copy step's default dest_org (github.repository_owner)")
    ap.add_argument("--summary", type=Path, help="also append the table here ($GITHUB_STEP_SUMMARY)")
    a = ap.parse_args(argv)
    try:
        rows = plan(a.workflow.read_text(), a.owner, token=os.environ.get("GHCR_TOKEN") or None)
    except PlanError as e:
        print(f"::error::mirror-plan: {e}", file=sys.stderr)
        return 2
    table = render(rows)
    print(table, end="")
    fails = [r for r in rows if r["action"].startswith("FAIL")]
    for r in fails:
        print(f"::error::{r['dest']}: {r['mirror']} - {r['action']}", file=sys.stderr)
    counts = {k: sum(1 for r in rows if r["action"].startswith(k)) for k in ("copy", "skip", "FAIL", "guard")}
    tail = (f"\n{len(rows)} lanes: {counts['copy']} copy, {counts['skip']} skip, "
            f"{counts['FAIL']} FAIL, {counts['guard']} unread (the copy guard decides)\n")
    print(tail, end="")
    if a.summary:
        with a.summary.open("a") as f:
            f.write("## mirror-images plan (read-only)\n\n" + table + tail)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
