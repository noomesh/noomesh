#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A final CLI release re-publishes the rc's tag-neutral binaries instead of rebuilding them.

The CLI pipeline's long pole is not the CLI: it is `noo-gateway` for
x86_64-unknown-linux-musl (18-24 min in rust:1-alpine; the CLI lanes take 3-6).
A final `noo-cli-vA.B.C` is cut on main from a tree byte-identical to the
`noo-cli-vA.B.C-rc.N` it was promoted from, so rebuilding the gateway for the
final re-runs work whose result the rc already published and tested, and
produces different bits from the ones the rc proved (builds are not
reproducible).

What a final may take from the rc is only what does not carry the tag:

  REUSABLE (noo-gateway-<target>): built from gateway-rust/ with no tag, ref,
      commit or stack-tag input; it reports gateway-rust's own Cargo version.
  TAG_STAMPED, always rebuilt (both are quick):
      build          the CLI: a candidate stamps `A.B.C-rc.N` into Cargo.toml
                     (so `noo --version`, and the release it fetches node
                     assets from, are the rc's) and bakes the PAIRED stack tag
                     (`stack-vX.Y.Z-rc.N` for an rc) into STANDALONE_STACK_TAG;
      darwin-agents  noo-node-agent / noo-hostd: build-cross.sh stamps
                     `git describe --tags` and the commit via -ldflags.

Every release still regenerates the per-file `.sha256`, `sha256sums.txt` and
its signature, because the rebuilt CLI binaries are in that manifest. The
signature covers the manifest bytes only (no tag), so a consumer (install.sh,
`noo upgrade`, `noo cluster provision`) verifies a re-published gateway
exactly as it verifies a built one.

The rc is reused only when ALL of these hold; anything else answers BUILD,
which is what every release did before:

  * the tag is a final `noo-cli-vA.B.C` and the repo variable CLI_RETAG is not
    `off` (the kill switch, no PR needed);
  * the NEWEST `noo-cli-vA.B.C-rc.N` has the final's tree;
  * that rc's newest noo-cli-release run, on the rc's own commit, completed
    with conclusion `success`;
  * the rc release exists, is not a draft, and carries every reusable asset,
    its `.sha256`, and the signed manifest pair.

Subcommands:

    plan    decide; writes reuse / rc_tag / why to $GITHUB_OUTPUT
    fetch   (gateway lane) download one rc asset; its bytes must hash to BOTH
            the rc's `.sha256` and the rc's `sha256sums.txt` row, else exit 1
            and the lane builds instead
    verify  (release job) the rc's manifest signature verifies with the CLI
            just built from this tree, and report, per reusable asset, whether
            this release carries the rc's exact bytes or a rebuild

Dry run against real data (read-only):

    scripts/cli-release-reuse.py plan --tag noo-cli-v0.5.89 --repo <owner>/<repo>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
WORKFLOW = "noo-cli-release.yml"
MANIFEST = "sha256sums.txt"
GATEWAY_TARGETS = ("x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl", "aarch64-apple-darwin")
REUSABLE = tuple(f"noo-gateway-{t}" for t in GATEWAY_TARGETS)
# job -> why its output can never come from the rc
TAG_STAMPED = {
    "build": "the CLI bakes A.B.C-rc.N (Cargo.toml stamp) and the paired stack tag",
    "darwin-agents": "build-cross.sh stamps git describe --tags and the commit via -ldflags",
}
FINAL_RE = re.compile(r"noo-cli-v\d+\.\d+\.\d+")


def git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout.strip()


def _token() -> str:
    tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    if not tok:
        try:
            tok = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True,
                                 check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            tok = ""
    return tok


class _DropAuthOnHostChange(urllib.request.HTTPRedirectHandler):
    """An asset download redirects to a storage host that must not see our
    bearer token (and may reject a second auth mechanism)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlparse(newurl).netloc != urllib.parse.urlparse(req.full_url).netloc:
            new.remove_header("Authorization")
        return new


_OPENER = urllib.request.build_opener(_DropAuthOnHostChange)


def _get(url: str, token: str, accept: str = "application/vnd.github+json") -> bytes:
    headers = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with _OPENER.open(urllib.request.Request(url, headers=headers), timeout=120) as r:
        return r.read()


def get_json(path: str, token: str) -> dict:
    return json.loads(_get(f"{API}{path}", token))


def rc_tags(final: str) -> list[str]:
    """`noo-cli-vA.B.C-rc.N` tags for this final, highest N first."""
    out = git("tag", "--list", f"{final}-rc.*")
    tags = [t for t in out.splitlines() if re.fullmatch(re.escape(final) + r"-rc\.\d+", t)]
    return sorted(tags, key=lambda t: int(t.rsplit(".", 1)[1]), reverse=True)


def required_assets() -> list[str]:
    return [n for a in REUSABLE for n in (a, f"{a}.sha256")] + [MANIFEST, f"{MANIFEST}.sig"]


def plan(tag: str, repo: str, token: str, *,
         tree_of=lambda ref: git("rev-parse", f"{ref}^{{tree}}"),
         commit_of=lambda ref: git("rev-parse", f"{ref}^{{commit}}"),
         list_rcs=rc_tags, api=get_json) -> dict:
    def build(why: str, rc: str = "") -> dict:
        return {"reuse": False, "rc_tag": rc, "why": why}

    if not FINAL_RE.fullmatch(tag):
        return build(f"{tag} is not a final noo-cli-vA.B.C tag (an rc and a dispatch always build)")
    if os.environ.get("CLI_RETAG", "").strip().lower() == "off":
        return build("reuse disabled by the repo variable CLI_RETAG=off")
    rcs = list_rcs(tag)
    if not rcs:
        return build(f"no {tag}-rc.N tag exists")
    rc = rcs[0]
    final_tree, rc_tree = tree_of(tag), tree_of(rc)
    if final_tree != rc_tree:
        return build(f"the newest rc {rc} has tree {rc_tree[:12]}, this tag {final_tree[:12]}", rc)
    rc_commit = commit_of(rc)

    runs = api(f"/repos/{repo}/actions/workflows/{WORKFLOW}/runs?branch={urllib.parse.quote(rc)}"
               f"&event=push&per_page=50", token).get("workflow_runs", [])
    runs = [r for r in runs if r.get("head_branch") == rc]
    if not runs:
        return build(f"no {WORKFLOW} run found for {rc}", rc)
    run = max(runs, key=lambda r: (r.get("created_at") or "", r.get("run_number") or 0))
    if run.get("head_sha") != rc_commit:
        return build(f"the newest {rc} run built {str(run.get('head_sha'))[:8]}, the tag is {rc_commit[:8]}", rc)
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return build(f"the newest {rc} run ({run.get('id')}) is {run.get('status')}/{run.get('conclusion')}", rc)

    rel = api(f"/repos/{repo}/releases/tags/{urllib.parse.quote(rc)}", token)
    if rel.get("draft"):
        return build(f"release {rc} is a draft", rc)
    have = {a.get("name") for a in rel.get("assets", []) if a.get("state", "uploaded") == "uploaded"}
    missing = [n for n in required_assets() if n not in have]
    if missing:
        return build(f"release {rc} lacks {', '.join(missing)}", rc)
    return {"reuse": True, "rc_tag": rc,
            "why": f"{rc} has this tree ({final_tree[:12]}), its run {run.get('id')} succeeded on "
                   f"{rc_commit[:8]}, and its release carries every reusable asset: "
                   f"re-publishing {', '.join(REUSABLE)}; rebuilding the tag-stamped jobs "
                   f"({', '.join(TAG_STAMPED)})"}


def _write(path: str | None, text: str) -> None:
    if path:
        with open(path, "a") as f:
            f.write(text)


def cmd_plan(a: argparse.Namespace) -> int:
    try:
        p = plan(a.tag, a.repo, _token())
    except Exception as e:  # noqa: BLE001 — any surprise means BUILD, never a guess
        p = {"reuse": False, "rc_tag": "", "why": f"planning failed ({type(e).__name__}: {e})"}
    path = "REUSE from " + p["rc_tag"] if p["reuse"] else "FULL BUILD"
    print(json.dumps(p, indent=2))
    print(f"::notice title=noo-cli release path::{a.tag}: {path} — {p['why']}")
    _write(os.environ.get("GITHUB_OUTPUT"),
           f"reuse={'true' if p['reuse'] else 'false'}\nrc_tag={p['rc_tag']}\n")
    _write(os.environ.get("GITHUB_STEP_SUMMARY"),
           f"### noo-cli release path for {a.tag}: {path}\n\n{p['why']}\n")
    return 0


def _asset_bytes(repo: str, rc: str, name: str, token: str, api=get_json, fetch=_get) -> bytes:
    rel = api(f"/repos/{repo}/releases/tags/{urllib.parse.quote(rc)}", token)
    asset = next((x for x in rel.get("assets", []) if x.get("name") == name), None)
    if asset is None:
        raise LookupError(f"release {rc} has no {name}")
    return fetch(asset["url"], token, accept="application/octet-stream")


def manifest_row(text: str, name: str) -> str | None:
    """The hex digest `sha256sum` recorded for `name`, or None."""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == name:
            return parts[0].lower()
    return None


def fetch(repo: str, rc: str, name: str, out: Path, token: str, get=None) -> str:
    """Download `name` from the rc; return its digest. Raise on ANY disagreement."""
    get = get or (lambda n: _asset_bytes(repo, rc, n, token))
    blob = get(name)
    digest = hashlib.sha256(blob).hexdigest()
    side = manifest_row(get(f"{name}.sha256").decode(), name)
    row = manifest_row(get(MANIFEST).decode(), name)
    if side is None or row is None:
        raise ValueError(f"{rc}: no digest for {name} in {'its .sha256' if side is None else MANIFEST}")
    if not digest == side == row:
        raise ValueError(f"{rc}/{name}: bytes {digest[:16]}, .sha256 {side[:16]}, {MANIFEST} {row[:16]} — not re-publishing")
    out.mkdir(parents=True, exist_ok=True)
    dest = out / name
    dest.write_bytes(blob)
    dest.chmod(0o755)
    return digest


def cmd_fetch(a: argparse.Namespace) -> int:
    try:
        d = fetch(a.repo, a.rc_tag, a.asset, Path(a.out), _token())
    except Exception as e:  # noqa: BLE001 — the lane builds instead
        print(f"::warning title=noo-cli reuse::{a.asset}: cannot re-publish from {a.rc_tag} "
              f"({type(e).__name__}: {e}) — this lane builds it")
        return 1
    print(f"re-published {a.asset} from {a.rc_tag}: sha256 {d} (matches its .sha256 and {MANIFEST})")
    _write(os.environ.get("GITHUB_OUTPUT"), "reused=true\n")
    _write(os.environ.get("GITHUB_STEP_SUMMARY"), f"- `{a.asset}`: re-published from {a.rc_tag} (`{d}`)\n")
    return 0


def verify(rc: str, dist: Path, noo: str, get, run=subprocess.run) -> tuple[list[str], list[str]]:
    """Prove the rc manifest is the pipeline's; return (reused, rebuilt) asset names.

    A reusable asset in `dist` whose bytes equal the rc manifest's row is
    re-published; any other digest is a lane that fell back to building.
    Raises when the signature does not verify.
    """
    work = dist.parent / "rc-manifest"
    work.mkdir(parents=True, exist_ok=True)
    (work / MANIFEST).write_bytes(get(MANIFEST))
    (work / f"{MANIFEST}.sig").write_bytes(get(f"{MANIFEST}.sig"))
    r = run([noo, "security", "release-verify", str(work / MANIFEST), str(work / f"{MANIFEST}.sig")],
            capture_output=True, text=True)
    if r.returncode != 0:
        raise ValueError(f"{rc}/{MANIFEST} signature does not verify: {(r.stdout + r.stderr).strip()}")
    rc_text = (work / MANIFEST).read_text()
    reused, rebuilt = [], []
    for name in REUSABLE:
        digest = hashlib.sha256((dist / name).read_bytes()).hexdigest()
        (reused if manifest_row(rc_text, name) == digest else rebuilt).append(name)
    return reused, rebuilt


def cmd_verify(a: argparse.Namespace) -> int:
    token = _token()
    try:
        reused, rebuilt = verify(a.rc_tag, Path(a.dist), a.noo,
                                 lambda n: _asset_bytes(a.repo, a.rc_tag, n, token))
    except Exception as e:  # noqa: BLE001 — never publish bytes we cannot prove
        print(f"::error::{type(e).__name__}: {e}. Re-run with `gh variable set CLI_RETAG --body off` "
              "(the WHOLE run, not --failed) to build everything.")
        return 1
    note = (f"{', '.join(reused)} re-published byte-for-byte from {a.rc_tag} (same tree; "
            f"its signed {MANIFEST} verified)" if reused else "all built by this run")
    if rebuilt:
        note += f"; rebuilt: {', '.join(rebuilt)}"
    print(f"::notice title=noo-cli release path::{note}")
    _write(os.environ.get("GITHUB_OUTPUT"), f"note={note}\n")
    _write(os.environ.get("GITHUB_STEP_SUMMARY"), f"\n**Gateway binaries:** {note}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    p = sub.add_parser("plan")
    p.add_argument("--tag", required=True)
    p.add_argument("--repo", default=repo, required=not repo)
    f = sub.add_parser("fetch")
    f.add_argument("--rc-tag", required=True)
    f.add_argument("--asset", required=True, choices=REUSABLE)
    f.add_argument("--out", default="dist")
    f.add_argument("--repo", default=repo, required=not repo)
    v = sub.add_parser("verify")
    v.add_argument("--rc-tag", required=True)
    v.add_argument("--dist", default="dist")
    v.add_argument("--noo", required=True, help="the CLI built by this run (carries the release keys)")
    v.add_argument("--repo", default=repo, required=not repo)
    a = ap.parse_args(argv)
    return {"plan": cmd_plan, "fetch": cmd_fetch, "verify": cmd_verify}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
