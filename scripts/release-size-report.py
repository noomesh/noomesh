#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Size report for a stack release: what we ship, and what a node downloads
to upgrade to it (noomesh-internal i673).

    scripts/release-size-report.py [--tag stack-vX.Y.Z] [--prev stack-vX.Y.Z] [--json OUT]

Defaults: the newest final stack release and the final before it. Read-only:
registry manifests (`docker buildx imagetools inspect --raw`) and release
metadata (`gh`); nothing is pulled.

Per image and platform in the release's signed lock, for the images WE
build (scripts/release-image-inputs.json):
  total_bytes    compressed layers of the image
  own_bytes      layers not in its base (the last FROM of its Dockerfile at
                 the tag; "?" when the base cannot be resolved, never a guess)
  upgrade_bytes  layers whose digest is not in the previous final's image for
                 the same platform: what an upgrading node downloads
Plus the CLI release assets' sizes. Totals per platform at the end.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

ROOT = __import__("pathlib").Path(__file__).resolve().parent.parent


def release_image_namespace() -> str:
    """The release image namespace from its one home, scripts/lib-dist.sh
    (`release_image_namespace`), never typed out here
    (tests/test_image_namespace_declarations.py)."""
    text = (ROOT / "scripts" / "lib-dist.sh").read_text()
    m = re.search(r"^release_image_namespace\(\)\s*\{\s*printf\s+'([^']+)';\s*\}", text, re.M)
    if not m:
        raise SystemExit("scripts/lib-dist.sh: release_image_namespace() not found in its one-line printf form")
    return m.group(1)


OURS = release_image_namespace()
DHI = f"{OURS}/dhi"      # the DHI mirror the release builds from (DHI_OWNER)
HUB = f"{OURS}/mirror"   # the Docker Hub mirror (scripts/hub-mirror.py)


def repo() -> str:
    """This repository: GITHUB_REPOSITORY in CI, else the checkout's own."""
    import os
    return os.environ.get("GITHUB_REPOSITORY") or sh("gh", "repo", "view", "--json", "nameWithOwner",
                                                     "-q", ".nameWithOwner").strip()


def sh(*cmd: str) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=180).stdout


# ---------------------------------------------------------------- pure parts

def parse_lock(text: str) -> dict[str, str]:
    """`name@sha256:...` rows of a stack lock (comments and key: rows skipped)."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^([a-z0-9][a-z0-9._-]*)@(sha256:[0-9a-f]{64})$", line.strip())
        if m:
            out[m.group(1)] = m.group(2)
    return out


def final_from(dockerfile: str) -> str | None:
    """The image reference of the LAST `FROM` (the stage that ships)."""
    froms = [l for l in dockerfile.splitlines() if re.match(r"^\s*FROM\s", l, re.I)]
    if not froms:
        return None
    toks = [t for t in froms[-1].split()[1:] if not t.startswith("--")]
    return toks[0] if toks else None


def resolve_base(ref: str | None, bases: dict[str, str]) -> str | None:
    """A Dockerfile FROM reference as a pullable `repo@digest`, or None."""
    if not ref:
        return None
    for var, digest_key, repo in (("${DEPS_CORE}", "deps-core", f"{DHI}/deps-core"),
                                  ("${DEPS_BASE}", "deps-base", f"{DHI}/deps-base")):
        if ref == var:
            return f"{repo}@{bases[digest_key]}" if digest_key in bases else None
    ref = ref.replace("${DHI_REGISTRY}", DHI).replace("${HUB_MIRROR}", HUB)
    if "${" in ref or "@sha256:" not in ref:
        return None  # an unpinned or unresolvable base: say "?", never guess
    name, digest = ref.split("@", 1)
    if ":" in name.rsplit("/", 1)[-1]:
        name = name.rsplit(":", 1)[0]
    return f"{name}@{digest}"


def sizes(layers: list[dict], base_layers: list[dict] | None, prev_layers: list[dict] | None) -> dict:
    total = sum(l["size"] for l in layers)
    base = {l["digest"] for l in base_layers} if base_layers is not None else None
    prev = {l["digest"] for l in prev_layers} if prev_layers is not None else set()
    return {
        "total_bytes": total,
        "own_bytes": sum(l["size"] for l in layers if l["digest"] not in base) if base is not None else None,
        "upgrade_bytes": sum(l["size"] for l in layers if l["digest"] not in prev),
    }


def platforms_of(index: dict, fetch) -> dict[str, list[dict]]:
    """{os/arch: layers} of an image index (or a single manifest)."""
    if "manifests" not in index:
        return {"single": index.get("layers", [])}
    out = {}
    for m in index["manifests"]:
        p = m.get("platform") or {}
        if p.get("architecture") in (None, "unknown"):
            continue
        out[f"{p['os']}/{p['architecture']}"] = fetch(m["digest"]).get("layers", [])
    return out


# ---------------------------------------------------------------- IO

def inspect_raw(ref: str) -> dict:
    return json.loads(sh("docker", "buildx", "imagetools", "inspect", "--raw", ref))


def image_layers(repo: str, digest: str) -> dict[str, list[dict]]:
    return platforms_of(inspect_raw(f"{repo}@{digest}"), lambda d: inspect_raw(f"{repo}@{d}"))


def finals(prefix: str) -> list[str]:
    rows = json.loads(sh("gh", "release", "list", "-R", repo(), "--limit", "60",
                         "--json", "tagName,isPrerelease,isDraft"))
    tags = [r["tagName"] for r in rows if r["tagName"].startswith(prefix)
            and not r["isPrerelease"] and not r["isDraft"]]
    key = lambda t: tuple(int(x) for x in re.findall(r"\d+", t))  # noqa: E731
    return sorted(tags, key=key, reverse=True)


def asset_text(tag: str, name: str) -> str:
    return sh("gh", "release", "download", tag, "-R", repo(), "-p", name, "-O", "-")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tag")
    ap.add_argument("--prev")
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    stack = finals("stack-v")
    tag = a.tag or stack[0]
    if a.prev:
        prev = a.prev
    elif tag in stack and stack.index(tag) + 1 < len(stack):
        prev = stack[stack.index(tag) + 1]  # the final before it (newest first)
    else:
        prev = None
    lock = parse_lock(asset_text(tag, f"{tag}.lock"))
    plock = parse_lock(asset_text(prev, f"{prev}.lock")) if prev else {}
    bases = parse_lock(asset_text(tag, f"{tag}.bases"))
    table = json.loads(sh("git", "show", f"{tag}:scripts/release-image-inputs.json"))["images"]
    rows = []
    for name, spec in sorted(table.items()):
        if name not in lock:
            continue
        repo = f"{OURS}/{name}"
        layers = image_layers(repo, lock[name])
        prev_layers = image_layers(repo, plock[name]) if name in plock else {}
        try:
            base_ref = resolve_base(final_from(sh("git", "show", f"{tag}:{spec['dockerfile']}")), bases)
        except subprocess.CalledProcessError:
            base_ref = None
        base_layers = {}
        if base_ref:
            try:
                base_layers = image_layers(*base_ref.split("@", 1))
            except (subprocess.CalledProcessError, json.JSONDecodeError):
                base_ref = None
        for plat, ls in layers.items():
            s = sizes(ls, base_layers.get(plat) if base_ref else None, prev_layers.get(plat))
            rows.append({"image": name, "platform": plat, "base": base_ref, **s})
    cli = json.loads(sh("gh", "release", "view", tag.replace("stack-", "noo-cli-"), "-R", repo(),
                        "--json", "assets"))["assets"]
    assets = {x["name"]: x["size"] for x in cli if not x["name"].endswith((".sha256", ".sig", ".txt"))}
    mb = lambda b: "?" if b is None else f"{b / 1e6:.1f}"  # noqa: E731
    print(f"## Release size: {tag} (upgrade from {prev or 'none'})\n")
    print("| image | platform | total MB | own MB | upgrade MB |\n|---|---|---|---|---|")
    for r in rows:
        print(f"| {r['image']} | {r['platform']} | {mb(r['total_bytes'])} | {mb(r['own_bytes'])} | {mb(r['upgrade_bytes'])} |")
    for plat in sorted({r["platform"] for r in rows}):
        up = sum(r["upgrade_bytes"] for r in rows if r["platform"] == plat)
        print(f"\n**{plat}: a node running every image downloads {mb(up)} MB to upgrade** (upper bound: a node runs a subset)")
    print("\n| CLI asset | MB |\n|---|---|")
    for n, b in sorted(assets.items()):
        print(f"| {n} | {mb(b)} |")
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"tag": tag, "prev": prev, "images": rows, "cli_assets": assets}, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
