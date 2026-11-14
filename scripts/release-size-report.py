#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Size report for a stack release: what we ship, and what a node downloads
to upgrade to it (noomesh-internal i673).

    scripts/release-size-report.py [--tag stack-vX.Y.Z] [--prev stack-vX.Y.Z] [--json OUT]
                                   [--memory [CELL=]memory.json ...]

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

--memory adds "Memory at idle (measured)": the install matrix cells'
memory.json (scripts/install-cell/memory_baseline.py, probe-memory-baseline).
A cell whose file is missing is listed as "not measured: <why>".
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


# ---------------------------------------------------------------- memory

def _baseline_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("memory_baseline", ROOT / "scripts" / "install-cell" / "memory_baseline.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MB = _baseline_module()
NODE_SHARE_LABEL = MB.NODE_SHARE_LABEL
FLEET_LINE = ("fleet, read-only: on 0.6.24+ each node agent exports its own process_resident_memory_bytes "
              "and noo_unit_memory_bytes (#1026); real-hardware node figures (robopi, the Mac) are read from "
              "the metrics door, no manual measurement.")


def load_memory(specs: list[str]) -> list[dict]:
    """`[CELL=]PATH` per cell -> {cell, measured, why | baseline}. The cell
    name is CELL=, else the file's own meta, else its artifact dir
    (install-cell-<cell>). A missing or unreadable file is "not measured"
    with the reason, never dropped."""
    from pathlib import Path
    out = []
    for spec in specs:
        cell, _, path = spec.rpartition("=") if "=" in spec else ("", "", spec)
        p = Path(path)
        dir_cell = p.parent.name.removeprefix("install-cell-")
        if not p.is_file():
            summary = p.parent / "summary.json"
            if summary.is_file():
                try:
                    s = json.loads(summary.read_text())
                    why = (f"no memory.json in the cell's artifact (cell {s.get('result', '?')}"
                           + (f" at {s['failed_step']}" if s.get("failed_step") else "") + ")")
                except (OSError, ValueError):
                    why = "no memory.json in the cell's artifact"
            elif p.parent.is_dir():
                why = "no memory.json in the cell's artifact"
            else:
                why = "no artifact from the cell (it did not run or did not upload)"
            out.append({"cell": cell or dir_cell, "measured": False, "why": why})
            continue
        try:
            doc = json.loads(p.read_text())
            doc["totals"], doc["meta"]  # noqa: B018 - the shape this report reads
        except (OSError, ValueError, KeyError, TypeError) as e:
            out.append({"cell": cell or dir_cell, "measured": False, "why": f"memory.json unreadable ({e})"})
            continue
        out.append({"cell": cell or doc["meta"].get("cell") or dir_cell, "measured": True, "baseline": doc})
    return out


def render_memory(cells: list[dict]) -> list[str]:
    mib = MB.mb
    L = ["", "## Memory at idle (measured)", "",
         "Idle after onboard: after health and verify, before the first chat. MiB. "
         "anon = process memory, file = page cache (reclaimable), current = the cgroup's memory.current; "
         "docker stats = memory.current minus inactive file. \"omitted\" = could not be read, never 0. "
         "A total marked \"n of m\" covers only the figures that were measured.", "",
         f"_{FLEET_LINE}_"]
    for c in cells:
        if not c["measured"]:
            L += ["", f"### {c['cell']}: not measured: {c['why']}"]
            continue
        d = c["baseline"]
        m = d["meta"]
        L += ["", f"### {c['cell']}: {d.get('idle') or 'unknown: memory.json predates the loaded-model check'}",
              f"noo `{m.get('noo_version', '?')}` · model {m.get('model', '?')} · settled {m.get('settle_seconds', '?')} s"
              f" · host RAM {mib(m.get('host_mem_total_bytes'))} MiB · {m.get('timestamp', '?')}", "",
              "| container | class | anon | file | current | docker stats | image |", "|---|---|---|---|---|---|---|"]
        for x in d.get("containers", []):
            L.append(f"| {x['name']} | {x.get('class', '?')} | " + " | ".join(MB._cell(x, k) for k in MB.CONTAINER_FIGURES)
                     + f" | {x.get('image', '?')} |")
        if d.get("containers_omitted"):
            L.append(f"\ncontainers: {d['containers_omitted']}")
        L += ["", "| host unit | anon | file | current | peak | VmRSS |", "|---|---|---|---|---|---|"]
        for u in d.get("host_units", []):
            if not u.get("present"):
                L.append(f"| {u['unit']} | absent: {u.get('why', '?')} | | | | |")
            else:
                L.append(f"| {u['unit']} | " + " | ".join(MB._cell(u, k) for k in MB.UNIT_FIGURES) + " |")
        omitted = [f"{e.get('name') or e.get('unit')} {k}: {why}"
                   for e in d.get("containers", []) + d.get("host_units", []) for k, why in e.get("omitted", {}).items()]
        if omitted:
            L += ["", "Omitted: " + "; ".join(omitted)]
        t = d["totals"]
        L += ["", "| total | anon | file | current |", "|---|---|---|---|"]
        for key, label in (("containers", "all containers"), ("host_units", "all host units"),
                           ("grand", "**grand total**"), ("controller_share", "controller share"),
                           ("node_share", f"**{NODE_SHARE_LABEL}**")):
            L.append(f"| {label} | " + " | ".join(MB._tot(t[key][k]) for k in MB.TOTAL_FIGURES) + " |")
    return L


def memory_json(cells: list[dict]) -> dict:
    return {"fleet": FLEET_LINE, "node_share_label": NODE_SHARE_LABEL,
            "cells": [{"cell": c["cell"], "measured": False, "why": c["why"]} if not c["measured"]
                      else {"cell": c["cell"], "measured": True, **{k: c["baseline"].get(k) for k in
                            ("idle", "models_loaded", "meta", "containers", "containers_omitted", "host_units", "totals")
                            if k in c["baseline"]}}
                      for c in cells]}


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
    ap.add_argument("--memory", nargs="+", default=[], metavar="[CELL=]memory.json",
                    help="install-matrix cells' memory.json: adds 'Memory at idle (measured)'")
    a = ap.parse_args(argv)
    mem = load_memory(a.memory) if a.memory else None
    # Memory first, and kept when the registry half fails: it comes from the
    # cells' own files, so a gh or registry error must not hide it.
    if mem is not None:
        print("\n".join(render_memory(mem)) + "\n")
    try:
        return _size(a, mem)
    except Exception:
        if mem is not None and a.json:
            with open(a.json, "w") as f:
                json.dump({"memory": memory_json(mem), "size_error": "the size half failed; see the job log"}, f, indent=1)
        raise


def _size(a, mem) -> int:
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
        image_repo = f"{OURS}/{name}"
        layers = image_layers(image_repo, lock[name])
        prev_layers = image_layers(image_repo, plock[name]) if name in plock else {}
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
        doc = {"tag": tag, "prev": prev, "images": rows, "cli_assets": assets}
        if mem is not None:
            doc["memory"] = memory_json(mem)
        with open(a.json, "w") as f:
            json.dump(doc, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
