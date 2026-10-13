#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Publish the gateway's OpenAPI spec to the console's contract (`ui/`).

DIRECTION MATTERS, and it is the opposite of what this repo used to do.

`sync-ui.sh` (retired with the vendored console, #684) rsynced mesh-UI's
packaged `dist/static/` over `src/noomesh/gateway/static/` — and because
mesh-UI symlinks `contracts/openapi.json` into `src/static/`, that rsync
silently carried its contract INTO the gateway. The file the gateway served,
and that `check-openapi-drift.py` validates its own routes against, was
downstream of the front end describing them.

THE ARBITER IS THE ROUTER, NOT EITHER SPEC.

The obvious implementation — copy the gateway's spec over the contract — is
wrong, and measurably so. The gateway's spec documents 239 of its 338 routes;
the mesh-UI contract documents ~40 routes the gateway spec has never covered
(`/api/external/*`, `/api/cluster/mint-join-key`, `/api/logs/tail`,
`/api/mesh/restart`, …). Those routes all EXIST — they are just among the
102 the gateway spec has not caught up with. A copy would delete real,
correct documentation and break the UI's typecheck, which is exactly the
failure the old direction had, pointed the other way.

So this merges, arbitrated by `.route(…)` registrations:

  path served by a route, documented in the gateway spec  → gateway entry wins
  path served by a route, documented only in the contract → contract entry kept
  path served by a route, documented nowhere              → stays undocumented
  path in a spec that NO route serves                     → reported, never
                                                            silently dropped

That last case is the one that needs a human. A phantom is either genuinely
retired, or a route the UI needs that the gateway has not built yet — the
contract has deliberately carried the latter before, flagged in its
description. Deleting one of those breaks the UI quietly, so this prints them
and leaves them alone unless you pass --prune.

    scripts/export-openapi.py                  # merge into ui/, in this tree
    scripts/export-openapi.py /path/to/repo    # a checkout elsewhere
    scripts/export-openapi.py --check          # report only, exit 1 if stale
    scripts/export-openapi.py --prune          # also drop phantoms (read them first)

THE CLONE IS GONE — this is the monorepo now. The console lives at `ui/`, so
the default target is `ui/` in this tree and both specs are read from one
working copy. The LOCATIONS did not change, exactly as this docstring
predicted; only the clone did.

Worth recording: the clone could not have worked for some time. REPO_URL named
`noo-mesh-ui` (under the old org), which is a 404 — the repository was
`pai-mesh-ui`. Only the explicit-local-checkout form ever ran. A default path
that no one exercises rots silently, and this one rotted into a repository
name that has never existed.
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "src" / "noomesh" / "gateway" / "static" / "openapi.json"
RUST_SRC = ROOT / "gateway-rust" / "src"
DEST_REL = "contracts/openapi.json"
# The console, in this tree. `target` still overrides it for a checkout
# elsewhere, which is the only reason the argument survives.
UI_ROOT = ROOT / "ui"

ROUTE_RE = re.compile(r'\.route\(\s*"([^"]+)"')
# Add-on routes are NOT part of the public contract. An HTTP add-on ships its
# own route manifest and the gateway mounts it at runtime (addon_proxy.rs), so
# the core tree has nothing to read and the console's contract carries core
# routes only. An add-on's console surface types its routes from its own
# manifest.
NEST_RE = re.compile(r'\.nest\(\s*"')


def rust_routes() -> set[str]:
    """Every path registered with `.route("…")`, the same extraction
    `check-openapi-drift.py` uses — deliberately, so the two agree on what
    "exists" means."""
    routes: set[str] = set()
    nested: list[str] = []
    for path in sorted(RUST_SRC.rglob("*.rs")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        if NEST_RE.search(text):
            nested.append(str(path.relative_to(ROOT)))
        routes.update(m.group(1) for m in ROUTE_RE.finditer(text) if m.group(1).startswith("/"))
    if nested:
        sys.exit(
            "export-openapi: `.nest(` found in " + ", ".join(nested) +
            "\nRoute strings are no longer full paths; this merge would drop "
            "every path it cannot match. Teach it to resolve prefixes first."
        )
    return routes


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=collections.OrderedDict)


def merge(spec: dict, contract: dict, routes: set[str], prune: bool) -> tuple[dict, dict]:
    """Return (merged contract, report)."""
    out = json.loads(json.dumps(spec), object_pairs_hook=collections.OrderedDict)
    sp, cp = spec.get("paths", {}), contract.get("paths", {})

    kept_from_contract = sorted(p for p in cp if p not in sp and p in routes)
    phantoms = sorted(p for p in set(sp) | set(cp) if p not in routes)
    added = sorted(p for p in sp if p not in cp)

    merged = collections.OrderedDict()
    for p, item in sp.items():
        if p in routes or not prune:
            merged[p] = item
    # Contract-only entries for real routes: documentation the gateway spec
    # has not caught up with. Appended rather than interleaved — they are
    # exactly the set the next person should be moving INTO the gateway spec.
    for p in kept_from_contract:
        merged[p] = cp[p]
    if not prune:
        for p in cp:
            if p not in merged and p not in routes:
                merged[p] = cp[p]

    out["paths"] = merged
    return out, {"added": added, "kept_from_contract": kept_from_contract, "phantoms": phantoms}


def main() -> int:
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("target", nargs="?", help="a console checkout elsewhere (default: ui/ in this tree)")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--prune", action="store_true")
    ap.add_argument("-h", "--help", action="store_true")
    args = ap.parse_args()
    if args.help:
        print(__doc__)
        return 0

    if not SPEC.exists():
        print(f"error: {SPEC} not found", file=sys.stderr)
        return 1

    if args.target:
        repo = Path(args.target)
        print(f"Using local checkout: {repo}")
    else:
        repo = UI_ROOT
        print(f"Using the console in this tree: {repo.relative_to(ROOT)}")

    dest = repo / DEST_REL
    if not dest.exists():
        print(f"error: {dest} not found — is that a console checkout?", file=sys.stderr)
        return 1

    routes = rust_routes()
    merged, rep = merge(load(SPEC), load(dest), routes, args.prune)

    print(f"\n{len(routes)} routes registered · {len(merged['paths'])} paths in the merged contract")
    if rep["added"]:
        print(f"\nFrom the gateway spec, new to the contract ({len(rep['added'])}):")
        for p in rep["added"]:
            print(f"  + {p}")
    if rep["kept_from_contract"]:
        print(f"\nKept from the contract — real routes the gateway spec has not "
              f"documented ({len(rep['kept_from_contract'])}):")
        for p in rep["kept_from_contract"]:
            print(f"  = {p}")
        print("  These are the backlog for moving documentation into the gateway.")
    if rep["phantoms"]:
        verb = "DROPPED (--prune)" if args.prune else "kept — no route serves them"
        print(f"\nPhantoms, {verb} ({len(rep['phantoms'])}):")
        for p in rep["phantoms"]:
            print(f"  ? {p}")
        if not args.prune:
            print("  Either genuinely retired, or a route the UI needs that does not")
            print("  exist yet. Read them before passing --prune.")

    body = json.dumps(merged, indent=2, ensure_ascii=True) + "\n"
    if args.check:
        if body == dest.read_text(encoding="utf-8"):
            print("\nContract is up to date.")
            return 0
        print("\nContract is STALE — run scripts/export-openapi.py to update it.", file=sys.stderr)
        return 1

    dest.write_text(body, encoding="utf-8")
    print(f"\nWrote {DEST_REL}")
    print("\nFinish in ui/ — same tree now, no PR to another repo:")
    print("  npm run gen:api          # regenerate packages/api/src/schema.d.ts")
    print("  npm run typecheck        # a removed path breaks its callers HERE")
    print("  npm run audit:contract   # UI calls must be a subset of the contract")
    print("  # dated entry in contracts/CHANGELOG.md, then PR into dev")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
