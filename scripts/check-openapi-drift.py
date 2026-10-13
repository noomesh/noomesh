#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Fail when the gateway's routes and its OpenAPI spec disagree.

The spec is hand-maintained: FastAPI used to generate it, that generator left
with the Python gateway, and nothing replaced it. By 2026-08-09 it had drifted
to 101 registered routes with no spec entry. This does not fix that — it stops
it getting worse, which is the cheap half and can land today.

Two directions are checked:

  undocumented  a route is registered in Rust with no matching spec path
  phantom       the spec advertises a path no route serves

Both are baselined. The baseline is the drift that existed when this check was
introduced; the check fails only on drift added *after* it. Shrink the baseline
as routes get documented — never grow it to make a build pass.

    scripts/check-openapi-drift.py             # verify against the baseline
    scripts/check-openapi-drift.py --update    # rewrite the baseline
    scripts/check-openapi-drift.py --strict    # ignore the baseline (goal state)

Routes are the `.route("…")` calls in Rust. An HTTP add-on's routes are not
part of this spec: the add-on ships its own manifest and the gateway mounts it
at runtime (`addon_proxy.rs`), so the public contract is core routes only.

Rust extraction relies on axum route strings being complete paths. That holds
because the router uses no `.nest()` — asserted below, since a future `.nest()`
would silently truncate paths and make this check lie.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUST_SRC = ROOT / "gateway-rust" / "src"
SPEC = ROOT / "src" / "noomesh" / "gateway" / "static" / "openapi.json"
BASELINE = ROOT / "scripts" / "openapi-drift-baseline.json"

ROUTE_RE = re.compile(r'\.route\(\s*"([^"]+)"')
NEST_RE = re.compile(r'\.nest\(\s*"')


def rust_routes() -> set[str]:
    """Every path registered with `.route("…")` under gateway-rust/src."""
    routes: set[str] = set()
    nested: list[str] = []
    for path in sorted(RUST_SRC.rglob("*.rs")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        if NEST_RE.search(text):
            nested.append(str(path.relative_to(ROOT)))
        for m in ROUTE_RE.finditer(text):
            p = m.group(1)
            if p.startswith("/"):
                routes.add(p)
    if nested:
        # Not a warning. With .nest() the extracted strings are suffixes, so
        # every comparison below becomes meaningless — better to stop than to
        # report a confident, wrong answer.
        sys.exit(
            "check-openapi-drift: `.nest(` found in "
            + ", ".join(nested)
            + "\nRoute strings are no longer full paths; teach this script to "
            "resolve prefixes before trusting it again."
        )
    return routes


def spec_paths() -> set[str]:
    doc = json.loads(SPEC.read_text(encoding="utf-8"))
    return set(doc.get("paths", {}))


def compute() -> tuple[list[str], list[str]]:
    routes, paths = rust_routes(), spec_paths()
    return sorted(routes - paths), sorted(paths - routes)


def load_baseline() -> dict[str, list[str]]:
    if not BASELINE.exists():
        return {"undocumented": [], "phantom": []}
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--update", action="store_true", help="rewrite the baseline")
    ap.add_argument("--strict", action="store_true", help="ignore the baseline")
    args = ap.parse_args()

    undocumented, phantom = compute()

    if args.update:
        BASELINE.write_text(
            json.dumps(
                {
                    "_comment": (
                        "Drift accepted when the check was introduced. Shrink this "
                        "as routes are documented; never grow it to pass a build."
                    ),
                    "undocumented": undocumented,
                    "phantom": phantom,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(
            f"baseline updated: {len(undocumented)} undocumented, "
            f"{len(phantom)} phantom"
        )
        return 0

    base = load_baseline()
    known_undoc = set() if args.strict else set(base.get("undocumented", []))
    known_phantom = set() if args.strict else set(base.get("phantom", []))

    new_undoc = [p for p in undocumented if p not in known_undoc]
    new_phantom = [p for p in phantom if p not in known_phantom]
    fixed = sorted((known_undoc - set(undocumented)) | (known_phantom - set(phantom)))

    print(
        f"routes={len(rust_routes())} spec_paths={len(spec_paths())} "
        f"undocumented={len(undocumented)} phantom={len(phantom)}"
    )

    if fixed:
        print(f"\n{len(fixed)} baselined path(s) now resolved — thank you:")
        for p in fixed[:10]:
            print(f"  + {p}")
        print("  Run --update to shrink the baseline.")

    if not new_undoc and not new_phantom:
        print("\nNo new drift.")
        return 0

    if new_undoc:
        print(f"\n{len(new_undoc)} route(s) registered with no OpenAPI entry:")
        for p in new_undoc:
            print(f"  - {p}")
    if new_phantom:
        print(f"\n{len(new_phantom)} spec path(s) with no route:")
        for p in new_phantom:
            print(f"  - {p}")

    print(
        "\nThe spec is the contract noo-mesh-ui builds against, so a missing "
        "entry surfaces there as what looks like a gateway bug.\n"
        f"Document the route in {SPEC.relative_to(ROOT)}, or remove the stale "
        "path. Do not add it to the baseline."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
