#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""SOURCE_DATE_EPOCH for an image build: the commit time of the newest commit
that touched the image's declared build inputs (or its parents' inputs).

    scripts/build-epoch.py IMAGE        # prints an integer, exit 0

WHY (2026-11-11). Our layers were never reproducible: ollama's 1688.5 MB
`COPY /out/lib/ollama/` (upstream's runners, byte-identical content) got a
new digest on every build. Two daily builds on 11-09 had the same build
fingerprint and different layer digests. So every release that took a newer
build made every node download 1.7 GB again: 2776 MB per amd64 node from
0.6.21 to 0.6.22, 1052 MB from 0.6.22 to 0.6.23.

buildx with `rewrite-timestamp=true` clamps every file time in a layer to
SOURCE_DATE_EPOCH, so an unchanged layer comes out byte-identical. The epoch
itself must not move without a reason. HEAD's commit time would move on every
dev commit and re-stamp every file a build creates or checks out, so this
takes the newest commit touching the image's OWN inputs, from
scripts/release-image-inputs.json (the table the release planner already
trusts), plus its parents' inputs, recursively.

Refuses (exit 1) on a shallow clone: there `git log` credits every file to
the shallow root, so the epoch would silently become HEAD's again.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUTS = os.path.join(ROOT, "scripts", "release-image-inputs.json")


def inputs_of(image: str, table: dict, seen: frozenset = frozenset()) -> list[str]:
    if image in seen:
        raise SystemExit(f"build-epoch: parent cycle through {image}")
    spec = table.get(image)
    if not isinstance(spec, dict) or not spec.get("inputs"):
        raise SystemExit(f"build-epoch: {image} has no declared inputs in {os.path.relpath(INPUTS, ROOT)}")
    out = list(spec["inputs"])
    for parent in spec.get("parents", []):
        out += inputs_of(parent, table, seen | {image})
    return out


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", ROOT, *args], capture_output=True, text=True, check=True).stdout.strip()


def epoch(image: str, table: dict) -> int:
    if git("rev-parse", "--is-shallow-repository") != "false":
        raise SystemExit("build-epoch: shallow clone; check out with fetch-depth: 0 "
                         "(a shallow log dates every file to the shallow root)")
    specs = [f":(glob){p}" for p in sorted(set(inputs_of(image, table)))]
    out = git("log", "-1", "--format=%ct", "HEAD", "--", *specs)
    if not out.isdigit():
        raise SystemExit(f"build-epoch: no commit touches {image}'s inputs")
    return int(out)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: build-epoch.py IMAGE", file=sys.stderr)
        return 2
    with open(INPUTS, encoding="utf-8") as f:
        table = json.load(f)["images"]
    print(epoch(argv[1], table))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
