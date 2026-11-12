#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Three-way merge of a conflicted OpenAPI JSON file, key by key.

    scripts/openapi-merge3.py FILE      # FILE is unmerged in the index

Two PRs that each add a route both add entries to the same few generated
JSON files, so git reports a conflict on lines that never really collide
(19 dev commits touched ui/contracts/openapi.json in the two weeks to
2026-11-11). Taking one side and regenerating is wrong here: gen-openapi.py
only ADDS stubs, so the other side's hand-written entries would be lost.

This reads the base / ours / theirs versions from the index (stages 1-3)
and merges them as JSON objects, recursively:
  - a key changed on one side only           -> that side
  - a key added on one side only             -> added
  - a key removed on one side, untouched on the other -> removed
  - the same key changed differently on both -> CONFLICT
Lists and scalars are atomic. Key order is ours, then keys only theirs has,
in theirs' order. On any conflict it prints every JSON path that collides,
writes nothing and exits 1: those need a person.
Output is written the way the generators write it (indent=2, ensure_ascii),
so a merged file passes their --check unchanged.
"""
from __future__ import annotations

import collections
import json
import subprocess
import sys

MISSING = object()


def _stage(n: int, path: str):
    p = subprocess.run(["git", "show", f":{n}:{path}"], capture_output=True, text=True)
    if p.returncode != 0:
        return MISSING
    return json.loads(p.stdout, object_pairs_hook=collections.OrderedDict)


def merge3(base, ours, theirs, path: str, conflicts: list[str]):
    if ours == theirs:
        return ours
    if base == ours:
        return theirs
    if base == theirs:
        return ours
    if all(isinstance(x, dict) for x in (ours, theirs)) and (base is MISSING or isinstance(base, dict)):
        b = base if isinstance(base, dict) else {}
        out = collections.OrderedDict()
        for k in list(ours) + [k for k in theirs if k not in ours]:
            v = merge3(b.get(k, MISSING), ours.get(k, MISSING), theirs.get(k, MISSING), f"{path}/{k}", conflicts)
            if v is not MISSING:
                out[k] = v
        return out
    conflicts.append(path or "/")
    return ours


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    path = argv[1]
    base, ours, theirs = (_stage(n, path) for n in (1, 2, 3))
    if ours is MISSING or theirs is MISSING:
        print(f"{path}: not a both-sides conflict (deleted on one side?); resolve it by hand", file=sys.stderr)
        return 1
    conflicts: list[str] = []
    merged = merge3(base, ours, theirs, "", conflicts)
    if conflicts:
        print(f"{path}: {len(conflicts)} entr{'y' if len(conflicts) == 1 else 'ies'} changed differently on both sides:", file=sys.stderr)
        for c in conflicts:
            print(f"  {c}", file=sys.stderr)
        return 1
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(merged, indent=2, ensure_ascii=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
