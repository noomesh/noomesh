#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""Which stack containers a `noo stack start` recreated, judged from their IDs.

  recreated.py snap FILE
      one line per compose container named noo-*: "name id service depends_on"
  recreated.py judge NAME BEFORE AFTER (--none | --all | --only SERVICE)
      prints ONE verdict line and exits 0 (PASS) or 1 (FAIL):
        --none          nothing recreated, created or removed
        --all           every container recreated
        --only SERVICE  SERVICE recreated; every other recreated container is
                        one compose itself recreates because it depends on SERVICE

A container that changed ID was recreated; one only in BEFORE was removed, one
only in AFTER created. Only compose containers (with a service label) count:
an agent-placed backend is not the launcher's.
"""
from __future__ import annotations

import subprocess
import sys

FMT = ('{{.Name}} {{.Id}} {{index .Config.Labels "com.docker.compose.service"}} '
       '{{index .Config.Labels "com.docker.compose.depends_on"}}')


def _docker(args: list[str]) -> str:
    for pre in (["docker"], ["sudo", "-n", "docker"]):
        try:
            r = subprocess.run(pre + args, capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0:
            return r.stdout
    raise SystemExit(f"cannot run docker {' '.join(args[:2])} (nor with sudo -n)")


def snap(path: str) -> int:
    ids = _docker(["ps", "-aq", "--filter", "name=noo-"]).split()
    rows = []
    if ids:
        for line in _docker(["inspect", "-f", FMT, *ids]).splitlines():
            parts = line.replace("<no value>", "-").split(" ", 3)
            if len(parts) >= 3 and parts[2] not in ("", "-"):
                rows.append(" ".join(p.strip() or "-" for p in (parts + ["-"])[:4]))
    with open(path, "w") as f:
        f.write("".join(r + "\n" for r in sorted(rows)))
    print(f"{len(rows)} compose containers recorded")
    return 0


def read(path: str) -> dict[str, tuple[str, str, str]]:
    """name -> (id, service, depends_on)"""
    out = {}
    with open(path) as f:
        for line in f:
            p = line.split()
            if len(p) >= 3:
                out[p[0].lstrip("/")] = (p[1], p[2], p[3] if len(p) > 3 else "-")
    return out


def judge(name: str, before: dict, after: dict, mode: str, only: str = "") -> tuple[bool, str]:
    recreated = sorted(n for n in before if n in after and before[n][0] != after[n][0])
    removed = sorted(n for n in before if n not in after)
    created = sorted(n for n in after if n not in before)
    if not before:
        return False, f"{name} FAIL: no stack container was recorded before the start"
    extra = "".join([f"; removed: {', '.join(removed)}" if removed else "",
                     f"; created: {', '.join(created)}" if created else ""])
    if mode == "none":
        if not recreated and not removed and not created:
            return True, f"{name} PASS: 0 containers recreated ({len(after)} unchanged)"
        return False, f"{name} FAIL: {len(recreated)} recreated: {', '.join(recreated) or '-'}{extra}"
    if mode == "all":
        kept = sorted(n for n in before if n in after and before[n][0] == after[n][0])
        if not kept and not removed:
            return True, f"{name} PASS: all {len(recreated)} containers recreated"
        return False, f"{name} FAIL: {len(kept)} not recreated: {', '.join(kept) or '-'}{extra}"
    target = [n for n in recreated if after[n][1] == only]
    others = [n for n in recreated if after[n][1] != only]
    # compose recreates a dependent of a recreated service itself:
    # its depends_on label reads "svc:condition:restart,…".
    stray = [n for n in others if not any(d.split(":")[0] == only for d in after[n][2].split(","))]
    if target and not stray and not removed and not created:
        dep = f" (+ {len(others)} that depend on it: {', '.join(others)})" if others else ""
        return True, f"{name} PASS: only {only} recreated{dep}; {len(after) - len(recreated)} unchanged"
    if not target:
        return False, f"{name} FAIL: {only} was not recreated (its input changed); recreated: {', '.join(recreated) or '-'}{extra}"
    return False, f"{name} FAIL: {len(stray)} recreated that do not depend on {only}: {', '.join(stray)}{extra}"


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "snap":
        return snap(argv[1])
    if len(argv) >= 5 and argv[0] == "judge" and argv[4] in ("--none", "--all", "--only"):
        mode = argv[4][2:]
        only = argv[5] if mode == "only" and len(argv) > 5 else ""
        if mode == "only" and not only:
            print(__doc__, file=sys.stderr)
            return 2
        ok, line = judge(argv[1], read(argv[2]), read(argv[3]), mode, only)
        print(line)
        return 0 if ok else 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
