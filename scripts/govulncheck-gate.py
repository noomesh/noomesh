#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""Gate for the go-vulncheck lane: fail on reachable vulnerabilities, except
the scoped, dated exceptions in node-agent-go/govulncheck-exceptions.json.

usage: govulncheck-gate.py OUT.json EXCEPTIONS.json [--today YYYY-MM-DD]

OUT.json is `govulncheck -format json` output (a stream of JSON objects:
config, progress, osv, finding). A finding is REACHABLE when its trace's first
frame names a function (symbol level); package- and module-level findings are
ignored, as plain `govulncheck` ignores them. The first frame is the
vulnerable symbol, so its module and version are the vulnerable module and the
version found.

An exception matches only on the SAME id AND the SAME module AND the SAME
found version. Fails (exit 1) when a reachable finding has no exception, an
exception has expired, an exception matches no reachable finding (stale), or
the exceptions file is malformed.
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys

FIELDS = ("id", "module", "found_version", "expires", "reason")


def parse_stream(text: str) -> list[dict]:
    dec = json.JSONDecoder()
    objs, i, n = [], 0, len(text)
    while True:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            return objs
        obj, i = dec.raw_decode(text, i)
        if not isinstance(obj, dict):
            raise ValueError("govulncheck stream holds a non-object value")
        objs.append(obj)


def reachable_findings(objs: list[dict]) -> dict[tuple[str, str, str], int]:
    """(id, module, version) -> number of reachable traces."""
    out: dict[tuple[str, str, str], int] = {}
    for o in objs:
        f = o.get("finding")
        if not isinstance(f, dict):
            continue
        trace = f.get("trace")
        if not isinstance(trace, list) or not trace or not isinstance(trace[0], dict):
            continue
        top = trace[0]
        if not top.get("function"):
            continue
        key = (str(f.get("osv", "")), str(top.get("module", "")), str(top.get("version", "")))
        out[key] = out.get(key, 0) + 1
    return out


def load_exceptions(path: str) -> tuple[list[dict], list[str]]:
    errs: list[str] = []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        return [], [f"exceptions file {path} unreadable: {e}"]
    if not isinstance(data, list):
        return [], [f"exceptions file {path}: top level must be a list"]
    seen: set[tuple[str, str]] = set()
    good: list[dict] = []
    for n, e in enumerate(data):
        if not isinstance(e, dict):
            errs.append(f"exception #{n}: not an object")
            continue
        bad = False
        for k in FIELDS:
            if not isinstance(e.get(k), str) or not e[k].strip():
                errs.append(f"exception #{n}: missing or empty field {k!r}")
                bad = True
        if bad:
            continue
        try:
            e["_expires"] = datetime.date.fromisoformat(e["expires"])
            if len(e["expires"]) != 10:
                raise ValueError
        except ValueError:
            errs.append(f"exception #{n} ({e['id']}): bad date {e['expires']!r}, want YYYY-MM-DD")
            continue
        k2 = (e["id"], e["module"])
        if k2 in seen:
            errs.append(f"exception #{n}: duplicate id+module {k2[0]} {k2[1]}")
            continue
        seen.add(k2)
        good.append(e)
    return good, errs


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out")
    ap.add_argument("exceptions")
    ap.add_argument("--today", help="YYYY-MM-DD (default: today, UTC)")
    a = ap.parse_args(argv)
    try:
        today = (datetime.date.fromisoformat(a.today) if a.today
                 else datetime.datetime.now(datetime.timezone.utc).date())
    except ValueError:
        print(f"FAIL: --today {a.today!r} is not YYYY-MM-DD")
        return 1

    excs, fails = load_exceptions(a.exceptions)
    try:
        with open(a.out, encoding="utf-8") as fh:
            objs = parse_stream(fh.read())
    except (OSError, ValueError) as e:
        print(f"FAIL: govulncheck output {a.out} unreadable: {e}")
        return 1
    configs = [o["config"] for o in objs if isinstance(o.get("config"), dict)]
    if not configs:
        print(f"FAIL: {a.out} has no govulncheck config message; the scan did not run")
        return 1
    # "Reachable" is a symbol-level fact: at module or package level no finding
    # names a function, and every advisory would pass by omission.
    level, mode = configs[0].get("scan_level"), configs[0].get("scan_mode")
    if level != "symbol" or mode != "source":
        print(f"FAIL: govulncheck ran at scan level {level!r} (mode {mode!r}); "
              f"the gate needs symbol-level findings from a source scan")
        return 1
    found = reachable_findings(objs)

    matched: dict[tuple[str, str], int] = {}
    for (oid, mod, ver), count in sorted(found.items()):
        hit = [e for e in excs if (e["id"], e["module"], e["found_version"]) == (oid, mod, ver)]
        if hit:
            matched[(oid, mod)] = count
        else:
            fails.append(f"reachable {oid} in {mod} {ver} ({count} trace(s)) has no exception "
                         f"for that id, module and found version")
    for e in excs:
        k = (e["id"], e["module"])
        if e["_expires"] < today:
            fails.append(f"exception {e['id']} {e['module']} expired {e['expires']} "
                         f"(today {today}): the bump was due; bump the module and remove the entry")
        if k not in matched:
            fails.append(f"exception {e['id']} {e['module']} {e['found_version']} matches no "
                         f"reachable finding (stale: the bump landed or the advisory was "
                         f"withdrawn); remove the entry")
    for r in fails:
        print(f"FAIL: {r}")
    if fails:
        return 1
    for e in excs:
        print(f"excepted: {e['id']} {e['module']} until {e['expires']}, "
              f"{matched[(e['id'], e['module'])]} reachable trace(s)")
    if not excs:
        print("no reachable vulnerabilities")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
