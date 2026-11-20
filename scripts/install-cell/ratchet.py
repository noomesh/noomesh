#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The install matrix's WARN ratchet (noomesh-internal i1098, "The matrix
ratchet"): a fresh install's `noo --json cluster verify` may not carry more
WARN rows than its cell's ceiling, nor a WARN row the ceiling does not name.

  ratchet.py judge CELL VERIFY_LOG [--ceiling FILE]
      reads the verify JSON (the cell's logs/probe-verify-json.log) and the
      ceiling (warn-ratchet.json beside this file) and prints:
        RATCHET PASS: <n> WARN ≤ <max> (rows: …)
        RATCHET FAIL: <n> WARN > <max>
        RATCHET FAIL: new WARN row(s): <rows>
        RATCHET NOTE: lower the ceiling: <rows> gone   (a fix landed; its PR lowers it)
        RATCHET NOTE: no measured ceiling for <cell> yet   (and what it measured now)
        RATCHET ROW: <row> (<status>)      one per WARN row, its status from row_status
        VERIFY FAIL: <rows>                 a row with verdict "fail" (only while
                                            fail_rows_fail_the_cell is true)
        VERIFY NOTE: …                      a FAIL row allow-listed, or seen while the
                                            rule is off
      exit 1 on any FAIL, else 0.
  ratchet.py skip CELL REASON
      RATCHET NOTE: <cell> not judged: <reason>   (a cell with no full install)
  ratchet.py only-down --base-ref REF [--file PATH]
      the ceiling file in the work tree against its version at REF: exit 1 if
      any cell's max_warn rose, a row was added, or a measured cell lost its
      ceiling, unless that cell carries a matching "raise" record (below);
      also if fail_rows_fail_the_cell was switched off again or a row was
      added to fail_allowed without a "decision".

What counts: every row whose `verdict` is exactly "warn", in the controller
section, every node section and every seat section. Never the text, never
the tier: since #1458 a few OK rows carry `tier: "later"` (advice for later
on a healthy box); they are OK, not WARN, and are not counted. A WARN row
tiered "later" or "not_here" IS a WARN and is counted.

A row's identity is "<section>:<name>", the section being controller, node
or seat. Not the node's id: a hosted runner's hostname changes every run.
Not the name alone: the row registry (noo-cli cluster_verify/rows.rs) gives
each row a scope, and the same words in another section are another fact.

Raising a ceiling is never routine. The one escape is a reviewed decision:
a separate commit that adds, to that cell, "raise": {"from_max": <old>,
"to_max": <new>, "add_rows": [<the added rows>], "reason": "<why, who
decided>"}; only-down accepts a rise only when that record matches the rise
exactly and was not already in the base.

row_status names, per row, why it may stand: "awaiting operator decision"
(an undecided operator decision: NOT accepted), "accepted" (honest on a
fresh box), "fix in flight" or "under triage". A WARN row it does not list
prints "(no status recorded)".

A FAIL row (i1098: "a FAIL row always fails the cell") fails the cell only
while "fail_rows_fail_the_cell" is true; fail_allowed lists, by row, the
FAIL rows that may stand, each with a "why". It only shrinks, by the same
rule as the ceiling.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CEILING = HERE / "warn-ratchet.json"
CEILING_REL = "scripts/install-cell/warn-ratchet.json"
MIN_REASON = 20
STATUSES = ("awaiting operator decision", "accepted", "fix in flight", "under triage")


def verify_json(text: str) -> dict | None:
    """The verify object in a step log: the first `{` at a line start that
    decodes to an object with a controller, nodes or seats section (stderr
    lines may stand before it)."""
    dec = json.JSONDecoder()
    starts = [0] + [i + 1 for i, ch in enumerate(text) if ch == "\n"]
    for s in starts:
        if text[s:s + 1] != "{":
            continue
        try:
            obj, _ = dec.raw_decode(text, s)
        except ValueError:
            continue
        if isinstance(obj, dict) and any(k in obj for k in ("controller", "nodes", "seats")):
            return obj
    return None


def rows_with(v: dict, verdict: str) -> list[str]:
    """One "<section>:<name>" per row whose verdict is exactly `verdict`
    (a row on two nodes counts twice), controller, nodes and seats."""
    out = []
    ctrl = v.get("controller") or {}
    for c in ctrl.get("checks") or []:
        if c.get("verdict") == verdict:
            out.append(f"controller:{c.get('name')}")
    for section, items in (("node", v.get("nodes")), ("seat", v.get("seats"))):
        for it in items or []:
            for c in (it or {}).get("checks") or []:
                if c.get("verdict") == verdict:
                    out.append(f"{section}:{c.get('name')}")
    return out


def warn_rows(v: dict) -> list[str]:
    return rows_with(v, "warn")


def fail_rows(v: dict) -> list[str]:
    return rows_with(v, "fail")


def status_lines(rows: list[str], ceiling: dict) -> list[str]:
    st = ceiling.get("row_status") or {}
    return [f"RATCHET ROW: {r} ({(st.get(r) or {}).get('status') or 'no status recorded'})"
            for r in sorted(set(rows))]


def verify_fail_lines(verify: dict | None, ceiling: dict) -> tuple[list[str], list[str]]:
    """(notes, fails) for the rows whose verdict is "fail"."""
    if verify is None:
        return [], []
    rows = sorted(set(fail_rows(verify)))
    if not rows:
        return [], []
    allowed = ceiling.get("fail_allowed") or {}
    ok = [r for r in rows if r in allowed]
    bad = [r for r in rows if r not in allowed]
    notes = [f"VERIFY NOTE: allowed FAIL row(s): "
             + "; ".join(f"{r} ({allowed[r].get('why', '')})" for r in ok)] if ok else []
    if not bad:
        return notes, []
    if ceiling.get("fail_rows_fail_the_cell") is True:
        return notes, [f"VERIFY FAIL: {', '.join(bad)}"]
    return notes + [f"VERIFY NOTE: FAIL row(s) {', '.join(bad)} "
                    "(not fatal yet: fail_rows_fail_the_cell is false)"], []


def load_ceiling(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def measured(entry: dict | None) -> bool:
    return bool(entry) and entry.get("measured") is not None


def judge(cell: str, verify: dict | None, ceiling: dict) -> tuple[bool, list[str]]:
    """(ok, lines). NOTE lines first, FAIL lines last (the step record takes
    its last line as the error)."""
    ok, lines = judge_warn(cell, verify, ceiling)
    notes, fails = verify_fail_lines(verify, ceiling)
    head = [l for l in lines if not l.startswith("RATCHET FAIL")]
    tail = [l for l in lines if l.startswith("RATCHET FAIL")]
    return ok and not fails, head + notes + tail + fails


def judge_warn(cell: str, verify: dict | None, ceiling: dict) -> tuple[bool, list[str]]:
    entry = (ceiling.get("cells") or {}).get(cell)
    rows = warn_rows(verify) if verify is not None else None
    if not measured(entry):
        now = ("no verify JSON was read" if rows is None else
               f"measured now: {len(rows)} WARN, rows: {json.dumps(sorted(set(rows)), ensure_ascii=False)}")
        return True, status_lines(rows or [], ceiling) + [f"RATCHET NOTE: no measured ceiling for {cell} yet ({now})"]
    mx, allowed = entry.get("max_warn"), entry.get("rows")
    if not isinstance(mx, int) or not isinstance(allowed, list):
        return False, [f"RATCHET FAIL: the ceiling for {cell} is measured but has no max_warn/rows"]
    if rows is None:
        return False, [f"RATCHET FAIL: no verify JSON to judge for {cell}"]
    n, seen, allowed = len(rows), set(rows), set(allowed)
    notes, fails = status_lines(rows, ceiling), []
    gone = sorted(allowed - seen)
    if gone:
        notes.append(f"RATCHET NOTE: lower the ceiling: {', '.join(gone)} gone")
    if n < mx and not gone:
        notes.append(f"RATCHET NOTE: lower the ceiling: {n} WARN < {mx}")
    if n > mx:
        fails.append(f"RATCHET FAIL: {n} WARN > {mx}")
    new = sorted(seen - allowed)
    if new:
        fails.append(f"RATCHET FAIL: new WARN row(s): {', '.join(new)}")
    if fails:
        return False, notes + fails
    listed = ", ".join(sorted(seen)) or "none"
    return True, notes + [f"RATCHET PASS: {n} WARN ≤ {mx} (rows: {listed})"]


def raise_ok(cell: str, base: dict, new: dict, added: list[str]) -> bool:
    r = new.get("raise")
    if not isinstance(r, dict) or r == base.get("raise"):
        return False
    return (r.get("from_max") == base.get("max_warn") and r.get("to_max") == new.get("max_warn")
            and sorted(r.get("add_rows") or []) == sorted(added)
            and len(str(r.get("reason") or "").strip()) >= MIN_REASON)


def only_down(base: dict, new: dict) -> list[str]:
    """Every way `new` raises a ceiling `base` had measured, without a
    matching raise record."""
    bad = []
    if base.get("fail_rows_fail_the_cell") is True and new.get("fail_rows_fail_the_cell") is not True:
        bad.append("fail_rows_fail_the_cell was switched off again")
    bfa, nfa = base.get("fail_allowed") or {}, new.get("fail_allowed") or {}
    for r in sorted(set(nfa) - set(bfa)):
        if len(str((nfa[r] or {}).get("decision") or "").strip()) < MIN_REASON:
            bad.append(f"fail_allowed: {r} added without a \"decision\" (the allow-list only shrinks)")
    bcells, ncells = base.get("cells") or {}, new.get("cells") or {}
    for cell, b in sorted(bcells.items()):
        if not measured(b):
            continue  # the first measurement is the baseline, any number
        n = ncells.get(cell)
        if n is None:
            bad.append(f"{cell}: the measured ceiling was removed")
            continue
        if not measured(n) or not isinstance(n.get("max_warn"), int) or not isinstance(n.get("rows"), list):
            bad.append(f"{cell}: the measured ceiling was made unmeasured")
            continue
        added = sorted(set(n["rows"]) - set(b.get("rows") or []))
        rose = n["max_warn"] > b.get("max_warn", 0)
        if (rose or added) and not raise_ok(cell, b, n, added):
            what = []
            if rose:
                what.append(f"max_warn {b.get('max_warn')} -> {n['max_warn']}")
            if added:
                what.append(f"rows added: {', '.join(added)}")
            bad.append(f"{cell}: {'; '.join(what)} (raising is never allowed; "
                       f"a reviewed decision adds a matching \"raise\" record in its own commit)")
    return bad


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True)


def base_text(ref: str, rel: str = CEILING_REL, cwd: Path = HERE) -> str | None:
    """The ceiling file at REF (its merge base with HEAD when git can find
    one), or None when the file did not exist there. Raises LookupError when
    REF itself is not here."""
    if _git(cwd, "rev-parse", "-q", "--verify", f"{ref}^{{commit}}").returncode != 0:
        raise LookupError(ref)
    mb = _git(cwd, "merge-base", "HEAD", ref)
    at = mb.stdout.strip() if mb.returncode == 0 and mb.stdout.strip() else ref
    r = _git(cwd, "show", f"{at}:{rel}")
    return r.stdout if r.returncode == 0 else None


def main(argv: list[str]) -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    if len(argv) >= 3 and argv[0] == "judge":
        cell, log = argv[1], Path(argv[2])
        ceil = Path(argv[argv.index("--ceiling") + 1]) if "--ceiling" in argv else CEILING
        text = log.read_text(errors="replace") if log.exists() else ""
        ok, lines = judge(cell, verify_json(text), load_ceiling(ceil))
        print("\n".join(lines))
        return 0 if ok else 1
    if len(argv) == 3 and argv[0] == "skip":
        print(f"RATCHET NOTE: {argv[1]} not judged: {argv[2]}")
        return 0
    if len(argv) >= 3 and argv[0] == "only-down" and argv[1] == "--base-ref":
        f = Path(argv[argv.index("--file") + 1]) if "--file" in argv else CEILING
        try:
            old = base_text(argv[2], cwd=f.resolve().parent)
        except LookupError:
            print(f"only-down: {argv[2]} is not in this clone", file=sys.stderr)
            return 2
        if old is None:
            print(f"only-down: no ceiling at {argv[2]}: nothing to compare")
            return 0
        bad = only_down(json.loads(old), load_ceiling(f))
        for b in bad:
            print(f"RATCHET RAISED: {b}")
        return 1 if bad else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
