#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The install matrix's verify ratchet (noomesh-internal i1098, "The matrix
ratchet"): a fresh install's `noo --json cluster verify` may not carry more
WARN rows than its cell's ceiling, nor a WARN row the ceiling does not name.

  ratchet.py judge CELL VERIFY_LOG [--ceiling FILE] [--rows ROWS_RS] [--onboard-log PATH]...
      reads the verify JSON (the cell's logs/probe-verify-json.log) and the
      ceiling (warn-ratchet.json beside this file) and prints:
        RATCHET ROW: <id> (<section>:<name>) — <status>   one per WARN row
        RATCHET LEFTOVER: <id> (<label>) reported fixed by <by> but still WARNs
        RATCHET PASS: <n> WARN ≤ <max> (rows: <ids>)
        RATCHET FAIL: <n> WARN > <max>
        RATCHET FAIL: new WARN row(s): <id (label)>
        RATCHET FAIL: row(s) with no id: <labels>   (neither the JSON nor rows.rs names it)
        RATCHET NOTE: lower the ceiling: <ids> gone   (a fix landed; its PR lowers it)
        RATCHET NOTE: no measured ceiling for <cell> yet   (and what it measured now)
        VERIFY FAIL: <ids>                  a row with verdict "fail" (only while
                                            fail_rows_fail_the_cell is true)
        VERIFY NOTE: …                      a FAIL row allow-listed, or seen while the
                                            rule is off
        RATCHET NOT JUDGED: default_chat (<label>) — registry outage at onboard,
            retries exhausted: "<5xx line>" … "<did not complete line>"
                                            the ONE exemption (below)
      exit 1 on any FAIL, else 0.
  ratchet.py run-summary DIR
      ratchet NOT JUDGED cells: N (<cells>)   from DIR/install-cell-*/summary.json
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

A row's identity is its STABLE id from the rows registry (noo-cli
cluster_verify/rows.rs, #1411): `noo --json cluster verify` prints it as
each check's `id`. A row reworded under the same id is the same row. A CLI
that prints no id (before #1411) is mapped name -> id through rows.rs; a row
with neither FAILS the cell by name. "<section>:<name>" is only the label.

Raising a ceiling is never routine. The one escape is a reviewed decision:
a separate commit that adds, to that cell, "raise": {"from_max": <old>,
"to_max": <new>, "add_rows": [<the added ids>], "reason": "<why, who
decided>"}; only-down accepts a rise only when that record matches the rise
exactly and was not already in the base.

row_status names, per id, why a row may stand: "awaiting operator decision"
(an undecided operator decision: NOT accepted), "accepted" (honest on a
fresh box), "reported fixed" (a merged change says it no longer WARNs: if it
does, a LEFTOVER line), "fix in flight" (not merged yet) or "under triage".
The last three name their carrier in "by" (a PR or a followup).

A FAIL row (i1098: "a FAIL row always fails the cell") fails the cell only
while "fail_rows_fail_the_cell" is true; fail_allowed lists, by id, the
FAIL rows that may stand, each with a "why". It only shrinks, by the same
rule as the ceiling.

The ONE exemption from that rule: a `default chat` FAIL (id default_chat)
is NOT JUDGED, not failed, when the cell's onboard log (--onboard-log, any
number; a missing file adds nothing) shows that the chat model's pull met a
registry 5xx AND the bounded retry (noo-cli pull_retry.rs, #1475) was
exhausted: a 5xx line, then the last try announced ("(try 3 of 3)"), then
"Ollama pull did not complete", and no "pulled via Ollama" after the 5xx.
A pull that recovered is judged. A build without the retry (no "retrying
in" line at all) is judged too: the release lead's rule is that exhaustion
must be visible, and a bare 5xx shows one try, not an exhausted retry.
Every other FAIL row fails the cell whatever the onboard log says.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CEILING = HERE / "warn-ratchet.json"
CEILING_REL = "scripts/install-cell/warn-ratchet.json"
ROWS_RS = HERE.parent.parent / "noo-cli" / "src" / "commands" / "cluster_verify" / "rows.rs"
MIN_REASON = 20
STATUSES = ("awaiting operator decision", "accepted", "reported fixed", "fix in flight", "under triage")
NEEDS_BY = ("reported fixed", "fix in flight")   # "by" must name the carrier
BY_KEY = NEEDS_BY + ("under triage",)            # "by" must be present (null: no followup yet)
ROW_RX = re.compile(r'id: "([^"]+)",\s*name: "([^"]+)",\s*scope: Scope::(\w+)')


def registry(path: Path = ROWS_RS) -> dict[str, str]:
    """name -> id, from rows.rs (empty when the file is not in this checkout)."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    return {name: rid for rid, name, _ in ROW_RX.findall(text)}


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


def rows_with(v: dict, verdict: str, names: dict[str, str] | None = None) -> list[tuple[str | None, str]]:
    """(id, "<section>:<name>") per row whose verdict is exactly `verdict`
    (a row on two nodes counts twice), controller, nodes and seats. The id is
    the check's own, else rows.rs's for its name, else None."""
    names = registry() if names is None else names
    out = []

    def add(section: str, c: dict) -> None:
        if c.get("verdict") == verdict:
            name = c.get("name")
            out.append((c.get("id") or names.get(name), f"{section}:{name}"))
    for c in (v.get("controller") or {}).get("checks") or []:
        add("controller", c)
    for section, items in (("node", v.get("nodes")), ("seat", v.get("seats"))):
        for it in items or []:
            for c in (it or {}).get("checks") or []:
                add(section, c)
    return out


def warn_rows(v: dict, names: dict[str, str] | None = None) -> list[tuple[str | None, str]]:
    return rows_with(v, "warn", names)


def fail_rows(v: dict, names: dict[str, str] | None = None) -> list[tuple[str | None, str]]:
    return rows_with(v, "fail", names)


def labels(rows: list[tuple[str | None, str]]) -> dict[str, str]:
    """id -> label (the first seen)."""
    out: dict[str, str] = {}
    for rid, label in rows:
        if rid:
            out.setdefault(rid, label)
    return out


def status_lines(rows: list[tuple[str | None, str]], ceiling: dict) -> list[str]:
    st = ceiling.get("row_status") or {}
    out, leftover = [], []
    for rid, label in sorted(labels(rows).items()):
        e = st.get(rid) or {}
        status = e.get("status") or "no status recorded"
        by = f" by {e['by']}" if e.get("by") else ""
        out.append(f"RATCHET ROW: {rid} ({label}) — {status}{by}")
        if status == "reported fixed":
            leftover.append(f"RATCHET LEFTOVER: {rid} ({label}) reported fixed by {e.get('by')} but still WARNs")
    return out + leftover


# The onboard model pull's lines (noo-cli onboard/steps.rs, pull_retry.rs).
REGISTRY_5XX = re.compile(r"Error: (?:pull model manifest: )?5\d\d: |"
                          r"registry answered 5\d\d \(a registry-side problem\): retrying in ")
RETRY = re.compile(r"retrying in \d+ s \(try (\d+) of (\d+)\)")
DID_NOT_COMPLETE = "Ollama pull did not complete"
PULLED = re.compile(r"Model \S+ pulled via Ollama")
EXEMPT_ROW = "default_chat"


def _quote(line: str) -> str:
    line = line.strip()
    return line if len(line) <= 200 else line[:199] + "…"


def registry_outage(text: str) -> tuple[str, str] | None:
    """(the 5xx line, the "did not complete" line) when the onboard log
    shows a registry 5xx whose bounded retry was exhausted with no later
    success; else None."""
    lines = text.splitlines()
    i5 = next((i for i, l in enumerate(lines) if REGISTRY_5XX.search(l)), None)
    if i5 is None:
        return None
    if any(PULLED.search(l) for l in lines[i5:]):
        return None  # it recovered: the row is judged
    last_try = [i for i, l in enumerate(lines)
                if (m := RETRY.search(l)) and m.group(1) == m.group(2)]
    if not last_try:
        return None  # no visible retry (an older build): not exhausted, judged
    done = [i for i, l in enumerate(lines) if DID_NOT_COMPLETE in l and i > last_try[-1]]
    if not done:
        return None
    return _quote(lines[i5]), _quote(lines[done[-1]])


def verify_fail_lines(verify: dict | None, ceiling: dict, names: dict[str, str],
                      onboard: str = "") -> tuple[list[str], list[str]]:
    """(notes, fails) for the rows whose verdict is "fail"."""
    if verify is None:
        return [], []
    rows = fail_rows(verify, names)
    if not rows:
        return [], []
    lab = labels(rows)
    allowed = ceiling.get("fail_allowed") or {}
    ok = sorted(r for r in lab if r in allowed)
    notes = [f"VERIFY NOTE: allowed FAIL row(s): "
             + "; ".join(f"{r} ({allowed[r].get('why', '')})" for r in ok)] if ok else []
    exempt = set()
    outage = registry_outage(onboard) if EXEMPT_ROW in lab and EXEMPT_ROW not in allowed else None
    if outage:
        exempt.update(lab)
        notes.append(f"RATCHET NOT JUDGED: {EXEMPT_ROW} ({lab[EXEMPT_ROW]}) — registry outage at onboard, "
                     f"retries exhausted: \"{outage[0]}\" … \"{outage[1]}\"")
    bad = [f"{r} ({lab[r]})" for r in sorted(lab) if r not in allowed and r not in exempt]
    bad += sorted({label for rid, label in rows if not rid})
    if not bad:
        return notes, []
    if ceiling.get("fail_rows_fail_the_cell") is True:
        return notes, [f"VERIFY FAIL: {', '.join(bad)}"]
    return notes + [f"VERIFY NOTE: FAIL row(s) {', '.join(bad)} "
                    "(not fatal yet: fail_rows_fail_the_cell is false)"], []


def status_problems(ceiling: dict) -> list[str]:
    """Every row_status entry that breaks the status rules: a known status,
    a "why", and the carrier: "reported fixed" and "fix in flight" name it
    in "by"; "under triage" carries a "by" key (null: no followup filed yet)."""
    bad = []
    for rid, e in sorted((ceiling.get("row_status") or {}).items()):
        st = (e or {}).get("status")
        if st not in STATUSES:
            bad.append(f"{rid}: unknown status {st!r}")
        if not (e or {}).get("why"):
            bad.append(f"{rid}: no why")
        if st in NEEDS_BY and not str((e or {}).get("by") or "").strip():
            bad.append(f"{rid}: {st} without \"by\" (the PR or followup that carries the fix)")
        if st in BY_KEY and "by" not in (e or {}):
            bad.append(f"{rid}: {st} without a \"by\" key")
    return bad


def load_ceiling(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def measured(entry: dict | None) -> bool:
    return bool(entry) and entry.get("measured") is not None


def judge(cell: str, verify: dict | None, ceiling: dict,
          names: dict[str, str] | None = None, onboard: str = "") -> tuple[bool, list[str]]:
    """(ok, lines). NOTE lines first, FAIL lines last (the step record takes
    its last line as the error). `onboard` is the cell's onboard log text."""
    names = registry() if names is None else names
    ok, lines = judge_warn(cell, verify, ceiling, names)
    notes, fails = verify_fail_lines(verify, ceiling, names, onboard)
    head = [l for l in lines if not l.startswith("RATCHET FAIL")]
    tail = [l for l in lines if l.startswith("RATCHET FAIL")]
    return ok and not fails, head + notes + tail + fails


def judge_warn(cell: str, verify: dict | None, ceiling: dict, names: dict[str, str]) -> tuple[bool, list[str]]:
    entry = (ceiling.get("cells") or {}).get(cell)
    rows = warn_rows(verify, names) if verify is not None else None
    unknown = sorted({label for rid, label in rows or [] if not rid})
    no_id = [f"RATCHET FAIL: row(s) with no id: {', '.join(unknown)} "
             "(the JSON has no id and rows.rs has no such name)"] if unknown else []
    if not measured(entry):
        ids = sorted({rid for rid, _ in rows or [] if rid})
        now = ("no verify JSON was read" if rows is None else
               f"measured now: {len(rows)} WARN, rows: {json.dumps(ids, ensure_ascii=False)}")
        return not no_id, status_lines(rows or [], ceiling) + \
            [f"RATCHET NOTE: no measured ceiling for {cell} yet ({now})"] + no_id
    mx, allowed = entry.get("max_warn"), entry.get("rows")
    if not isinstance(mx, int) or not isinstance(allowed, list):
        return False, [f"RATCHET FAIL: the ceiling for {cell} is measured but has no max_warn/rows"]
    if rows is None:
        return False, [f"RATCHET FAIL: no verify JSON to judge for {cell}"]
    lab = labels(rows)
    n, seen, allowed = len(rows), set(lab), set(allowed)
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
        fails.append(f"RATCHET FAIL: new WARN row(s): {', '.join(f'{r} ({lab[r]})' for r in new)}")
    fails += no_id
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


def run_summary(root: Path) -> str:
    """One line for the run: the cells whose verify-ratchet reported a row
    NOT JUDGED (cell.py summary's `ratchet_not_judged`), so a registry
    outage that keeps hiding the default chat row is seen run after run."""
    cells = []
    for s in sorted(root.glob("*/summary.json")):
        try:
            d = json.loads(s.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if d.get("ratchet_not_judged"):
            cells.append(d.get("cell") or s.parent.name)
    return f"ratchet NOT JUDGED cells: {len(cells)} ({', '.join(cells) or 'none'})"


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
        names = registry(Path(argv[argv.index("--rows") + 1]) if "--rows" in argv else ROWS_RS)
        onboard = "".join(Path(argv[i + 1]).read_text(errors="replace") + "\n"
                          for i, a in enumerate(argv[:-1])
                          if a == "--onboard-log" and Path(argv[i + 1]).is_file())
        ok, lines = judge(cell, verify_json(text), load_ceiling(ceil), names, onboard)
        print("\n".join(lines))
        return 0 if ok else 1
    if len(argv) == 2 and argv[0] == "run-summary":
        print(run_summary(Path(argv[1])))
        return 0
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
