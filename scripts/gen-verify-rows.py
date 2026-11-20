#!/usr/bin/env python3
"""Generate docs/reference/verify-rows.md from the verify-row registry.

The registry is `noo-cli/src/commands/cluster_verify/rows.rs` (`ROWS`): one
entry per row `noo cluster verify` (or `noo security at-rest
preflight-firmware`) can print, with its stable `id`, display `name`, scope,
the verdicts it can emit, a one-line meaning and what clears it.

It is guarded both ways, with no Rust build:
  - every row name the CLI source builds must be registered;
  - every registered row must be built somewhere in the source.
The noo-cli tests add the third guard: `Check::new` refuses, in a test
build, a name that is not registered or a verdict the row does not declare.

Usage: gen-verify-rows.py          write the page
       gen-verify-rows.py --check  exit 1 if the page is stale or a guard fails
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "noo-cli" / "src"
REGISTRY = SRC / "commands" / "cluster_verify" / "rows.rs"
OUT = REPO / "docs" / "reference" / "verify-rows.md"

SCOPES = {"Node": "node", "Controller": "controller", "Seat": "seat", "Preflight": "preflight"}
VERDICT_MARK = {"Warn": "`!`", "Fail": "`x`", "Accepted": "accepted", "Starting": "starting"}

# ---------------------------------------------------------------- registry


def _str(field: str, body: str) -> str | None:
    m = re.search(rf'\b{field}:\s*"((?:[^"\\]|\\.)*)"', body)
    return m.group(1).replace('\\"', '"').replace("\\\\", "\\") if m else None


def parse_registry(text: str) -> list[dict]:
    start = text.index("pub(crate) const ROWS: &[Row] = &[")
    end = text.index("\n];", start)
    rows = []
    for m in re.finditer(r"\n    Row \{(.*?)\n    \},", text[start:end], re.S):
        b = m.group(1)
        scope = re.search(r"\bscope:\s*Scope::(\w+)", b)
        verdicts = re.search(r"\bverdicts:\s*&\[([^\]]*)\]", b)
        doc = re.search(r'\bdoc:\s*(None|Some\("([^"]*)"\))', b)
        shown = re.search(r'\bshown_as:\s*(None|Some\("([^"]*)"\))', b)
        findings = re.findall(r'Finding \{\s*code:\s*"([^"]+)",\s*clears:\s*"((?:[^"\\]|\\.)*)",\s*needs_human:\s*(true|false)', b)
        rows.append({
            "id": _str("id", b),
            "name": _str("name", b),
            "scope": SCOPES.get(scope.group(1)) if scope else None,
            "verdicts": re.findall(r"Verdict::(\w+)", verdicts.group(1)) if verdicts else None,
            "meaning": _str("meaning", b),
            "clears": _str("clears", b),
            "doc": doc.group(2) if doc and doc.group(2) else None,
            "shown_as": shown.group(2) if shown and shown.group(2) else None,
            "findings": [{"code": c, "clears": cl, "needs_human": h == "true"} for c, cl, h in findings],
        })
    return rows


# ---------------------------------------------------------- source resolver

CONST = re.compile(r'const (\w+): &(?:\'static )?str = "([^"]+)"')


def strip_tests(text: str) -> str:
    """Blank out `#[cfg(test)] mod x { … }` (closed by a `}` at the mod's own
    indent), keeping line numbers."""
    lines = text.split("\n")
    out, i = [], 0
    while i < len(lines):
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if lines[i].lstrip().startswith("#[cfg(test)]") and re.match(r"\s*(pub(\(crate\))? )?mod \w+ *\{", nxt):
            close = " " * (len(nxt) - len(nxt.lstrip())) + "}"
            j = i + 2
            while j < len(lines) and lines[j] != close:
                j += 1
            out += [""] * (j + 1 - i)
            i = j + 1
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


def built_rows() -> tuple[dict[str, set[str]], list[str]]:
    """Every row name the CLI source builds, with where. Returns (rows,
    unresolved sites). A row is built by `Check::new(<name>, …)`, by a
    helper whose first parameter is `name: &'static str` and which returns a
    Check (ok/warn/fail/accepted and per-module helpers), or from the
    `at_rest_dirs` table. A name is a string literal or a `const` resolved
    to the nearest preceding definition (then any in the crate)."""
    files = {f.relative_to(SRC).as_posix(): strip_tests(f.read_text(encoding="utf-8")) for f in sorted(SRC.rglob("*.rs"))}
    helpers: dict[str, set[str]] = defaultdict(set)
    for rel, b in files.items():
        for m in re.finditer(r"fn (\w+)\(\s*\w+: &'static str", b):
            head = b[m.end(): b.find("{", m.end())]
            if re.search(r"->\s*(?:Option<|Vec<)?(?:[\w:]+::)?Check\b", head):
                helpers[rel].add(m.group(1))
    all_consts = {m.group(1): m.group(2) for b in files.values() for m in CONST.finditer(b)}
    rows: dict[str, set[str]] = defaultdict(set)
    unresolved: list[str] = []
    for rel, b in files.items():
        names = {"new"} if "Check::new(" in b else set()
        names |= helpers.get(rel, set())
        for hrel, hs in helpers.items():
            for h in hs:
                if h in ("ok", "warn", "fail", "accepted"):
                    if "cluster_verify" in rel or f"cluster_verify::{h}" in b or re.search(
                        r"use (super|crate::commands::cluster_verify)::\{[^}]*\b" + h + r"\b", b
                    ):
                        names.add(h)
                elif re.search(r"\b" + re.escape(Path(hrel).stem) + r"::" + h + r"\(", b):
                    names.add(h)
        consts = [(b[: m.start()].count("\n") + 1, m.group(1), m.group(2)) for m in CONST.finditer(b)]
        sites = [
            (b[: m.start()].count("\n") + 1, m.group(1).strip())
            for m in re.finditer(r"\bCheck\s*\{\s*name\s*:\s*([^,}]*)", b)
        ]
        pat = r"(?<![\w>])(?:[\w:]*::)?(" + "|".join(map(re.escape, sorted(names))) + r")\(\s*([^,()]*),"
        for m in re.finditer(pat, b) if names else ():
            if b[max(0, m.start() - 3): m.start()].endswith("fn "):
                continue
            if m.group(1) == "new" and not b[max(0, m.start() - 7): m.start()].endswith("Check::"):
                continue
            if "output::" in m.group(0):
                continue  # crate::output::fail, the error printer, not a row
            sites.append((b[: m.start()].count("\n") + 1, m.group(2).strip()))
        for ln, arg in sites:
            arg = arg.split("::")[-1]
            if arg.startswith('"'):
                rows[arg.strip('"')].add(f"{rel}:{ln}")
                continue
            if arg == "name":  # a helper forwarding its own parameter
                continue
            if arg == "row.name":  # the at_rest_dirs table, read below
                continue
            c = [x for x in consts if x[1] == arg and x[0] <= ln] or [x for x in consts if x[1] == arg]
            if c:
                rows[c[-1][2]].add(f"{rel}:{ln}")
            elif arg in all_consts:
                rows[all_consts[arg]].add(f"{rel}:{ln}")
            else:
                unresolved.append(f"noo-cli/src/{rel}:{ln}: row name `{arg}` is not a literal or a const")
        i = b.find("fn at_rest_dirs(")
        if i >= 0:
            body = b[i: b.find("\n}\n", i)]
            for m in re.finditer(r'\bname:\s*"([^"]+)"', body):
                rows[m.group(1)].add(f"{rel}:at_rest_dirs")
    return rows, unresolved


def _close_brace(s: str, i: int) -> int:
    """Index of the `}` closing the `{` at s[i], skipping strings, raw
    strings, char literals and line comments."""
    depth, j = 0, i
    while j < len(s):
        c = s[j]
        if s.startswith("//", j):
            j = s.find("\n", j)
            continue
        raw = re.match(r'r(#*)"', s[j:]) if c == "r" and not (s[j - 1].isalnum() or s[j - 1] == "_") else None
        if raw:
            j = s.find('"' + raw.group(1), j + len(raw.group(0))) + 1 + len(raw.group(1))
            continue
        if c == '"':
            j += 1
            while s[j] != '"':
                j += 2 if s[j] == "\\" else 1
            j += 1
            continue
        ch = re.match(r"'(\\.|[^\\'])'", s[j:]) if c == "'" else None
        if ch:
            j += len(ch.group(0))
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    raise ValueError("unbalanced")


def unchecked_literals() -> list[str]:
    """Every `Check { … }` literal outside tests that sets `name` or
    `verdict` must end in `.checked()`, the test-build registry guard.
    (A `..other` update that changes only `detail` keeps a checked row's
    name and verdict.)"""
    out = []
    for f in sorted(SRC.rglob("*.rs")):
        t = strip_tests(f.read_text(encoding="utf-8"))
        for m in re.finditer(r"(?<![\w:])(?:super::cluster_verify::)?Check\s*\{", t):
            if t[max(0, m.start() - 12): m.start()].rstrip().endswith(("struct", "impl", "for", "->")):
                continue
            ob = t.index("{", m.start())
            cb = _close_brace(t, ob)
            fields = t[ob + 1: cb].split("..")[0]
            if not re.search(r"(^|[,{\s])(name|verdict)\s*[:,}]", fields):
                continue
            if t[cb + 1: cb + 11] != ".checked()":
                ln = t[: m.start()].count("\n") + 1
                out.append(f"noo-cli/src/{f.relative_to(SRC).as_posix()}:{ln}: a row literal must end in `.checked()` (the registry guard)")
    return out


# ------------------------------------------------------------------- guard


def problems(rows: list[dict]) -> list[str]:
    out = []
    ids, names = set(), set()
    for r in rows:
        where = f"rows.rs `{r.get('name') or r.get('id')}`"
        for f in ("id", "name", "scope", "verdicts", "meaning", "clears"):
            if r[f] is None:
                out.append(f"{where}: field `{f}` missing or unparsable")
        if r["id"] and not re.fullmatch(r"[a-z][a-z0-9_]*", r["id"]):
            out.append(f"{where}: id `{r['id']}` is not snake_case")
        if r["id"] in ids:
            out.append(f"{where}: id `{r['id']}` registered twice")
        if r["name"] in names:
            out.append(f"{where}: name registered twice")
        ids.add(r["id"])
        names.add(r["name"])
        for fd in r["findings"]:
            if not re.fullmatch(r"[a-z][a-z0-9_]*", fd["code"]):
                out.append(f"{where}: finding code `{fd['code']}` is not snake_case")
    built, unresolved = built_rows()
    out += unresolved
    out += unchecked_literals()
    for n in sorted(set(built) - names):
        out.append(f"row `{n}` is built ({sorted(built[n])[0]}) but not registered in {REGISTRY.relative_to(REPO)}")
    for n in sorted(names - set(built)):
        out.append(f"row `{n}` is registered but nothing in noo-cli/src builds it; remove it")
    return out


# -------------------------------------------------------------------- page


def cell(s: str) -> str:
    return s.replace("|", "\\|")


def render(rows: list[dict]) -> str:
    head = """# Verify rows

<!-- GENERATED by scripts/gen-verify-rows.py from noo-cli/src/commands/cluster_verify/rows.rs; do not edit. -->

Every row `noo cluster verify` can print, and the few that `noo security
at-rest preflight-firmware` prints. `!` is a warning (the verb still
passes), `x` a failure (exit 1). A row's `id` is stable: programs key on it
(`noo --json cluster verify` prints it beside `name`, which may be
reworded); `id` is never null, and a null is a bug to report. Node rows
are under `nodes[].checks`, controller rows under
`controller.checks`. A row "shown as" another is printed inside that one in
the default table (`--verbose` lists it alone); `--json` lists every row
and carries `shown_as` on it.
"""
    parts = [head]
    titles = [("node", "Node rows (one set per node)"), ("controller", "Controller rows (`--controller`, run on the controller)"),
              ("seat", "Seat rows (kiosk displays)"), ("preflight", "`noo security at-rest preflight-firmware` rows")]
    for scope, title in titles:
        sel = sorted((r for r in rows if r["scope"] == scope), key=lambda r: r["name"].lower())
        if not sel:
            continue
        parts.append(f"\n## {title}\n\n| Row | id | Can be | Means | Clears when |\n|---|---|---|---|---|\n")
        for r in sel:
            can = ", ".join(VERDICT_MARK[v] for v in r["verdicts"] if v in VERDICT_MARK) or "OK only"
            name = f"[{r['name']}]({r['doc']})" if r["doc"] else r["name"]
            if r["shown_as"]:
                name += f"<br>(shown as {r['shown_as']})"
            clears = cell(r["clears"])
            if r["findings"]:
                clears += "<br>" + "<br>".join(f"`{f['code']}`: {cell(f['clears'])}" + (" (a person)" if f["needs_human"] else "") for f in r["findings"])
            parts.append(f"| {name} | `{r['id']}` | {can} | {cell(r['meaning'])} | {clears} |\n")
    return "".join(parts)


def main() -> int:
    rows = parse_registry(REGISTRY.read_text(encoding="utf-8"))
    errs = problems(rows)
    if errs:
        for e in errs:
            print(f"gen-verify-rows: ERROR {e}", file=sys.stderr)
        return 1
    page = render(rows)
    if "--check" in sys.argv[1:]:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != page:
            print(f"gen-verify-rows: {OUT.relative_to(REPO)} is stale; run scripts/gen-verify-rows.py", file=sys.stderr)
            return 1
        print(f"gen-verify-rows: up to date ({len(rows)} rows)")
        return 0
    OUT.write_text(page, encoding="utf-8")
    print(f"gen-verify-rows: wrote {OUT.relative_to(REPO)} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
