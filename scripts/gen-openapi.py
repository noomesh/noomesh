#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Fill the gateway's OpenAPI spec from the router, so it covers every route.

The spec is hand-maintained: FastAPI generated it, that generator left with
the Python gateway, and nothing replaced it. By 2026-08-09 it had drifted to
101 registered routes with no entry. `check-openapi-drift.py` stopped the
drift growing; this closes it, and keeps it closed by construction.

WHAT THIS DOES AND DOES NOT TOUCH

Existing entries are NEVER rewritten. The 284 already in the spec carry prose
a person wrote — richer than any doc comment — and clobbering it with a
one-line summary would be a large downgrade dressed as automation. This only
ADDS operations that are absent, and reports what it could not describe.

Sources, in order:
  1. the handler's `///` doc comment (316 of 349 handlers have one)
  2. failing that, a `[undocumented]` stub naming the handler, so the gap is
     visible in the spec instead of only in a baseline file

WHY A PARSER AND NOT A REGEX

`.route("/p", get(h).post(h2))` nests, and its layout varies. A non-greedy
regex silently skips the forms it cannot close — 54 of 338 registrations, 16%
of the surface, all of them looking exactly like success. This balances
parentheses instead, and asserts it found every path the simple
path-only regex finds. `.nest(` is a hard stop, same as the drift check:
with it, route strings are suffixes and every comparison here becomes a
confident wrong answer.

    scripts/gen-openapi.py            # write missing entries
    scripts/gen-openapi.py --check    # report only, exit 1 if incomplete
    scripts/gen-openapi.py --report   # what would be added, and from where
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUST_SRC = ROOT / "gateway-rust" / "src"
SPEC = ROOT / "src" / "noomesh" / "gateway" / "static" / "openapi.json"

METHOD_RE = re.compile(r"\b(get|post|put|delete|patch)\s*\(\s*(?:[A-Za-z0-9_]+::)*([A-Za-z0-9_]+)")
DOC_RE = re.compile(
    r"((?:^[ \t]*///.*\n)+)[ \t]*(?:pub(?:\([a-z]+\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)", re.M
)
SIMPLE_ROUTE_RE = re.compile(r'\.route\(\s*"([^"]+)"')
NEST_RE = re.compile(r"\.nest\(\s*\"")


def route_calls(text: str):
    """Yield (path, argument-source) for every `.route("…", …)`, balancing
    parentheses so nested and multi-line forms are not skipped."""
    i, needle = 0, ".route("
    while (i := text.find(needle, i)) != -1:
        j = i + len(needle)
        while j < len(text) and text[j] in " \t\r\n":
            j += 1
        if j >= len(text) or text[j] != '"':
            i += len(needle)
            continue
        k = text.find('"', j + 1)
        while k != -1 and text[k - 1] == "\\":
            k = text.find('"', k + 1)
        if k == -1:
            i += len(needle)
            continue
        path = text[j + 1 : k]
        depth, m, in_str = 1, k + 1, False
        while m < len(text) and depth:
            c = text[m]
            if in_str:
                if c == "\\":
                    m += 1
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            m += 1
        yield path, text[k + 1 : m - 1]
        i = m


def scan() -> tuple[dict[str, list[tuple[str, str]]], dict[str, str]]:
    """(path -> [(method, handler)], handler -> doc text)."""
    routes: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)
    docs: dict[str, str] = {}
    nested: list[str] = []
    simple: set[str] = set()

    for f in sorted(RUST_SRC.rglob("*.rs")):
        text = f.read_text(encoding="utf-8", errors="ignore")
        if NEST_RE.search(text):
            nested.append(str(f.relative_to(ROOT)))
        simple.update(m.group(1) for m in SIMPLE_ROUTE_RE.finditer(text) if m.group(1).startswith("/"))
        for m in DOC_RE.finditer(text):
            docs.setdefault(m.group(2), m.group(1))
        for path, args in route_calls(text):
            if not path.startswith("/"):
                continue
            for verb, handler in METHOD_RE.findall(args):
                if (verb, handler) not in routes[path]:
                    routes[path].append((verb, handler))
            routes.setdefault(path, routes[path])

    if nested:
        sys.exit(
            "gen-openapi: `.nest(` found in " + ", ".join(nested) +
            "\nRoute strings are no longer full paths; every comparison here "
            "would be a confident wrong answer. Teach it to resolve prefixes first."
        )
    # The balanced parser must see everything the crude one does. If it ever
    # does not, it is skipping routes silently — the failure this parser exists
    # to prevent.
    missed = simple - set(routes)
    if missed:
        sys.exit(f"gen-openapi: parser missed {len(missed)} route(s): {sorted(missed)[:5]}")
    return routes, docs


def clean_doc(raw: str) -> str:
    """`///` block -> prose. Rust doc comments open with a summary line, so
    the first paragraph is the description and the rest is usually rationale
    aimed at the next maintainer, not an API consumer."""
    lines = [re.sub(r"^\s*///\s?", "", ln).rstrip() for ln in raw.splitlines()]
    while lines and not lines[0].strip():
        lines.pop(0)
    para: list[str] = []
    for ln in lines:
        if not ln.strip():
            break
        para.append(ln.strip())
    return " ".join(para).strip()


def summary_for(path: str, method: str) -> str:
    tail = [p for p in path.strip("/").split("/") if not p.startswith("{")]
    noun = tail[-1].replace("-", " ").replace("_", " ") if tail else path
    return f"{ {'get': 'Get', 'post': 'Create', 'put': 'Update', 'delete': 'Delete', 'patch': 'Patch'}[method] } {noun}"


def ok_response() -> collections.OrderedDict:
    return collections.OrderedDict([
        ("description", "OK"),
        ("content", {"application/json": {"schema": {"type": "object", "additionalProperties": True}}}),
    ])


def build_op(path: str, method: str, handler: str, docs: dict[str, str]) -> tuple[dict, bool]:
    doc = clean_doc(docs[handler]) if handler in docs else ""
    described = bool(doc)
    op = collections.OrderedDict()
    op["tags"] = ["other"]
    op["summary"] = summary_for(path, method)
    op["description"] = (
        f"[native] {doc}" if described
        else f"[native] [undocumented] Handled by `{handler}`. No `///` comment on the "
             f"handler to describe it — add one there and re-run scripts/gen-openapi.py."
    )
    op["operationId"] = f"{handler}"
    if method in ("post", "put", "patch"):
        op["requestBody"] = {
            "required": False,
            "content": {"application/json": {"schema": {"type": "object", "additionalProperties": True}}},
        }
    op["responses"] = {"200": ok_response()}
    return op, described


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="report only; exit 1 if incomplete")
    ap.add_argument("--report", action="store_true", help="show what would be added")
    args = ap.parse_args()

    routes, docs = scan()
    spec = json.loads(SPEC.read_text(encoding="utf-8"), object_pairs_hook=collections.OrderedDict)
    paths = spec.setdefault("paths", collections.OrderedDict())

    added_paths, added_ops, refreshed_ops, undescribed = [], 0, 0, []
    for path in sorted(routes):
        item = paths.get(path)
        new_path = item is None
        if new_path:
            item = collections.OrderedDict()
        for method, handler in routes[path]:
            if method in item:
                # Never rewrite a hand-authored entry — but a stub THIS
                # script wrote is ours to replace once the handler gains a
                # `///` doc. Without this branch the stub's own instruction
                # ("add one there and re-run") was unfulfillable: the first
                # run planted the stub and every later run skipped it.
                existing_desc = item[method].get("description", "")
                if "[undocumented]" not in existing_desc:
                    continue
                op, described = build_op(path, method, handler, docs)
                if not described:
                    continue  # still no doc — keep the stub as-is
                item[method] = op
                refreshed_ops += 1
                continue
            op, described = build_op(path, method, handler, docs)
            item[method] = op
            added_ops += 1
            if not described:
                undescribed.append(f"{method.upper()} {path}  ({handler})")
        if new_path and item:
            paths[path] = item
            added_paths.append(path)

    total_ops = sum(len(v) for v in routes.values())
    print(f"{len(routes)} paths · {total_ops} operations registered")
    print(f"spec now covers {len(paths)} paths")
    print(f"adding {len(added_paths)} paths / {added_ops} operations; refreshing {refreshed_ops} stub(s) whose handler gained a doc")
    if undescribed:
        print(f"\n{len(undescribed)} operation(s) have no `///` on the handler — stubbed, "
              f"and the stub says so:")
        for u in undescribed[:15]:
            print(f"  ? {u}")
        if len(undescribed) > 15:
            print(f"  … and {len(undescribed) - 15} more")
        print("  Fix these by writing the doc comment in Rust, then re-running.")

    if args.report or args.check:
        if args.check and added_ops:
            print("\nSpec is INCOMPLETE — run scripts/gen-openapi.py.", file=sys.stderr)
            return 1
        if args.check:
            print("\nSpec covers every registered route.")
        return 0

    if added_ops or refreshed_ops:
        SPEC.write_text(json.dumps(spec, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        print(f"\nWrote {SPEC.relative_to(ROOT)}")
    else:
        print("\nNothing to add.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
