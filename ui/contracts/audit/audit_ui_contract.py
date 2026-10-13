#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Contract audit: what the UI calls vs contracts/openapi.json vs the live router.

Run from the repo root (or via `npm run audit:contract`).

Three surfaces, checked pairwise:

  UI      — every path literal in apps/web/src + packages/*/src
  spec    — contracts/openapi.json (the agreed interface)
  router  — `.route(...)` declarations in gateway-rust (same tree since
            the monorepo import)
            (the runtime authority; checked when the backend repo is
            available, override the location with PAI_ASSISTANT_ROOT)
  proposed — contracts/proposed/*.json: shapes the UI needs that the
            gateway does not serve yet. NOT the agreed interface. A UI call
            into one is reported in its own bucket and does not gate; the
            directory exists so the UI can go first without the spec
            becoming a wish list. See contracts/proposed/README.md.

The router arm replaced a diff against `config/api_contract/`, which is a
hand-maintained file in the backend repo and had drifted four days and 41
route commits behind the router it claimed to describe — so every one of its
findings was a false alarm. Parsing the router directly cannot go stale.

Exit code 1 when the UI calls a path that is missing from the spec, or (when
the router is readable) one the router does not serve. Both are breakage: the
first ships an undocumented dependency, the second ships a 404.
"""
import json, os, re, sys
from pathlib import Path
from collections import defaultdict

HERE = Path(__file__).resolve()
REPO = HERE.parents[2]
OPENAPI = REPO / "contracts/openapi.json"
# The gateway is IN THIS TREE now. Before the monorepo import the console was
# its own repository and this defaulted to a sibling checkout that CI never had,
# so the router half reported itself skipped on every run — half an audit,
# permanently. REPO.parent is the monorepo root, which contains gateway-rust.
#
# NOOMESH_ROOT overrides it; PAI_ASSISTANT_ROOT still works for anyone whose
# muscle memory or scripts predate the move.
BACKEND = Path(
    os.environ.get("NOOMESH_ROOT")
    or os.environ.get("PAI_ASSISTANT_ROOT")
    or REPO.parent
)

# Roots holding hand-written call sites. `packages/api/src/schema.d.ts` is
# excluded by name: it is GENERATED from openapi.json, so every path in it
# would trivially match the spec and mask a real gap.
UI_ROOTS = [REPO / "apps/web/src", REPO / "packages"]
UI_SUFFIXES = {".ts", ".tsx", ".js", ".jsx", ".html"}
GENERATED = {"schema.d.ts"}

# Test files are excluded for the OPPOSITE reason to schema.d.ts. That file
# matches the spec too easily; these do not match it at all — a test asserts
# against invented endpoints (`/api/a`, `/ws/x`) that deliberately do not
# exist, and the audit dutifully reported four of them as undocumented UI
# calls the moment the first test suites landed.
#
# Four false positives is not the cost. The cost is that this report is read
# to answer "is the contract drifting?", and an answer with permanent known
# noise in it stops being read at all — at which point a REAL undocumented
# call sits in the same list unnoticed.
TEST_MARKERS = (".test.", ".spec.")
TEST_DIRS = {"__tests__", "__mocks__", "test", "tests"}

# ---- 1. extract UI calls ----------------------------------------------------
LIT = re.compile(r"""(['"`])((?:/|\$\{[^}]*\}/?)(?:api|auth|ws|v1|health|metrics)[^'"`\n]*)\1""")
LIT2 = re.compile(r"""(['"`])(\$\{[A-Za-z_.]+\}/(?:api|auth|v1)[^'"`\n]*)\1""")
HEALTH = re.compile(r"""['"`](/health|/metrics|/v1/models)['"`]""")


def normalize(p: str) -> str:
    p = re.sub(r"\$\{[^}]*\}", "{param}", p)          # template exprs -> {param}
    p = p.split("?")[0]                                # strip query
    p = re.sub(r"^\{param\}(?=/)", "", p)              # leading ${API} base -> ''
    p = re.sub(r"/+", "/", p)
    if len(p) > 1: p = p.rstrip("/")
    return p


def ui_files():
    for root in UI_ROOTS:
        if not root.exists():
            continue
        for f in sorted(root.rglob("*")):
            if not f.is_file() or "node_modules" in f.parts:
                continue
            if f.name in GENERATED or f.suffix not in UI_SUFFIXES:
                continue
            if any(m in f.name for m in TEST_MARKERS):
                continue
            if TEST_DIRS.intersection(f.parts):
                continue
            yield f


ui_calls = defaultdict(set)   # path -> set(files)
for f in ui_files():
    text = f.read_text(errors="replace")
    rel = str(f.relative_to(REPO))
    for rx in (LIT, LIT2):
        for m in rx.finditer(text):
            p = normalize(m.group(2))
            if p.startswith("/") and len(p) > 1:
                ui_calls[p].add(rel)
    for m in HEALTH.finditer(text):
        ui_calls[m.group(1)].add(rel)

# `/static` is a file-serving prefix (ServeDir), not an API surface, so it has
# no spec entry to check against.
#
# `/api/docs` used to be excluded alongside it. That was wrong: the exclusion
# was silencing the Docs tab's *broken* links — hrefs at `/docs/runbooks/<slug>`
# that the Rust gateway never served — and so it also hid the real, contracted
# calls that replaced them. An exclusion added to quiet a symptom kept the
# audit quiet about the cause.
ui_calls = {p: s for p, s in ui_calls.items()
            if not p.startswith("/static")
            and not p.endswith((".js", ".css", ".html", ".json", ".png", ".svg"))}

# ---- 2. load spec + router --------------------------------------------------
spec_paths = set(json.loads(OPENAPI.read_text()).get("paths", {}).keys())

# One OpenAPI path-item fragment per file: { "/api/…": { "get": {…} } }.
PROPOSED = REPO / "contracts/proposed"
proposed_paths = {}
for pf in sorted(PROPOSED.glob("*.json")) if PROPOSED.exists() else []:
    for path in json.loads(pf.read_text(encoding="utf-8")).keys():
        proposed_paths[path] = pf.name

# Parse `.route("/path", get(h).post(h))` out of the Rust router. Split on
# `.route(` rather than scanning with a bounded-window regex: a regex that
# captures the following N chars consumes them, so any `.route(` inside that
# window is never visited — which silently drops a third of the table.
router_paths = set()
gw = BACKEND / "gateway-rust/src"
if gw.exists():
    head = re.compile(r'^\s*"([^"]+)"\s*,')
    for rs in sorted(gw.rglob("*.rs")):
        flat = re.sub(r"\s+", " ", rs.read_text(errors="replace"))
        for chunk in flat.split(".route(")[1:]:
            m = head.match(chunk)
            if m:
                router_paths.add(m.group(1))

# Add-on routes are not here on purpose. An HTTP add-on ships its own route
# manifest and the gateway mounts it at runtime, so neither the router source
# nor the spec carries them, and the core console calls none of them. An
# add-on's console surface types its routes from its own manifest.

# ---- 3. match ---------------------------------------------------------------
def seg_match(ui: str, spec: str) -> bool:
    a, b = ui.split("/"), spec.split("/")
    if len(a) != len(b): return False
    return all(x == y or x == "{param}" or (y.startswith("{") and y.endswith("}"))
               for x, y in zip(a, b))


def find(p, pool):
    if any(seg_match(p, s) for s in pool): return True
    # String-concat call sites ("/api/x/approve/" + id) surface as the bare
    # prefix; accept when a spec path continues with a {param} segment.
    return any(s.startswith(p + "/{") for s in pool)


rows = [(p, find(p, spec_paths), find(p, router_paths), sorted(ui_calls[p]))
        for p in sorted(ui_calls)]
is_proposed = lambda p: find(p, set(proposed_paths))
# A call into a proposed path is neither "undocumented" nor "will 404 by
# accident": it is documented in proposed/ and expected to 404 until the
# gateway lands it. Reported separately, never gating — but never silent.
proposed_calls = [r for r in rows if not r[1] and is_proposed(r[0])]
missing_oa = [r for r in rows if not r[1] and not is_proposed(r[0])]
# Only meaningful when the router was actually readable. Without the backend
# checked out `router_paths` is empty, so every path "misses" it and the run
# fails on all 69 — which is why CI skipped this audit entirely rather than
# false-failing. The UI-vs-spec half needs no backend and is the half that
# protects the typed client, so it must gate on its own.
missing_rt = [r for r in rows if not r[2] and not is_proposed(r[0])] if router_paths else []
# Lifecycle nudges for proposed/: the fragment is done when the router serves
# the path (promote it into openapi.json), and stale once openapi.json has it.
proposed_promote = sorted(p for p in proposed_paths if router_paths and find(p, router_paths))
proposed_stale = sorted(p for p in proposed_paths if find(p, spec_paths))
unused = [s for s in sorted(spec_paths) if not any(seg_match(p, s) for p in ui_calls)]
# Spec entries the router does not serve — the drift that ships 404s to a
# typed client generated from this spec.
dead_spec = sorted(s for s in spec_paths if not find(s, router_paths)) if router_paths else []

print(f"UI distinct endpoint paths: {len(rows)}")
print(f"openapi.json paths: {len(spec_paths)} | live router paths: "
      f"{len(router_paths) if router_paths else 'n/a (backend not checked out)'}")

print(f"\n== UI paths MISSING from contracts/openapi.json ({len(missing_oa)}) ==")
for p, _, in_rt, srcs in missing_oa:
    print(f"  {p:60s} [{'router:yes' if in_rt else 'router:NO '}] {','.join(srcs)}")

if router_paths:
    print(f"\n== UI paths with NO live route ({len(missing_rt)}) == these 404 ==")
    for p, in_oa, _, srcs in missing_rt:
        print(f"  {p:60s} [{'spec:yes' if in_oa else 'spec:NO '}] {','.join(srcs)}")
    print(f"\n== spec paths the router does not serve ({len(dead_spec)}) == "
          f"remove or re-add the route ==")
    for s in dead_spec:
        print(f"  {s}")

if proposed_paths or proposed_calls:
    print(f"\n== UI paths calling PROPOSED endpoints ({len(proposed_calls)}) == "
          f"not contracted, not gating; contracts/proposed/README.md ==")
    for p, _, in_rt, srcs in proposed_calls:
        print(f"  {p:60s} [{proposed_paths.get(p, '?')}] "
              f"[{'router:yes' if in_rt else 'router:NO '}] {','.join(srcs)}")
    if proposed_promote:
        print(f"\n== proposed paths the router NOW SERVES ({len(proposed_promote)}) == "
              f"promote into openapi.json, delete the fragment ==")
        for p in proposed_promote: print(f"  {p}  [{proposed_paths[p]}]")
    if proposed_stale:
        print(f"\n== proposed paths ALREADY in openapi.json ({len(proposed_stale)}) == "
              f"delete the fragment ==")
        for p in proposed_stale: print(f"  {p}  [{proposed_paths[p]}]")

print(f"\n== spec paths not called by UI ({len(unused)}) == (informational; CLI/external consumers)")
for s in unused: print(f"  {s}")

out = REPO / "contracts/audit/audit_result.json"
json.dump({"ui_paths": {p: srcs for p, _, _, srcs in rows},
           "missing_from_openapi": [r[0] for r in missing_oa],
           "missing_from_router": [r[0] for r in missing_rt],
           "spec_paths_without_route": dead_spec,
           "spec_unused_by_ui": unused,
           "proposed_calls": [r[0] for r in proposed_calls],
           "proposed_promote": proposed_promote,
           "proposed_stale": proposed_stale},
          open(out, "w"), indent=1)
print(f"\nwrote {out}")
if not router_paths:
    print("\nNOTE: router half skipped — gateway-rust not readable "
          f"at {BACKEND}. Set PAI_ASSISTANT_ROOT to include it. "
          "The UI-vs-openapi half above still gated.")
sys.exit(1 if (missing_oa or missing_rt) else 0)
