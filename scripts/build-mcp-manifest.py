#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Export the external MCP tool surface as JSON for the Rust door to serve.

The Python ``ToolDef`` registry stays the single source of truth for what a
tool IS — name, description, input schema, and the HTTP call it proxies to.
This dumps the ``external``-tagged subset as data so the Rust external door
can serve and dispatch them without a Rust struct per tool.

That works ONLY while the REQUEST side is declarative. It was not: this file
claimed "exactly one overrides get_body and one overrides get_params" as a
reassurance, and exported both anyway. The Rust door cannot see a hand-written
override, so it sent the derived request instead —
``noo_graph_search_entities`` renamed ``query`` → ``q`` in ``get_params``, the
door sent ``query=``, the route reads ``q``, and every search through that
door returned ``[]`` with HTTP 200. Nothing errored.

That one is fixed declaratively (``serialization_alias``). The remaining
override is listed in [`UNREPRESENTABLE`] and a new one now FAILS this build,
because the reassurance above is exactly what let the first one ship.

Everything else is derivable from metadata:

    path      "/api/v1/graph/entities/{entity_id}"  → substitute from args
    method    POST                                  → args become the body
    aliases   field_name → api_key                  → wire naming

Response *formatting* (``format_response``, 16 of the 24 external tools) is
deliberately NOT exported. Those render results as prose for a human reader;
the Rust door returns the gateway's JSON unchanged, which an MCP client can
parse. That is a behaviour change, and an intentional one.

Run:
    python3 scripts/build-mcp-manifest.py            # write the default path
    python3 scripts/build-mcp-manifest.py --check    # verify it is current (CI)
    python3 scripts/build-mcp-manifest.py --stdout   # print, write nothing
"""
from __future__ import annotations

import argparse
import difflib
import inspect
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO_ROOT / "gateway-rust" / "mcp-tools.json"
# Full-registry manifest for the LOCAL door .
# Kept as a SEPARATE file from the external one on purpose: the external
# door's 'external'-tagged subset is a security decision, and a shared file
# would make widening it a one-character diff nobody reviews.
DEFAULT_OUT_LOCAL = REPO_ROOT / "gateway-rust" / "mcp-tools-local.json"

# Bump when the CONSUMER contract changes (field added/removed/retyped), not
# when a tool is added — the Rust side asserts on this so a stale checked-in
# manifest fails loudly instead of silently serving the wrong shape.
MANIFEST_VERSION = 2



#: Exported tools whose wire shape a manifest entry cannot express, with what
#: the Rust door therefore gets wrong. NOT a suppression list — each entry is
#: a live defect, and the build fails for anything not here.
UNREPRESENTABLE = {
    "noo_config_set": (
        "get_body unwraps the payload so the section's keys land at the top "
        "level. The door wraps them under `updates` instead, which the route "
        "deep-merges into the section as a literal key — the change never "
        "applies and the call reports success. Fixed Python-side in #337; "
        "#345 carries it across the seam with a declarative `body_field`, "
        "after which this entry goes away."
    ),
    "noo_inference": (
        "get_body injects max_iterations=1 and channel='tool_call'. The door "
        "drops both, so a call through it re-enters the agent loop and times "
        "out at 120s — the exact failure the override's own comment says it "
        "exists to prevent."
    ),
}


def _request_side_is_declarative(registry) -> "list[str]":
    """Exported tools that override request building and are not accounted for."""
    offenders = []
    for name, cls in registry.items():
        overrides = {"get_params", "get_body"} & set(cls.__dict__)
        if overrides and name not in UNREPRESENTABLE:
            offenders.append(f"{name} overrides {sorted(overrides)}")
    return offenders


def build(full: bool = False) -> dict:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from noomesh.mcp import tool_defs  # noqa: F401  (registers every tool)
    from noomesh.mcp.tool_models import get_all_tools, get_external_tools

    registry = get_all_tools() if full else get_external_tools()
    # Only noomesh's own tools: on a pro dev machine the guarded import in
    # tool_defs/__init__ also registers noo_evolve's delivered defs, and
    # without this filter the committed manifest would differ between a dev
    # venv (noo-evolve installed) and CI/OSS (not installed). The add-on's
    # tools reach the door via its own fragment (NOO_MCP_EXTRA_MANIFEST),
    # never via these files.
    registry = {
        n: c for n, c in registry.items()
        if c.__module__.startswith("noomesh.")
    }
    offenders = _request_side_is_declarative(registry)
    if offenders:
        raise SystemExit(
            "manifest build refused — these exported tools build their request "
            "in Python, which the Rust door cannot see:\n  "
            + "\n  ".join(offenders)
            + "\n\nExpress it declaratively (a `serialization_alias` covers a "
            "renamed parameter) or add it to UNREPRESENTABLE with what the "
            "door gets wrong. Silently exporting it is how "
            "noo_graph_search_entities returned [] for a year."
        )

    tools = []
    for name, cls in sorted(registry.items()):
        # field_name → wire key, so Rust reproduces path substitution and
        # body/param naming without knowing Python attribute names.
        aliases = {}
        for field_name, field_info in cls.model_fields.items():
            api_key = cls._api_key(field_name, field_info)
            if api_key != field_name:
                aliases[field_name] = api_key

        tools.append({
            "name": name,
            # inspect.cleandoc, not .strip(): `description` comes from the
            # class docstring, and Python 3.13 dedents docstrings at compile
            # time while 3.11/3.12 preserve the source indentation. Stripping
            # only the ends leaves that indentation on continuation lines, so
            # the same source produced DIFFERENT manifests per interpreter and
            # the drift gate failed on 3.13 only. cleandoc normalises
            # identically everywhere.
            "description": inspect.cleandoc(cls.description or ""),
            "input_schema": cls.model_json_schema(),
            "method": cls.method.value,
            "path": cls.path,
            "auth": cls.auth.value,
            "timeout_secs": cls.timeout_secs,
            "risk_level": cls.risk_level.value,
            "tags": list(cls.tags),
            "aliases": aliases,
            # Which field IS the body, when the route takes the payload
            # directly rather than as a named field inside one. Exported so
            # the Rust doors reproduce it: they build the request themselves
            # and never call `get_body`, so a Python-side override would fix
            # the stdio client and leave both doors wrapping the payload.
            "body_field": cls.body_field,
            # Advisory for reviewers: these had custom Python formatting that
            # the Rust door does not reproduce (it returns raw JSON).
            "had_custom_format": "format_response" in cls.__dict__,
        })

    return {"version": MANIFEST_VERSION, "tools": tools}


def _check_one(out: Path, text: str, tool_count: int) -> int:
    if not out.exists():
        print(f"MISSING: {out} — run scripts/build-mcp-manifest.py",
              file=sys.stderr)
        return 1
    current = out.read_text()
    if current != text:
        print(f"STALE: {out} does not match the ToolDef registry.\n"
              "The Rust MCP door would serve a schema the Python "
              "tools no longer have. Re-run scripts/build-mcp-manifest.py "
              "and commit the result.\n", file=sys.stderr)
        # Show WHAT differs. Without this the gate says "stale" and leaves
        # you guessing — which cost a CI round trip when the only delta was
        # docstring indentation on one interpreter version.
        diff = difflib.unified_diff(
            current.splitlines(), text.splitlines(),
            fromfile="committed", tofile="regenerated", lineterm="", n=2,
        )
        for i, line in enumerate(diff):
            if i > 60:
                print("  … (truncated)", file=sys.stderr)
                break
            print(f"  {line}", file=sys.stderr)
        return 1
    print(f"ok: {out} matches ({tool_count} tools)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=None,
                    help="override the output path (with --full: the local "
                         "manifest; otherwise the external one)")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if either manifest on disk differs (CI drift gate)")
    ap.add_argument("--stdout", action="store_true")
    ap.add_argument("--full", action="store_true",
                    help="operate on the full-registry LOCAL manifest only "
                         "(for --out/--stdout; the default write and --check "
                         "always cover both)")
    args = ap.parse_args()

    # (out path, full?) pairs this invocation covers. --out/--stdout narrow
    # to one manifest; the bare default and --check always do both, so a
    # tool added to the registry cannot ship with only one file regenerated.
    if args.stdout or args.out is not None:
        targets = [(args.out or (DEFAULT_OUT_LOCAL if args.full else DEFAULT_OUT), args.full)]
    else:
        targets = [(DEFAULT_OUT, False), (DEFAULT_OUT_LOCAL, True)]

    rc = 0
    for out, full in targets:
        manifest = build(full=full)
        text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"

        if args.stdout:
            print(text, end="")
            continue
        if args.check:
            rc |= _check_one(out, text, len(manifest["tools"]))
            continue

        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text)
        custom = sum(1 for t in manifest["tools"] if t["had_custom_format"])
        print(f"wrote {out} — {len(manifest['tools'])} tools "
              f"({custom} lose custom Python formatting → raw JSON)")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
