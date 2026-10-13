#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Derive the PUBLIC OpenAPI spec from the full one and the auth layer.

`/static/openapi.json` was public, so the complete route map — 418 paths
including admin, security, posture, PKI and user management — was readable
by anything that could reach the gateway, with no credential. Not a breach;
every one of those routes authenticates. But it is a free inventory of the
surface, and on a tailnet install "anything that can reach the gateway" is
every node, every device and every colleague.

Only 34 of the 418 are reachable without a credential. Those are worth
publishing: an OAuth client reading
`/.well-known/oauth-authorization-server`, an A2A peer reading
`/.well-known/agent.json`, or a node in the middle of enrolling has no
credential by construction and still needs to know the shape of what it may
call. The other 384 are documentation for people who are already inside.

So the split is DERIVED, never hand-maintained: the public spec is the full
spec filtered by the same two lists `auth::require_any_auth` checks. Two
hand-kept files would drift, and the drift would be silent in the dangerous
direction — a gated path left in the public copy is a disclosure nobody
notices, because both files still parse and both still serve.

    scripts/gen-public-openapi.py            # write it
    scripts/gen-public-openapi.py --check    # exit 1 if it is stale
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUTH = ROOT / "gateway-rust/src/auth.rs"
FULL = ROOT / "src/noomesh/gateway/static/openapi.json"
PUBLIC = ROOT / "src/noomesh/gateway/static/openapi.public.json"


def _list(name: str, src: str) -> list[str]:
    """One `pub const NAME: &[&str] = &[…];` from auth.rs, as strings.

    Read rather than restated. The whole point is that this file cannot
    disagree with the code that does the checking, and a copy of the lists
    here would be exactly the second home the derivation exists to avoid.
    """
    m = re.search(rf"{name}: &\[&str\] = &\[(.*?)\];", src, re.S)
    if not m:
        raise SystemExit(f"gen-public-openapi: {name} not found in auth.rs — its shape changed")
    # Skip `//` comments: those lists are heavily commented and the comments
    # quote paths, which would otherwise be read as entries.
    body = "\n".join(l.split("//")[0] for l in m.group(1).splitlines())
    items = re.findall(r'"([^"]+)"', body)
    if not items:
        raise SystemExit(f"gen-public-openapi: parsed an empty {name} — the shape changed")
    return items


def public_paths() -> tuple[set[str], list[str]]:
    """Every path a caller with no credential can reach.

    CREDENTIAL_OPTIONAL_PATHS belongs here: those answer anonymously, just
    with a smaller body. Leaving them out would publish a spec that says a
    reachable endpoint does not exist, which is the opposite of what this
    spec is for — the shape of what you may call before you have a key.
    """
    src = AUTH.read_text(encoding="utf-8")
    exact = set(_list("PUBLIC_PATHS_EXACT", src)) | set(_list("CREDENTIAL_OPTIONAL_PATHS", src))
    return exact, _list("PUBLIC_PATH_PREFIXES", src)


def is_public(path: str, exact: set[str], prefixes: list[str]) -> bool:
    return path in exact or any(path.startswith(p) for p in prefixes)


def render() -> str:
    exact, prefixes = public_paths()
    doc = json.loads(FULL.read_text(encoding="utf-8"))
    kept = {p: v for p, v in doc["paths"].items() if is_public(p, exact, prefixes)}
    if not kept:
        raise SystemExit("gen-public-openapi: no public paths — refusing to write an empty spec")
    doc["paths"] = kept
    info = doc.setdefault("info", {})
    info["title"] = f"{info.get('title', 'noomesh')} (public surface)"
    info["description"] = (
        "The endpoints reachable WITHOUT a credential — enrollment, discovery, "
        "auth and health. Derived from the full spec by "
        "scripts/gen-public-openapi.py, filtered by the same lists "
        "gateway-rust/src/auth.rs checks. The full spec is authenticated: "
        "GET /api/docs/openapi."
    )
    # Components are shared; a public path may reference one. Keeping them is
    # cheaper than computing the reachable subset, and a schema name is not
    # the disclosure this split is about — the route map is.
    # ensure_ascii matches the full spec's own encoding: that file stores
    # escaped unicode, and writing literals here would make every diff of
    # the derived file disagree with its source for no reason.
    return json.dumps(doc, indent=2) + "\n"


def main(argv: list[str]) -> int:
    new = render()
    if "--check" in argv:
        old = PUBLIC.read_text(encoding="utf-8") if PUBLIC.exists() else ""
        if old != new:
            print(
                f"{PUBLIC.relative_to(ROOT)} is stale — run scripts/gen-public-openapi.py",
                file=sys.stderr,
            )
            return 1
        print(f"public spec up to date ({len(json.loads(new)['paths'])} paths)")
        return 0
    PUBLIC.write_text(new, encoding="utf-8")
    print(f"wrote {PUBLIC.relative_to(ROOT)} ({len(json.loads(new)['paths'])} paths)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
