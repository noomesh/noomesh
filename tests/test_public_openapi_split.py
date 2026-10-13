# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The public spec may contain only endpoints that need no credential.

`/static/openapi.json` was served under a public `/static/` prefix, so the
complete route map — 418 paths, including admin, security, posture, PKI and
user management — was readable by anything that could reach the gateway.
Every one of those routes authenticates, so this was disclosure rather than
access; but on a tailnet install "anything that can reach the gateway" is
every node, every device and every member, and a full inventory of the
surface is worth more to an attacker than it is to anyone else
.

The split that replaced it is DERIVED, and these tests are why that matters.
Two hand-kept specs would drift, and the drift is silent in the dangerous
direction: a gated path left in the public copy still parses and still
serves, and nothing complains. So the public spec is generated from the full
one by `scripts/gen-public-openapi.py`, filtered by the very lists
`auth::require_any_auth` checks, and the tests below assert the derivation
rather than a snapshot of its output.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUTH = ROOT / "gateway-rust/src/auth.rs"
FULL = ROOT / "src/noomesh/gateway/static/openapi.json"
PUBLIC = ROOT / "src/noomesh/gateway/static/openapi.public.json"
GEN = ROOT / "scripts/gen-public-openapi.py"


def _list(name: str) -> list[str]:
    src = AUTH.read_text(encoding="utf-8")
    m = re.search(rf"{name}: &\[&str\] = &\[(.*?)\];", src, re.S)
    assert m, f"{name} changed shape in auth.rs"
    body = "\n".join(l.split("//")[0] for l in m.group(1).splitlines())
    return re.findall(r'"([^"]+)"', body)


def _is_public(path: str) -> bool:
    """Reachable with no credential.

    CREDENTIAL_OPTIONAL_PATHS counts: those answer an anonymous caller, just
    with a smaller body, so a spec that omitted them would tell a client
    without a key that an endpoint it CAN call does not exist. The generator
    reads the same three lists — if these two derivations ever disagree, the
    disagreement is the bug, which is why this asserts the union rather than
    a snapshot.
    """
    exact = set(_list("PUBLIC_PATHS_EXACT")) | set(_list("CREDENTIAL_OPTIONAL_PATHS"))
    return path in exact or any(path.startswith(p) for p in _list("PUBLIC_PATH_PREFIXES"))


def test_the_public_spec_leaks_no_gated_path():
    """The direction that matters. A gated path in the public file is a
    disclosure that nothing else in the system would notice."""
    gated = sorted(p for p in json.loads(PUBLIC.read_text())["paths"] if not _is_public(p))
    assert not gated, (
        "these paths are in the PUBLIC spec but need a credential:\n  "
        + "\n  ".join(gated)
        + "\n\nRegenerate with scripts/gen-public-openapi.py."
    )


def test_the_public_spec_is_complete():
    """The other direction. Too narrow is safe but wrong: an OAuth client or
    an enrolling node needs the endpoints it can actually reach."""
    full = json.loads(FULL.read_text())["paths"]
    public = set(json.loads(PUBLIC.read_text())["paths"])
    missing = sorted(p for p in full if _is_public(p) and p not in public)
    assert not missing, f"public endpoints absent from the public spec: {missing}"


def test_the_full_spec_is_not_public():
    """`/static/` must not be a public PREFIX again — that is what made the
    whole map readable. Only the derived public file is exempt, by exact
    path, so a second file dropped into that directory is NOT served."""
    prefixes = _list("PUBLIC_PATH_PREFIXES")
    assert "/static/" not in prefixes, (
        "/static/ is a public prefix again — that publishes every file in the "
        "gateway's static directory, including the full openapi.json"
    )
    assert "/static/openapi.public.json" in _list("PUBLIC_PATHS_EXACT")


def test_the_full_spec_is_reachable_authenticated():
    """Gating without a replacement would just delete the reference."""
    assert '"/api/docs/openapi"' in (ROOT / "gateway-rust/src/routes/ui.rs").read_text()
    assert "/api/docs/openapi" in json.loads(FULL.read_text())["paths"]


def test_check_mode_catches_a_stale_public_spec():
    """A guard nobody has seen fail is a guard nobody should trust."""
    original = PUBLIC.read_text(encoding="utf-8")
    doc = json.loads(original)
    doc["paths"]["/api/security/service-keys"] = {"get": {"summary": "planted"}}
    PUBLIC.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    try:
        r = subprocess.run([sys.executable, str(GEN), "--check"], capture_output=True, text=True)
        assert r.returncode == 1, "a stale public spec passed --check"
        assert "stale" in (r.stdout + r.stderr)
    finally:
        PUBLIC.write_text(original, encoding="utf-8")


def test_the_generator_reads_comments_as_comments():
    """`/bootstrap/bundle/` appears in auth.rs only inside a NOTE saying it is
    no longer public. A parser that did not strip `//` would publish three
    paths that were deliberately withdrawn — found while building this."""
    raw = re.search(
        r"PUBLIC_PATH_PREFIXES: &\[&str\] = &\[(.*?)\];", AUTH.read_text(), re.S
    ).group(1)
    assert "/bootstrap/bundle/" in raw, "the NOTE moved; this test needs a new example"
    assert "/bootstrap/bundle/" not in _list("PUBLIC_PATH_PREFIXES")
    assert not any(
        p.startswith("/bootstrap/bundle/") for p in json.loads(PUBLIC.read_text())["paths"]
    )
