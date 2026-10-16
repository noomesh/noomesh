# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The rail's body cap must fit what the rail actually carries.

Outgrown twice by the same mechanism — something new joined the bundle and
nobody re-read the number:

  2026-09-03  a ~9 MB CLI asset against the 2 MB default
  2026-09-19  an earlier change's harness put the GATEWAY BINARY in every remote
              node's bundle (48-61 MB per target, bundles 74-82 MB) against
              64 MB, and all four non-controller nodes failed to stage

Both reached the operator as `io: Broken pipe (os error 32)`, because a
server refusing an over-cap body answers 413 and stops reading before the
client has finished writing. The controller's own node carries neither the
CLI nor the harness, so its small bundle passed each time — the one node an
operator watches most closely was the one that could not fail.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BOOTSTRAP = REPO / "gateway-rust/src/routes/bootstrap.rs"
PROVISION = REPO / "noo-cli/src/commands/provision.rs"

# The largest single thing a bundle carries is the gateway binary (the
# harness): 61 MB unstripped for x86_64 at the time of
# writing, and the encrypted bundle around it was 82 MB. The cap must clear
# that with room for the next arrival, not sit just above today's number.
LARGEST_OBSERVED_BUNDLE_MB = 82

# i83 E1e: a node whose harness placement names a vendor CLI carries that
# native binary too, 100-250 MB per artefact (Copilot's is an already
# compressed tarball), so its bundle is up to ~330 MB. An ESTIMATE from the
# pinned artefacts' sizes, not an observed bundle; the cap must clear it
# twice as well.
LARGEST_EXPECTED_VENDOR_BUNDLE_MB = 330

# Postgres refuses a bytea (noo_provision_bundles.blob) over 1 GB.
POSTGRES_FIELD_LIMIT_MB = 1024


def _cap_bytes() -> int:
    text = BOOTSTRAP.read_text()
    m = re.search(r"const MAX_RAIL_BODY:\s*usize\s*=\s*(\d+)\s*\*\s*1024\s*\*\s*1024", text)
    assert m, "MAX_RAIL_BODY is not a <N> * 1024 * 1024 constant in bootstrap.rs"
    return int(m.group(1)) * 1024 * 1024


def test_the_cap_clears_the_largest_bundle_with_headroom() -> None:
    cap_mb = _cap_bytes() // (1024 * 1024)
    assert cap_mb >= LARGEST_OBSERVED_BUNDLE_MB * 2, (
        f"the rail cap is {cap_mb} MB and the largest bundle we have shipped is "
        f"{LARGEST_OBSERVED_BUNDLE_MB} MB. A cap just above today's bundle is how "
        "this broke twice; leave room for the next thing that joins one."
    )


def test_the_cap_clears_a_vendor_cli_bundle_and_fits_the_database() -> None:
    cap_mb = _cap_bytes() // (1024 * 1024)
    assert cap_mb >= LARGEST_EXPECTED_VENDOR_BUNDLE_MB * 2, (
        f"the rail cap is {cap_mb} MB; a bundle carrying a vendor CLI is up to "
        f"{LARGEST_EXPECTED_VENDOR_BUNDLE_MB} MB"
    )
    assert cap_mb < POSTGRES_FIELD_LIMIT_MB, "a staged bundle is one bytea; Postgres refuses one over 1 GB"


def test_both_rail_upload_routes_use_the_named_cap() -> None:
    """A literal on one route and the constant on the other is how they drift."""
    text = BOOTSTRAP.read_text()
    for route in ("provision-bundle", "cli-asset"):
        block = [ln for ln in text.splitlines() if route in ln and "DefaultBodyLimit" in ln]
        if not block:
            # the layer may sit on the following line
            idx = next(i for i, ln in enumerate(text.splitlines()) if route in ln and ("post(" in ln or "put(" in ln or ".route(" in ln))
            block = text.splitlines()[idx:idx + 3]
        joined = " ".join(block)
        assert "DefaultBodyLimit::max(MAX_RAIL_BODY)" in joined, (
            f"the {route} route must use MAX_RAIL_BODY, not a literal: {joined.strip()[:160]}"
        )
    assert not re.search(r"DefaultBodyLimit::max\(\s*\d+\s*\*", text), (
        "a numeric literal body limit is back in bootstrap.rs — use MAX_RAIL_BODY"
    )


def test_a_mid_upload_disconnect_is_explained_not_just_reported() -> None:
    """`Broken pipe` names a syscall; the operator needs the cause."""
    src = PROVISION.read_text()
    assert "fn oversize_hint(" in src
    hint = src.split("fn oversize_hint(", 1)[1].split("\nfn ", 1)[0]
    for needle in ("broken pipe", "connection reset"):
        assert needle in hint, f"{needle} must be recognised as a possible refusal"
    assert "cap" in hint.lower(), "the hint must name the body cap as the likely cause"
    # And a real 413, when the client does see it, says so plainly.
    assert "413" in src and "too large" in src
