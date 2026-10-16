# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The OpenAPI route scan's per-file opt-out is explicit, shared and honest.

scripts/check-openapi-drift.py and scripts/gen-openapi.py collect every
`.route("…")` literal under gateway-rust/src as a gateway route. A file whose
router is bound somewhere other than the gateway's listener (the node
harness's loopback wire translator) carries the marker
``openapi-drift: not-gateway-routes`` in its module doc and is skipped.

Pinned here:
  (a) both scripts define the same marker and skip a marked file;
  (b) every marked file in the tree gives a reason on the marker line and
      never touches the gateway's router (no `AppState` router wiring), so
      the opt-out cannot be used to hide a real gateway route;
  (c) the marker sits near the top of the file, inside the window the
      scripts read.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUST_SRC = ROOT / "gateway-rust" / "src"
SCRIPTS = [ROOT / "scripts" / "check-openapi-drift.py", ROOT / "scripts" / "gen-openapi.py"]
MARKER = "openapi-drift: not-gateway-routes"


def _load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _marked_files() -> list[Path]:
    out = []
    for f in sorted(RUST_SRC.rglob("*.rs")):
        if MARKER in f.read_text(encoding="utf-8", errors="ignore"):
            out.append(f)
    return out


def test_both_scripts_share_the_marker_and_skip_a_marked_file():
    for script in SCRIPTS:
        mod = _load(script)
        assert mod.NOT_GATEWAY_ROUTES_MARKER == MARKER, script.name
        assert mod.declares_not_gateway_routes(f"//! {MARKER} — reason\n.route(\"/x\")"), script.name
        assert not mod.declares_not_gateway_routes('.route("/x")'), script.name
        # The marker must be near the top: a marker buried past the window
        # does not count, so a file cannot be exempted by a stray comment.
        buried = "x" * (mod.MARKER_WINDOW + 10) + MARKER
        assert not mod.declares_not_gateway_routes(buried), script.name


def test_the_drift_scan_really_skips_marked_files():
    drift = _load(SCRIPTS[0])
    routes = drift.rust_routes()
    for f in _marked_files():
        text = f.read_text(encoding="utf-8")
        for m in re.finditer(r'\.route\(\s*"([^"]+)"', text):
            assert m.group(1) not in routes or _route_also_in_unmarked(m.group(1)), (
                f"{f.relative_to(ROOT)} route {m.group(1)} still counted"
            )


def _route_also_in_unmarked(path: str) -> bool:
    for f in RUST_SRC.rglob("*.rs"):
        text = f.read_text(encoding="utf-8", errors="ignore")
        if MARKER in text:
            continue
        if f'.route("{path}"' in text:
            return True
    return False


def test_every_marked_file_says_why_and_is_not_gateway_wiring():
    marked = _marked_files()
    assert marked, "at least the harness wire translator carries the marker"
    for f in marked:
        text = f.read_text(encoding="utf-8")
        line = next(l for l in text.splitlines() if MARKER in l)
        reason = line.split(MARKER, 1)[1].strip(" —-:")
        assert len(reason) > 20, f"{f.relative_to(ROOT)}: the marker line must carry a reason"
        head = text[:4000]
        assert MARKER in head, f"{f.relative_to(ROOT)}: marker must be in the first 4000 bytes"
        # A file that builds the gateway's own router must never be exempt.
        assert "Router<Arc<AppState>>" not in text and "Router<std::sync::Arc<AppState>>" not in text, (
            f"{f.relative_to(ROOT)}: a gateway router file cannot opt out of the spec"
        )
