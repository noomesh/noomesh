# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Console overlays dim, they never blur what is behind them.

A `backdrop-filter: blur(...)` over animated content made the console's modals
flicker on the operator's browser (GPU compositing of an animated backdrop);
the same fix in pai-voice (personifAI/pai-voice 7abf9f0e) held. The overlays
keep their translucent background; the blur is gone and must not come back.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WEB_SRC = ROOT / "ui" / "apps" / "web" / "src"
OVERLAYS = (".login-overlay", ".confirm-overlay", ".diag-modal-overlay")
BLUR = re.compile(r"backdrop-filter\s*:\s*[^;]*blur\(", re.IGNORECASE)


def _css_files() -> list[Path]:
    files = sorted(WEB_SRC.rglob("*.css"))
    assert files, f"no stylesheet found under {WEB_SRC}"
    return files


def test_no_console_stylesheet_blurs_a_backdrop():
    hits = []
    for f in _css_files():
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if BLUR.search(line):
                hits.append(f"{f.relative_to(ROOT)}:{n}: {line.strip()}")
    assert not hits, "backdrop blur makes overlays flicker; dim instead:\n" + "\n".join(hits)


def test_each_overlay_still_dims():
    css = (WEB_SRC / "app.css").read_text(encoding="utf-8")
    for sel in OVERLAYS:
        m = re.search(re.escape(sel) + r"\s*\{(?P<body>[^}]*)\}", css)
        assert m, f"{sel} not found in app.css"
        body = m.group("body")
        assert re.search(r"\bbackground\s*:", body), f"{sel} lost its dimming background"
        assert re.search(r"backdrop-filter\s*:\s*none\b", body), f"{sel} must set backdrop-filter: none"
