# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Nothing imports the retired Python gateway modules.

`noomesh.gateway.app` and `noomesh.gateway.coordinator` were deleted in the
Rust port; `noomesh.gateway.auth` (the Python login: an env-admin bootstrap,
a JWT signer defaulting to `dev-secret-change-in-production`, a `UserStore`
built at import time) was deleted once its last importer — worker_pool, for
`get_secret` alone — moved to `noomesh.secret_env`.

Every surviving import of them sat inside `try: … except Exception: pass`,
so it could never fail loudly: it just read as a working fallback. This
keeps them from coming back the same way.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "noomesh"

RETIRED = ("app", "auth", "coordinator")

# Absolute (`noomesh.gateway.app`), package-relative from inside gateway/
# (`from .app import`), and from a sibling package (`from ..gateway.app`).
PATTERNS = [
    re.compile(rf"^\s*(?:import|from)\s+noomesh\.gateway\.({'|'.join(RETIRED)})\b", re.M),
    re.compile(rf"^\s*from\s+\.\.gateway\.({'|'.join(RETIRED)})\s+import\b", re.M),
    re.compile(rf"^\s*from\s+\.\.gateway\s+import\s+({'|'.join(RETIRED)})\b", re.M),
    re.compile(rf"^\s*from\s+noomesh\.gateway\s+import\s+({'|'.join(RETIRED)})\b", re.M),
]
GATEWAY_RELATIVE = re.compile(rf"^\s*from\s+\.({'|'.join(RETIRED)})\s+import\b", re.M)


def test_the_retired_modules_are_gone() -> None:
    for name in RETIRED:
        assert not (SRC / "gateway" / f"{name}.py").exists(), f"gateway/{name}.py is back"


def test_nothing_imports_a_retired_gateway_module() -> None:
    files = sorted(SRC.rglob("*.py"))
    assert len(files) > 100, "scanned suspiciously few files — wrong root?"
    hits: list[str] = []
    for f in files:
        text = f.read_text(encoding="utf-8", errors="replace")
        pats = list(PATTERNS)
        if f.parent == SRC / "gateway":
            pats.append(GATEWAY_RELATIVE)
        for pat in pats:
            for m in pat.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                hits.append(f"{f.relative_to(ROOT)}:{line}: {m.group(0).strip()}")
    assert not hits, "imports of retired Python gateway modules:\n" + "\n".join(hits)


def test_the_scan_would_see_one() -> None:
    """Plant: each pattern matches the shape it is for."""
    samples = [
        "        import noomesh.gateway.app as _app_mod",
        "        from ..gateway.app import conversation_store",
        "from noomesh.gateway.auth import get_secret",
        "    from ..gateway.coordinator import get_coordinator",
    ]
    for s in samples:
        assert any(p.search(s) for p in PATTERNS), s
    assert GATEWAY_RELATIVE.search("        from .auth import get_secret")
