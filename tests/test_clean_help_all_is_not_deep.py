# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""`noomesh-clean.sh --help` says what --all really does (i677a 3e).

--all is --volumes + --images + --cache. It never sets DEEP_CLEAN, so it runs
no host-wide image prune, wipes no data dir, removes no PKI or secrets, and
keeps the postgres/redis/noo-data volumes. The help said "Same as --deep",
which a stranger starting over would read as the full wipe.
"""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "noomesh-clean.sh"


def test_the_all_help_line_does_not_claim_deep():
    out = subprocess.run(["bash", str(SCRIPT), "--help"], capture_output=True, text=True, timeout=30, cwd=ROOT)
    assert out.returncode == 0, out.stderr
    lines = [l for l in out.stdout.splitlines() if re.match(r"\s+--all\b", l)]
    assert len(lines) == 1, out.stdout
    assert "same as --deep" not in lines[0].lower(), lines[0]
    assert "NOT --deep" in lines[0], lines[0]


def test_all_really_is_not_deep_in_the_parser():
    src = SCRIPT.read_text()
    m = re.search(r"\n\s+--all\)\n(.*?);;", src, re.S)
    assert m, "the --all case was not found: this test checks nothing"
    assert "DEEP_CLEAN=true" not in m.group(1), m.group(1)
