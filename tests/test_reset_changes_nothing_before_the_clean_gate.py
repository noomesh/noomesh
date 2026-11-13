# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""`noo stack reset` changes nothing before noomesh-clean.sh's docker gate.

The reset script's first change is `bash noomesh-clean.sh --deep -y`, whose
docker gate refuses ("cannot reach docker … nothing was removed") before any
removal (test_clean_volumes_this_project_only.py), and set -e then ends the
reset. So no command before that call may change the machine: a daemon stop,
a docker call or a removal there would run before docker has answered (rc.2
install matrix: offboard stopped the self-heal daemons first).
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESET = ROOT / "scripts" / "noomesh-reset.sh"
CHANGES = re.compile(r"^\s*(?:sudo\s+)?(?:rm|docker|systemctl|noo|pkill|kill|mv|bash\s+\S*noomesh-(?:stop|start)\.sh)\b")


def test_the_reset_runs_under_set_e_so_a_refused_clean_ends_it():
    assert re.search(r"^set -e", RESET.read_text(), re.M), "without set -e a refused clean would not end the reset"


def test_nothing_before_the_clean_call_changes_the_machine():
    lines = RESET.read_text().splitlines()
    at = next((i for i, l in enumerate(lines) if 'bash "$SCRIPT_DIR/noomesh-clean.sh"' in l), None)
    assert at is not None, "the clean call was not found: this test checks nothing"
    bad = [f"{i + 1}: {l.strip()}" for i, l in enumerate(lines[:at]) if not l.lstrip().startswith("#") and CHANGES.match(l)]
    assert not bad, "runs before noomesh-clean.sh's docker gate:\n" + "\n".join(bad)
