# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Under `noo onboard`, the scripts it runs do not print their by-hand notes.

A stranger's literal onboard run (0.6.28, a fresh Ubuntu 24.04 VM) showed
notes written for a person running a script by hand, in the middle of a
wizard that does those steps itself: the SOPS "To switch the cluster onto
encrypted secrets: 1. sops -d … | head" how-to (which prints secrets, and
which the wizard's own summary later says NEVER to do), the launcher's
endpoint and verb guide, "no chat model installed — pick one" one step before
the wizard picks one, and "Location unset — the collector will show
'tailnet'". Onboard sets NOO_ONBOARD=1 on its own process (noo-cli
`onboard/mod.rs` ONBOARD_ENV); these run the real blocks of each script with
and without it. Lines that report an error are never gated.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

# Every gated call prints its name and arguments, so a test sees what would
# have been said.
STUBS = "\n".join(
    f'{name}() {{ printf "{name} %s\\n" "$*"; }}'
    for name in ("ui_note", "ui_phase", "ui_rule", "ui_guide_cmd", "print_service_urls", "ui_kv")
)


def run(script: str, onboard: bool) -> str:
    env = {k: v for k, v in os.environ.items() if k != "NOO_ONBOARD"}
    if onboard:
        env["NOO_ONBOARD"] = "1"
    out = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return out.stdout + out.stderr


def block(path: Path, start: str, end: str) -> str:
    """The text of `path` from the line holding `start` through the first
    line equal to `end` after it."""
    lines = path.read_text().splitlines()
    i = next(n for n, line in enumerate(lines) if start in line)
    j = next(n for n in range(i, len(lines)) if lines[n] == end)
    return "\n".join(lines[i : j + 1]) + "\n"


def test_the_sops_switch_over_how_to_is_not_said_under_onboard():
    text = block(SCRIPTS / "noo-secrets-sops-init.sh", 'if [ "${NOO_ONBOARD:-}" != 1 ]; then', "fi")
    assert "== Done. To switch the cluster onto encrypted secrets:" in text, "the gate no longer holds the how-to"
    script = f'ENC_FILE=secrets/env.sops\n{text}'
    by_hand = run(script, onboard=False)
    assert "sops -d --input-type dotenv" in by_hand, "a person running the script still gets the how-to"
    assert run(script, onboard=True).strip() == "", "onboard's run printed the by-hand how-to"


def test_the_launchers_endpoint_guide_is_not_said_under_onboard():
    text = block(SCRIPTS / "noomesh-start.sh", "# The endpoint and verb guide is for a person", "fi")
    assert 'ui_phase "Endpoints"' in text and 'ui_guide_cmd "noo stack stop"' in text
    by_hand = run(f"{STUBS}\n{text}", onboard=False)
    assert "ui_phase Endpoints" in by_hand and "ui_guide_cmd noo stack status" in by_hand
    assert run(f"{STUBS}\n{text}", onboard=True).strip() == ""


def test_the_pick_a_model_note_is_not_said_under_onboard():
    text = block(SCRIPTS / "noomesh-start.sh", 'if docker exec "$OLLAMA_CTR" ollama list 2>/dev/null | tail -n +2', "        fi")
    # A fresh container: nothing pulled.
    script = f'{STUBS}\ndocker() {{ :; }}\nOLLAMA_CTR=noo-ollama-embed\n{text}'
    assert "no chat model installed" in run(script, onboard=False)
    assert "no chat model installed" not in run(script, onboard=True)
    # An install that has a chat model keeps its line either way.
    has = f'{STUBS}\ndocker() {{ printf "NAME\\nqwen3:8b x\\n"; }}\nOLLAMA_CTR=noo-ollama\n{text}'
    assert "no OLLAMA_MODEL declared" in run(has, onboard=True)


def test_the_unset_location_line_is_not_said_under_onboard(tmp_path):
    # A tailscale that reports no relay: the unset branch.
    script = f'cd "{tmp_path}"\n{STUBS}\ntailscale() {{ :; }}\n. "{SCRIPTS / "lib-bind-addr.sh"}"\nunset NODE_LOCATION\nresolve_location\n'
    assert "unset — the collector will show 'tailnet'" in run(script, onboard=False)
    assert "Location" not in run(script, onboard=True)
