# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The launcher's Fix line under a refused add-on names the command that
actually repairs it (noomesh-internal i570, 2a).

A resource the launcher cannot produce is refused with a reason that names
its own remedy: "`noo addons enable <addon>` mints it"
(noo-cli/src/addons/resources.rs `plan`). scripts/lib-dist.sh
`_addon_refused_lines` printed `Fix: noo addons upgrade <addon>` under it
regardless, and with the pin current `addons upgrade` says "nothing changed"
and mints nothing: the operator looped between the two on the 0.6.18 roll.

The reasons are rendered from the Rust format strings themselves, so a
reworded refusal cannot leave this test checking a sentence nothing prints.

Old code: every case below printed `noo addons upgrade rhaddon`."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ADDON = "rhaddon"


def _fix_line(why: str) -> str:
    r = subprocess.run(
        ["bash", "-c", 'source scripts/lib-dist.sh && _addon_refused_lines "$1" "$2"', "_", ADDON, why],
        cwd=REPO, capture_output=True, text=True, check=True,
    )
    lines = [l.strip() for l in r.stdout.splitlines() if l.strip().startswith("Fix:")]
    assert len(lines) == 1, r.stdout
    return lines[0]


def _rust_reasons() -> list[tuple[str, str]]:
    """Each resource refusal that names `noo addons enable`, rendered for
    ADDON, with the command it names."""
    src = (REPO / "noo-cli/src/addons/resources.rs").read_text()
    out = []
    for fmt in re.findall(r'format!\("(\{[a-z_]+\} is not in the encrypted store; `noo addons enable \{addon\}[^"]*)"\)', src):
        why = "resource r (shared_secret): " + fmt.replace("{addon}", ADDON).replace("{var}", "NOO_V").replace("{pw_var}", "NOO_PW")
        cmd = re.search(r"`(noo addons enable [^`]*)`", why).group(1)
        out.append((why, cmd))
    return out


def test_a_refusal_that_names_its_remedy_gets_that_remedy_as_the_fix() -> None:
    reasons = _rust_reasons()
    # The add-on key, the shared secret and the database password.
    assert len(reasons) >= 3, reasons
    assert any(c.endswith("--provision-only") for _, c in reasons), reasons
    for why, cmd in reasons:
        fix = _fix_line(why)
        assert fix.startswith(f"Fix:  {cmd}   "), (why, fix)
        assert "addons upgrade" not in fix, fix
    # Any other reason keeps the upgrade remedy, and a command for ANOTHER
    # add-on is never borrowed.
    assert _fix_line("its pinned image x is not on this host").startswith(f"Fix:  noo addons upgrade {ADDON}   ")
    assert _fix_line("see `noo addons enable other` mints it").startswith(f"Fix:  noo addons upgrade {ADDON}   ")
