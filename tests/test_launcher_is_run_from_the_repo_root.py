# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every launcher-script spawn sets its working directory.

`scripts/noomesh-restart.sh` and its siblings resolve `secrets/env.sops`,
`.env` and the compose files RELATIVE TO THEIR CWD. Spawned from anywhere
else they abort with `secrets load failed` before touching a container.

That is not hypothetical. `noo security service-key provision` shipped
without `.current_dir(...)` on 2026-09-21 and the controller hit it on the
first live run: the key was minted and stored, the launcher aborted, and the
verb correctly reported "stored but not live" — honest, but the cause was a
missing argument here, not anything about the containers.

`rotate` had always passed it. One call site out of several is exactly the
shape a guard is for: the rule is invisible at the call site, and its absence
fails somewhere else entirely.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLI_SRC = ROOT / "noo-cli" / "src"
# The scripts that read repo-relative paths. A script added here without a
# cwd is the same bug under a new name.
LAUNCHERS = ("noomesh-restart.sh", "noomesh-start.sh", "noomesh-stop.sh")


def _spawns() -> list[tuple[Path, int, str]]:
    """Every `Command::new(...)` block that names a launcher script."""
    out: list[tuple[Path, int, str]] = []
    for f in sorted(CLI_SRC.rglob("*.rs")):
        text = f.read_text(encoding="utf-8")
        for m in re.finditer(r"Command::new\(", text):
            # The statement runs to its terminating semicolon.
            end = text.find(";", m.start())
            if end == -1:
                continue
            block = text[m.start():end]
            if any(s in block for s in LAUNCHERS):
                line = text.count("\n", 0, m.start()) + 1
                out.append((f, line, block))
    return out


def test_the_guard_finds_the_spawns_at_all() -> None:
    """A regex that matches nothing would make the assertion below vacuous —
    which is how a guard passes while the bug is present."""
    spawns = _spawns()
    assert spawns, "parsed no launcher spawns from noo-cli/src; the pattern is wrong"


def test_every_launcher_spawn_sets_its_working_directory() -> None:
    missing = [
        f"  {f.relative_to(ROOT)}:{line}"
        for f, line, block in _spawns()
        if "current_dir" not in block
    ]
    assert not missing, (
        "these spawn a launcher script without setting a working directory:\n"
        + "\n".join(missing)
        + "\n\nThe script resolves secrets/env.sops and the compose files relative to its "
        "CWD, so from anywhere else it aborts with `secrets load failed` before touching a "
        "container — and the caller sees a consumer problem instead of a missing argument."
    )
