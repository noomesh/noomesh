# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Advice that follows an ENV change must name a command that recreates.

`noo stack restart` is `docker compose restart`, which keeps the old
environment. `--force` is what runs `up -d --force-recreate`
(`scripts/noomesh-restart.sh`).

Three places told the operator, in the same breath, that "an env change does not
survive a plain restart" and then to run the plain restart. It cost a live
outage on 2026-09-13: a rotated Telegram token left the gateway on the OLD value
after the restart the tool recommended, and because the old token had been
revoked at the provider, the channel stayed down and the symptom was a 401 that
reads as "you typed it wrong". The container's value only changed after --force,
confirmed by digest.

Static, and in the Python job, so it needs no CLI build.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CLI = REPO / "noo-cli/src"

# The sentence that means "this changed a value a container holds in its env".
ENV_CHANGE = re.compile(r"env change|environment change|hold the old value", re.I)
PLAIN_RESTART = re.compile(r"noo stack restart(?!\s*--force)")


def test_no_env_change_advice_recommends_a_plain_restart():
    offenders: list[str] = []
    for path in CLI.rglob("*.rs"):
        lines = path.read_text().splitlines()
        for n, line in enumerate(lines, 1):
            if not PLAIN_RESTART.search(line):
                continue
            # Two ways a line qualifies. Either it CLAIMS to recreate, which a
            # plain restart does not do — that is the case a 3-line window
            # missed, because the sentence about env changes sat six lines up in
            # a different print. Or the surrounding block says an env value
            # changed.
            claims_recreate = re.search(r"recreat", line, re.I)
            window = "\n".join(lines[max(0, n - 8) : n + 1])
            if claims_recreate or ENV_CHANGE.search(window):
                offenders.append(f"{path.relative_to(REPO)}:{n}\t{line.strip()}")
    assert not offenders, (
        "these tell the operator an env change needs a recreate and then name a "
        "plain restart, which keeps the old value:\n  " + "\n  ".join(offenders)
    )


def test_every_caller_of_the_restart_script_passes_force():
    """A caller that shells out to the script is applying a CHANGED value.

    Both callers ran it bare and then reported a recreate. Checking every caller
    rather than the one that bit us is the point: the NATS credential path had
    the identical bug and was found by widening this check, not by an incident.
    """
    offenders: list[str] = []
    for path in CLI.rglob("*.rs"):
        src = path.read_text()
        # Anchored on the SCRIPT, not on every bash call in a file that happens
        # to mention it — the first draft flagged sops invocations and unrelated
        # helpers, which is the shape that gets a check waived rather than read.
        for m in re.finditer(r"noomesh-restart\.sh", src):
            window = src[m.start() : m.start() + 700]
            call = re.search(r"Command::new\(\"bash\"\)[^;]*;", window, re.S)
            if not call:
                continue
            if '.arg("--force")' not in call.group(0) and '"--force"' not in call.group(0):
                line = src[: m.start()].count("\n") + 1
                offenders.append(f"{path.relative_to(REPO)}:{line}")
    assert not offenders, (
        "these run the restart script without --force, so the containers keep "
        "the old value while the tool reports a recreate:\n  " + "\n  ".join(offenders)
    )


def test_the_rotate_flag_passes_force_to_the_restart_script():
    """`--restart` must not claim a recreate it did not perform."""
    src = (CLI / "commands/secrets.rs").read_text()
    # The invocation itself, not a byte window after the path: a comment
    # explaining WHY --force is needed should not be able to push the call out
    # of range and turn this check green.
    call = re.search(r'Command::new\("bash"\)[^;]*;', src, re.S)
    assert call, "rotate no longer shells out to the restart script; update this check"
    window = call.group(0)
    assert '.arg("--force")' in window, (
        "rotate --restart runs the restart script without --force, so it leaves "
        "the old value in place and then prints 'stack recreated with the new values'"
    )
