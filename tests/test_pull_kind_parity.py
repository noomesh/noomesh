# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every `/pull` kind the CLI sends must be a kind the agent's switch handles.

The kind string is declared in three places that cannot see each other: the
Rust CLI that sends it, the Go switch that dispatches it, and the error
message that lists what is supported. Nothing in either compiler compares
them.

This test exists because all three drifted at once and shipped. `kind:
sandbox-base` was added to the CLI and documented in `pull.go`'s header, but
the `case` arm was lost — a Python edit script asserted its way out after the
first replacement and before the write, and the `go build` that followed
proved only that the UNCHANGED file still compiled. `noo cluster sync-images`
against an arm64 node would have answered

    400 unsupported pull kind 'sandbox-base'

The Go tests passed, because they call `BuildSandboxBase` directly and never
route to it. A test that exercises a function is not a test that the function
is reachable.
"""

from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
PULL_GO = REPO / "node-agent-go/internal/api/pull.go"
CLI = REPO / "noo-cli/src/commands"

# Kinds the agent implements but no CLI command sends today. Each entry is a
# kind reachable by hand or by a future caller, with why it is still declared.
# It must only ever get shorter.
UNSENT: dict[str, str] = {}


def switch_kinds() -> set[str]:
    """The `case "x":` arms of handlePull's switch."""
    body = PULL_GO.read_text()
    start = body.index("func (s *Server) handlePull(")
    return set(re.findall(r'^\tcase "([a-z0-9-]+)":', body[start:], re.M))


def documented_kinds() -> set[str]:
    """The kinds the default arm's error message advertises."""
    body = PULL_GO.read_text()
    m = re.search(r"\(kinds: ([^;)]+)[;)]", body)
    assert m, "pull.go no longer lists its kinds in the unsupported-kind error"
    return {k.strip() for k in m.group(1).split(",") if k.strip()}


def _without_test_modules(src: str) -> str:
    """Drop every `#[cfg(test)] mod … { … }` block (brace-matched), keep the rest."""
    out, i = [], 0
    while True:
        j = src.find("#[cfg(test)]", i)
        if j < 0:
            out.append(src[i:])
            return "".join(out)
        out.append(src[i:j])
        k = src.find("{", j)
        if k < 0:
            return "".join(out)
        depth, n = 0, k
        while n < len(src):
            if src[n] == "{":
                depth += 1
            elif src[n] == "}":
                depth -= 1
                if depth == 0:
                    break
            n += 1
        i = n + 1


def cli_kinds() -> set[str]:
    """Kinds sent by the CLI: `"kind": "x"` in a /pull request body."""
    found: set[str] = set()
    for f in CLI.rglob("*.rs"):
        src = f.read_text()
        if "/pull" not in src:
            continue
        # Production code only: a `#[cfg(test)]` module's fixtures are not
        # request bodies (the fit screen's `"budget": {"kind": "unified"}`).
        src = _without_test_modules(src)
        found |= set(re.findall(r'"kind"\s*:\s*"([a-z0-9-]+)"', src))
    return found


def test_the_switch_and_its_error_message_agree() -> None:
    switch, documented = switch_kinds(), documented_kinds()
    assert switch, "found no case arms — this test is reading the wrong thing"
    assert switch == documented, (
        f"handlePull dispatches {sorted(switch)} but its error message "
        f"advertises {sorted(documented)}"
    )


def test_every_kind_the_cli_sends_is_dispatched() -> None:
    sent, switch = cli_kinds(), switch_kinds()
    assert sent, "found no kinds in the CLI — this test is reading the wrong thing"
    undispatched = sorted(sent - switch)
    assert not undispatched, (
        f"the CLI sends {undispatched}, which handlePull answers 400 for. "
        "A kind is added in two places or it is added in none."
    )


def test_no_kind_is_dispatched_that_nothing_sends() -> None:
    # The other direction: a case arm nothing reaches is dead weight that
    # reads as a working feature.
    orphans = sorted(switch_kinds() - cli_kinds() - set(UNSENT))
    assert not orphans, (
        f"handlePull dispatches {orphans}, which no CLI command sends. "
        "Wire a caller, delete the arm, or record it in UNSENT with a reason."
    )
