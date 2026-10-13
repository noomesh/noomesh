# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`cargo-docker.sh clippy` must actually lint, not merely exit 0.

The rust images ship the `minimal` profile, so clippy and rustfmt are absent.
The wrapper had two branches: with `CARGO_DOCKER_COMPONENTS` set it ran as
root and `rustup component add`ed first; with it unset it went straight to
`cargo "$@"`. So `scripts/cargo-docker.sh clippy -- -D warnings` — the exact
invocation the script's own usage block advertises — ran an image with no
clippy in it. That is not a lint that passed. It is no lint, reported as
success, and three sessions read it as green on 2026-09-12 before CI
contradicted each of them.

These are static checks on purpose: they run in the Python job, which needs no
docker, so they cannot be silenced by the toolchain they are about.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SH = (REPO / "scripts/cargo-docker.sh").read_text()


# The two landmarks these checks reason about, found anywhere in the file so a
# refactor that moves them is judged on behaviour rather than on layout.
INFER = re.search(r"clippy\)\s*COMPONENTS=", SH)
PLAIN_BRANCH = re.search(r'if \[ -z "\$COMPONENTS" \]; then\s*\n\s*# shellcheck', SH)


def test_clippy_and_fmt_derive_their_component_without_the_env_var():
    assert INFER, (
        "`cargo-docker.sh clippy` no longer derives the clippy component, so it "
        "runs an image that has no clippy and reports success without linting"
    )
    fmt = re.search(r"fmt\)\s*COMPONENTS=(\S+)", SH)
    assert fmt, "`cargo-docker.sh fmt` no longer derives rustfmt"
    assert "rustfmt" in fmt.group(1), "the fmt arm must name the rustfmt component"


def test_the_env_var_still_overrides_the_inference():
    """The inference fills a gap; it must not take the decision away.

    A caller asking for a component this script has never heard of (miri, or
    two at once) must still win, so the inference only fires when nothing was
    stated.
    """
    assert INFER, "no inference to guard"
    head = SH[: INFER.start()]
    guard = re.search(r'if \[ -z "\$COMPONENTS" \]; then\s*\n\s*case ', head + SH[INFER.start() :][:200])
    assert guard, (
        "the inference must be wrapped in a test that CARGO_DOCKER_COMPONENTS "
        "is unset, or an explicit request is silently replaced"
    )


def test_the_plain_branch_is_unreachable_for_a_subcommand_that_needs_a_component():
    """The ordering is the whole fix.

    The inference has to happen BEFORE the `-z "$COMPONENTS"` test that picks
    the no-component branch, or it changes nothing at all.
    """
    assert INFER, "no inference at all"
    assert PLAIN_BRANCH, "the no-component branch is gone; this check needs rewriting"
    assert INFER.start() < PLAIN_BRANCH.start(), (
        "the component is inferred AFTER the branch that skips installing it, "
        "so clippy still runs without clippy"
    )


def test_the_usage_block_warns_that_a_cached_crate_reports_nothing():
    """A clean lint and an un-run lint look identical.

    The target dir persists, so a crate whose artifacts are fresh is not
    re-examined and no diagnostics are printed. Anyone reading that as "clean"
    is reading cache. The script says so, because the alternative is each
    session rediscovering it.
    """
    head = SH[: SH.index("set -euo pipefail")]
    assert "Checking" in head and "touch" in head, (
        "the usage block no longer explains that a cached crate produces no "
        "diagnostics and how to force a real re-lint"
    )


def test_every_file_this_script_cites_as_a_guard_exists():
    """A comment that names the wrong guard is worse than naming none.

    Line 103 read "`scripts/cargo-docker-exit-code.sh` is the guard" for the
    exit-code contract. That file has never existed, so the comment written to
    stop someone breaking the contract sent them looking for a file that is not
    there, and a reader who failed to find it would reasonably conclude the
    contract was unguarded. The real pin is in
    tests/test_cargo_docker_harness_reaches_the_repo.py.

    So every repo path this script cites must resolve. One exception, marked in
    the text itself: the historical note recording the name that was wrong.
    """
    cited = []
    for line in SH.splitlines():
        if "never existed" in line:
            continue  # the note about the phantom path, quoted on purpose
        for m in re.finditer(r"\b((?:scripts|tests)/[\w./-]+\.(?:sh|py))", line):
            cited.append(m.group(1))
    assert cited, "the script cites no guard at all any more"
    missing = [c for c in cited if not (REPO / c).exists()]
    assert not missing, (
        f"cargo-docker.sh cites paths that do not exist: {missing} — a reader "
        "sent to a missing guard concludes the contract is unguarded"
    )


def test_the_exit_code_guard_is_named_by_the_test_that_actually_pins_it():
    guard = REPO / "tests/test_cargo_docker_harness_reaches_the_repo.py"
    assert "test_cargo_s_exit_status_is_the_script_s_exit_status" in guard.read_text(), (
        "the test cargo-docker.sh points at for the exit-code contract is gone; "
        "update the comment rather than leaving it pointing at nothing"
    )
    assert "test_cargo_s_exit_status_is_the_script_s_exit_status" in SH, (
        "cargo-docker.sh no longer names the guard for its exec contract"
    )
