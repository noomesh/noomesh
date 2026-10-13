# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The container test harness must let a test read the repo.

`scripts/cargo-docker.sh` mounted only the crate directory, so inside the
container `/w/../scripts` did not exist and every test that reads a repo file
outside its own crate took its skip arm. The assertions were real; the
harness never let them execute; the green tick said the contract was checked.
That is worse than an absent test.

The one this was found through —
`noo-cli/src/commands/node_fetch.rs::neither_poller_has_an_unverified_lane` —
asserts that `noo-fetch.sh` and `prep-host.sh` carry no unverified-transport
lane. It had never run in CI.

These checks run in the Python job, which always has the whole tree, so they
cannot be disabled by the very thing they are checking.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SH = (REPO / "scripts/cargo-docker.sh").read_text()
FETCH = (REPO / "noo-cli/src/commands/node_fetch.rs").read_text()


def test_the_harness_mounts_the_repo_root_not_just_the_crate():
    assert "-v $REPO_ROOT:/repo -w /repo/$CRATE_REL" in SH, (
        "cargo-docker.sh no longer mounts the repo root; every repo-reaching "
        "test in every crate is silently inert again"
    )
    assert "-v $CRATE_DIR:/w -w /w" in SH, (
        "the crate-only fallback for an out-of-tree CARGO_DOCKER_CRATE is gone; "
        "it should warn, not disappear"
    )


def test_the_harness_marks_itself_so_a_skip_can_be_made_loud():
    assert "-e NOO_CARGO_DOCKER=1" in SH, (
        "cargo-docker.sh no longer sets NOO_CARGO_DOCKER; a test cannot tell a "
        "legitimate skip from a harness regression"
    )


def test_cargo_s_exit_status_is_the_script_s_exit_status():
    """A harness that swallows a failure is the same bug one level up.

    `exec` is what guarantees it: the shell process BECOMES docker, so there
    is nothing left to run after cargo and nothing to overwrite `$?`. A
    trailing cleanup command would silently become the exit code.
    """
    lines = [ln.strip() for ln in SH.splitlines() if ln.strip()]
    docker_runs = [ln for ln in lines if ln.startswith("docker run") or ln.startswith("exec docker run")]
    assert docker_runs, "no docker run in cargo-docker.sh"
    assert all(ln.startswith("exec ") for ln in docker_runs), (
        f"a docker run is not exec'd, so its exit code can be masked: {docker_runs}"
    )
    # Nothing may follow the final exec at top level.
    tail = SH[SH.rindex("exec docker run"):]
    trailing = [
        ln for ln in tail.splitlines()[1:]
        if ln.strip() and not ln.lstrip().startswith("#")
        and not ln.startswith((" ", "\t", "-", '"', "'"))
        and not ln.strip().startswith(("rustup", "cargo", '"'))
    ]
    assert not trailing, f"commands follow the final exec: {trailing}"


def test_the_repo_reaching_tests_panic_under_the_harness_instead_of_skipping():
    """The band-aid becomes a control.

    A skip arm that prints and returns is indistinguishable from a pass. Under
    the harness — where `scripts/` is guaranteed present — an unreadable
    `scripts/` is now a failure.
    """
    assert "fn scripts_dir()" in FETCH, (
        "node_fetch.rs no longer routes repo reads through a single helper; the "
        "skip arms are back to being copy-pasted and silent"
    )
    assert 'std::env::var_os("NOO_CARGO_DOCKER").is_none()' in FETCH, (
        "scripts_dir() no longer fails loudly under the container harness"
    )
    # "assert the file the test claims to read is readable, before asserting
    # on its contents" — the check that would have caught 97b itself.
    assert 'root.join("noo-apply.sh").is_file()' in FETCH

    # No test in this module may still carry a silent skip arm.
    silent = re.findall(r'eprintln!\("scripts/ not beside the crate[^"]*skipping"\)', FETCH)
    assert len(silent) == 1, (
        f"{len(silent)} silent skip arms in node_fetch.rs; exactly one belongs, "
        "inside scripts_dir(), guarded by the NOO_CARGO_DOCKER assertion"
    )


def test_the_contract_that_test_actually_asserts_still_holds():
    """Assert the contract here too, in a job that has always run it.

    `neither_poller_has_an_unverified_lane` is real again, but it was inert
    for long enough that the contract deserves a second, always-executed
    home. Same predicates, same exact code spellings.
    """
    fetch = (REPO / "scripts/noo-fetch.sh").read_text()
    prep = (REPO / "scripts/prep-host.sh").read_text()
    assert "$CONF_DIR/pki/ca.crt" in fetch
    assert "$CONF_DIR/controller-insecure" not in fetch
    assert 'TLS="-k"' not in fetch
    assert "touch /etc/noo/controller-insecure" not in prep
    assert 'elif [ "${PREP_INSECURE:-0}" = "1" ]' not in prep
    assert "PREP_CA_SHA256 is required" in prep
