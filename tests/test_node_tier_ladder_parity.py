# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""One tier ladder, two crates that cannot see each other.

The canonical rules live in `gateway-rust/src/node_tier.rs`: it is the only
implementation that runs continuously, and it sits beside its consumers
(`slots_for_tier`, `normalize_tier`). Two more restate them in `noo-cli`,
where classification happens at BIRTH — `noo enroll` must answer before a
controller has heard of the node:

  * `derive_tier_facts` — over the enrolment facts JSON,
  * `derive_tier`       — over `noo-gate facts` text.

Nothing forces the three to agree. The crates have no workspace, no path
dependency, and `scripts/cargo-docker.sh` mounts only the crate being built —
so neither can even `include_str!` a file above its own root, let alone call
the other's function. No compiler spans them.

This module is the guard, and it parses the sources textually for the same
reason `test_job_type_declarations.py` does: importing a Rust declaration is
not possible, and a parse catches the drift that matters — a board added to
one list and not the others, or a threshold changed on one side.

Behaviour (as opposed to these constants) is pinned by
`gateway-rust/fixtures/node_tier_cases.json`, which the gateway's own unit
tests run in full. This file also asserts that corpus is still wired up,
because a fixture nothing reads is worse than no fixture: it looks like
coverage.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
GATEWAY_LADDER = REPO / "gateway-rust" / "src" / "node_tier.rs"
CLI_LADDERS = REPO / "noo-cli" / "src" / "commands" / "provision.rs"
CORPUS = REPO / "gateway-rust" / "fixtures" / "node_tier_cases.json"


def _boards(src: str) -> set[str]:
    """Every SBC model substring named in a source file."""
    return {
        m.lower()
        for m in re.findall(r'"(raspberry|jetson|orangepi|orange pi|rock)"', src)
    }


def test_the_board_list_is_the_same_everywhere() -> None:
    """A board recognised by one ladder and not another is a split brain.

    Concretely: enrol a machine whose model the CLI knows, and it lands on
    tier 4. If the gateway's list lacks it, continuous derivation reads the
    same box as tier 3 or 4-by-architecture, calls that a disagreement, and
    (armed) re-tiers a correctly classified node.
    """
    gateway = _boards(GATEWAY_LADDER.read_text())
    cli = _boards(CLI_LADDERS.read_text())
    assert gateway, "no board substrings parsed out of node_tier.rs"
    assert cli, "no board substrings parsed out of provision.rs"
    assert gateway == cli, (
        "the SBC model lists have diverged — "
        f"only in gateway: {sorted(gateway - cli)}; only in cli: {sorted(cli - gateway)}"
    )


def test_the_unified_memory_thresholds_match() -> None:
    """10 GB for tier 1, 4 GB for tier 2, on both sides.

    These decide whether a Mac mini is an edge box or a worker, and the pair
    was already wrong once (an 8 GB mini landed in tier 4). Two copies of a
    number are two chances to fix only one.
    """
    gateway = GATEWAY_LADDER.read_text()
    cli = CLI_LADDERS.read_text()
    for threshold in ("10.0", "4.0"):
        assert f"usable >= {threshold}" in gateway, f"gateway lost the {threshold} threshold"
        assert f"usable >= {threshold}" in cli, f"cli lost the {threshold} threshold"


def test_tier_one_is_never_assigned_from_a_bare_gpu_signal() -> None:
    """Both ladders must treat a discrete GPU as tier 2, not tier 1.

    Tier 1 carries TWO scheduler slots. The ladder deleted with
    `cluster add-node` keyed tier 1 off `VRAM >= 10`, and restoring that
    reasoning anywhere would quietly double a GPU box's concurrency relative
    to what enrolment assigned it.
    """
    gateway = GATEWAY_LADDER.read_text()
    cli = CLI_LADDERS.read_text()
    # In the gateway the GPU branch yields a literal `tier: 2`.
    gpu_branch = gateway.split("if f.gpu_present == Some(true)", 1)
    assert len(gpu_branch) == 2, "could not find the gateway's GPU branch"
    assert "tier: 2" in gpu_branch[1][:400], "the gateway's GPU branch no longer yields tier 2"
    # In the CLI both ladders return the string "2".
    assert '"2".into()' in cli, "the cli ladders no longer yield tier 2 for a GPU"


def test_the_corpus_is_actually_read() -> None:
    """A fixture nothing consumes looks like coverage and is not.

    The gateway embeds it with `include_str!` and asserts every case; if that
    line goes, the corpus silently stops being a contract.
    """
    assert CORPUS.is_file(), f"missing {CORPUS.relative_to(REPO)}"
    gateway = GATEWAY_LADDER.read_text()
    assert 'include_str!("../fixtures/node_tier_cases.json")' in gateway, (
        "node_tier.rs no longer embeds the shared corpus"
    )
    cases = json.loads(CORPUS.read_text())["cases"]
    assert len(cases) >= 8, "corpus too thin to be a contract"


def test_every_corpus_case_is_answerable_by_both_sides() -> None:
    """A `tier: null` case must say what the birth-time ladders answer instead.

    The gateway declines when the facts do not decide; the CLI ladders cannot,
    because at birth the enrolling script always sends every field and an
    absence there means the probe genuinely found nothing. That difference is
    legitimate, but it has to be WRITTEN DOWN per case — otherwise 'the two
    disagree here' and 'nobody thought about this case' look identical.
    """
    for case in json.loads(CORPUS.read_text())["cases"]:
        name = case.get("name", "<unnamed>")
        if case.get("tier") is None:
            assert "birth_time_default" in case, (
                f"case `{name}` expects the gateway to decline but does not say "
                "what the birth-time ladders answer"
            )
        assert case.get("tier") not in (5, 6), (
            f"case `{name}` derives a role tier; 5 and 6 are operator "
            "declarations about purpose, never hardware readings"
        )


def test_role_tiers_are_excluded_from_derivation() -> None:
    """Tiers 5 and 6 must be refused by name, not by luck.

    A companion is a Pi with a webcam: on hardware it classifies exactly like
    a tier-4 edge node. The only thing keeping a sensor proxy out of the
    scheduler is an explicit refusal.
    """
    gateway = GATEWAY_LADDER.read_text()
    assert "pub fn is_role_tier" in gateway, "the role-tier guard is gone"
    assert "tier == 5 || tier == 6" in gateway, "the role-tier guard no longer names 5 and 6"
    evaluators = (REPO / "gateway-rust" / "src" / "autonomy_evaluators.rs").read_text()
    assert "is_role_tier(declared)" in evaluators, (
        "node_tier_drift no longer skips role tiers — a companion could be "
        "re-tiered into schedulable work"
    )
