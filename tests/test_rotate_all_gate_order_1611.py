# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`noo security pki rotate-all`: the order of the gate's branches.

A gate that could not see (Blind) must keep the rotated certificates and
leave before any revert step; a revert must re-sync `pki/public/` before it
restarts the consumers; and "REVERT DID NOT RECOVER" belongs to the
Unhealthy second-gate arm alone. The decision itself is unit-tested in
`security_local.rs` (`rotate_gate_tests`); this guards how `pki_rotate_all`
acts on it.
"""

from __future__ import annotations

from pathlib import Path

from tests import _rust_src as rs

SRC = Path(__file__).resolve().parents[1] / "noo-cli/src/commands/security_local.rs"


def _code() -> str:
    return rs.own_code(SRC.read_text())


def _body() -> str:
    return rs.fn_body(_code(), "pub fn pki_rotate_all(")


def test_the_blind_branch_exits_before_any_revert_step():
    body = _body()
    blind = body.index("GateAction::KeepUnconfirmed")
    exit_at = body.index('"rotation_unconfirmed"', blind)
    revert_at = body.index("copy_tree(&backup_dir", blind)
    assert exit_at < revert_at, "the Blind branch must fail() before the revert's copy_tree"
    branch = body[blind:revert_at]
    assert "copy_tree" not in branch and '"restart"' not in branch and "restart_each" not in branch and "apply_to_stack" not in branch, branch


def test_the_resync_precedes_the_restart_in_the_revert_path():
    body = _body()
    revert = body.index("copy_tree(&backup_dir")
    resync = body.index("sync_public_view()", revert)
    restart = body.index("apply_to_stack(&plan", revert)
    assert revert < resync < restart, "restore, then re-sync pki/public/, then restart"


def test_revert_did_not_recover_is_only_the_unhealthy_second_gate_arm():
    code = _code()
    assert code.count("REVERT DID NOT RECOVER") == 1, "the phrase must appear once"
    body = _body()
    at = body.index("REVERT DID NOT RECOVER")
    arm = body.rindex("GateOutcome::", 0, at)
    assert body[arm:].startswith("GateOutcome::Unhealthy(detail2)"), body[arm : arm + 60]
    assert "gate2" in body[: at], "it belongs to the revert's own (second) gate"
