# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The upgrade's docker calls are bounded (i1149).

After a power cut the controller's hard NFS mount hung, and `noo upgrade
--all` printed `# Stack` and sat silent for hours on a bare
`Command::new("docker")... .output()` (`running_gateway_tag`): a child that
blocks on a dead mount lives until the server answers, and `.output()` waits
for it. Every docker call in `noo-cli/src/commands/upgrade.rs` now goes
through `crate::bounded::docker` (spawn, wait with a deadline, kill on
expiry), and `onboard::sh::docker` (used across onboard and the launchers)
does too.

This guard refuses a new `Command::new("docker")` in upgrade.rs, and a
return of one inside the shared helper. Sites that are allowed to stay
unbounded are listed in ALLOWED with the later item that migrates them;
today there are none in upgrade.rs (the batch that bounds the remaining
direct `Command::new("docker")` calls in cluster_verify, doctor, stack
status and the rest is the later `container_state()` item).

It also pins the order that makes the refusal safe: the storage check runs
at the top of `upgrade`, before the self-update, the channel step and the
stack work.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests import _rust_src as rs

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "noo-cli" / "src"

DOCKER_CMD = re.compile(r'Command::new\(\s*"docker"\s*\)')

# (file, fn name) -> reason. Empty: every docker call in upgrade.rs is bounded.
ALLOWED: dict[tuple[str, str], str] = {}


def code_of(rel: str) -> str:
    return rs.own_code((SRC / rel).read_text(encoding="utf-8"))


def unbounded_sites(code: str) -> list[int]:
    return [m.start() for m in DOCKER_CMD.finditer(code)]


def test_the_detector_sees_the_shapes_the_hang_had():
    old = 'std::process::Command::new("docker").args(["inspect", "x"]).output().ok()?;'
    assert unbounded_sites(old)
    assert unbounded_sites('Command::new( "docker" )\n    .args(a)\n    .status()')
    assert not unbounded_sites('crate::bounded::docker(&["inspect", "x"], limit)')
    assert not unbounded_sites('Command::new(format!("docker-credential-{helper}"))')


def test_upgrade_rs_spawns_no_docker_outside_the_bounded_helper():
    code = code_of("commands/upgrade.rs")
    hits = unbounded_sites(code)
    allowed = [k for k in ALLOWED if k[0] == "commands/upgrade.rs"]
    assert len(hits) == len(allowed), (
        "an unbounded `Command::new(\"docker\")` is back in upgrade.rs (i1149: a hung mount "
        "made one sit for hours): use crate::bounded::docker, or list the site in ALLOWED "
        f"with the item that will migrate it; found {len(hits)} at offsets {hits}")


def test_the_upgrade_asks_docker_through_the_bounded_helper():
    code = code_of("commands/upgrade.rs")
    tag = rs.fn_body(code, "fn running_gateway_tag(")
    assert "crate::bounded::docker(" in tag, tag
    mapped = rs.fn_body(code, "fn gateway_tag_from(")
    assert "Bounded::TimedOut" in mapped and "GatewayTag::TimedOut" in mapped, "a timeout is its own answer, never None"
    embed = rs.fn_body(code, "fn ensure_embedder_after_roll(")
    assert "crate::bounded::docker(" in embed, embed


def test_the_shared_onboard_docker_helper_is_bounded():
    code = code_of("onboard/sh.rs")
    body = rs.fn_body(code, "pub fn docker(")
    assert not unbounded_sites(body), body
    assert "crate::bounded::docker(" in body, body
    assert "docker_limit(" in body, body


def test_the_storage_check_runs_before_anything_is_touched():
    code = code_of("commands/upgrade.rs")
    up = rs.fn_body(code, "pub fn upgrade(")
    call = up.index("refuse_when_storage_hangs(g)")
    for later in ("if stage2 {", "super::channel::request(&chan)", "resolve_latest(g)", "run_fleet_stages("):
        assert call < up.index(later), f"the storage check must come before {later}"
    check = rs.fn_body(code, "fn refuse_when_storage_hangs(")
    assert "probe_data_roots()" in check and "running_gateway_tag" in check, check
    assert "fail(" in check, "a hung mount stops the upgrade"
