# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A node gets the privileged helper the harness lifecycle needs.

The harness is started by a `noo-hostd` op, because the agent runs under
`NoNewPrivileges=true` and cannot sudo. So a Linux node with
no hostd cannot start a harness at all.

Until 2026-09-19 nothing put one there, on any of three paths:
  - `provision` never staged the `hostd-binary` kind, though the applier and
    the bundle signer both support it;
  - the release carried `noo-hostd-aarch64-apple-darwin` and no Linux build;
  - `cluster upgrade-hostd` cross-builds from `repo_root()/node-agent-go`,
    which a standalone controller does not have.

So the fix has to hold on all three, and these pin the two that are code.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github/workflows/noo-cli-release.yml"
PROVISION = REPO / "noo-cli/src/commands/provision.rs"
UPGRADE = REPO / "noo-cli/src/commands/upgrade.rs"
APPLIER = REPO / "scripts/noo-apply.sh"

LINUX_HOSTD = [
    "noo-hostd-x86_64-unknown-linux-gnu",
    "noo-hostd-aarch64-unknown-linux-gnu",
]


def test_the_release_builds_and_attaches_a_linux_helper() -> None:
    wf = WORKFLOW.read_text()
    for asset in LINUX_HOSTD:
        assert f"dist/{asset}" in wf, f"{asset} is never produced by the release lane"
        assert f"dist/{asset} \\" in wf or f"dist/{asset}\n" in wf, (
            f"{asset} is built but never attached to the release"
        )
    # Built from the Go cross-builder, not hand-copied from somewhere.
    assert "BINARY=noo-hostd bash build-cross.sh linux/amd64" in wf
    assert "BINARY=noo-hostd bash build-cross.sh linux/arm64" in wf


def test_provision_stages_the_helper_as_a_bundle_kind() -> None:
    src = PROVISION.read_text()
    assert "hostd_asset_for" in src, "no mapper from a node's platform to a hostd asset"
    assert '"hostd-binary"' in src, (
        "provision must stage the hostd-binary kind — the applier has always "
        "handled it and nothing ever sent one"
    )
    # The applier's side has to know the kind, or the bundle is refused.
    assert "hostd-binary" in APPLIER.read_text()


def test_the_helper_ships_to_darwin_too() -> None:
    """The previous pin said darwin "needs no helper" because the agent
    drives launchctl as the enrolling user. That was true of a per-user
    LaunchAgent and false of what the root applier actually installs: a
    SYSTEM LaunchDaemon, which a user process cannot bootstrap. host6
    (2026-09-22) sat at harness=absent with no privilege path to fix it.
    Darwin now gets the helper as a system daemon — one design, two
    runtimes — and the release lane has built the binary all along."""
    src = PROVISION.read_text()
    body = src.split("pub(crate) fn hostd_asset_for", 1)[1].split("\n}", 1)[0]
    assert '"linux"' in body
    assert '"darwin"' in body and "noo-hostd-aarch64-apple-darwin" in body, (
        "darwin nodes have no privileged path to start the harness without the helper"
    )


def test_the_controller_caches_the_helper_for_the_rail() -> None:
    src = UPGRADE.read_text()
    assert "hostd_asset_for" in src, (
        "`noo upgrade` must cache the hostd asset, or provision has nothing to stage"
    )
    # Cached by the same loop that fetches the gateway binary, so the two
    # cannot drift into different freshness rules.
    assert "gateway_assets.iter().chain(hostd_assets.iter())" in src
