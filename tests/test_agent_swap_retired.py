# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""an earlier change A3: the gateway-signed agent swap is retired, on every hop.

The swap was the second lane that put code on a node: `noo cluster
upgrade-agents` exported an agent binary, the GATEWAY signed its manifest
with its own TLS key, the agent pulled it (`/pull kind=binary`) and the root
`noo-hostd` installed it. A compromised gateway was therefore root on every
Linux node. The behavioural tests live beside each hop
(`TestPullKindBinaryIsRefused`, `TestSwapAgentIsRefused`,
`binary_manifest_is_refused`, `the_retired_swap_lane_is_not_called`); this
file pins the cross-language facts none of them can see alone.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GO = ROOT / "node-agent-go"


def test_no_hop_of_the_swap_survives() -> None:
    gone = [
        GO / "internal/docker/binary_artifact.go",
        GO / "internal/hostd/manifest.go",
        GO / "internal/hostd/swap_secrets.go",
    ]
    assert [str(p.relative_to(ROOT)) for p in gone if p.exists()] == []
    artifacts = (ROOT / "gateway-rust/src/routes/artifacts.rs").read_text()
    assert "EncodingKey" not in artifacts, "the gateway signs artifact manifests again"
    assert '"binary" => Some(' not in artifacts, "the gateway serves a binary store again"
    hostd = (GO / "internal/hostd/worker_ops.go").read_text()
    assert "Getenv(\"NOO_HOSTD_ALLOW_UNSIGNED\")" not in hostd, "the unsigned-swap escape is back"
    assert '"swap-agent":     {Name: "swap-agent", Run: opSwapAgentRetired}' in hostd


def test_the_swap_op_name_stays_advertised_for_the_applier() -> None:
    """noo-apply proves a freshly installed hostd is the one running by a new
    heartbeat that names `swap-agent`. Every applier already on a node does
    that (v0.2.101 included), so dropping the NAME from the op table would
    make the old applier revert the new hostd. The name stays; its op refuses."""
    applier = (ROOT / "scripts/noo-apply.sh").read_text()
    assert re.search(r"grep -q 'swap-agent' \"\$HB\"", applier), (
        "the applier no longer keys its hostd check on swap-agent — if that is deliberate, "
        "this test (and the op-table entry kept for it) can go"
    )


def test_upgrade_agents_rides_the_bundle_rail() -> None:
    src = (ROOT / "noo-cli/src/commands/cluster_provision_subprocess.rs").read_text()
    fn = src[src.index("pub fn cluster_upgrade_agents("):]
    fn = fn[: fn.index("\n}\n")]
    assert "/pull" not in fn, "upgrade-agents talks to an agent's /pull again"
    assert "upgrade_agents_child_args" in fn


def test_the_binary_store_is_neither_mounted_nor_served() -> None:
    """The bin store fed only the swap. With it retired, no container mounts
    it and model-cache serves no /bin/ tree a node could fetch code from."""
    compose = (ROOT / "docker-compose.cluster.yml").read_text()
    assert ":/artifacts/bin" not in compose and ":/bin-store" not in compose
    assert "BIN_DIR" not in compose
    nginx = (ROOT / "docker/model-cache.locations.conf").read_text()
    assert not re.search(r"^\s*location\s+/bin/", nginx, re.M), "model-cache serves /bin/ again"
    assert "/bin-store" not in re.sub(r"#.*", "", nginx)
