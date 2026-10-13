# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The platform-package pattern has two homes that must agree.

`noo-hostd` reports which platform packages a node has and which are held
(`PlatformPackagePattern`), and the host-updates runbook
tells the operator to hold exactly that set with one command. If they drift,
`noo cluster verify` warns about packages the runbook never told anyone to
hold — or stays quiet about ones it did.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GO = ROOT / "node-agent-go/internal/hostd/hostfacts.go"
RUNBOOK = ROOT / "docs/operating/runbooks/host-updates.md"


def _go_pattern() -> str:
    m = re.search(r"PlatformPackagePattern = regexp\.MustCompile\(`([^`]+)`\)", GO.read_text())
    assert m, "PlatformPackagePattern not found in hostfacts.go — the parse broke"
    return m.group(1)


def _runbook_pattern() -> str:
    m = re.search(r"grep -E '(\^\(linux[^']+)'", RUNBOOK.read_text())
    assert m, "the hold command's grep -E pattern not found in the runbook — the parse broke"
    return m.group(1)


def test_the_runbook_holds_exactly_what_hostd_reports() -> None:
    assert _go_pattern() == _runbook_pattern()


def test_the_pattern_selects_the_platform_and_nothing_else() -> None:
    pat = re.compile(_go_pattern())
    for pkg in ("linux-system76", "linux-generic", "nvidia-driver-580", "nvidia-dkms-580",
                "docker-ce", "docker-compose-plugin", "containerd.io", "tailscale",
                "libnvidia-container1", "nvidia-container-toolkit-base"):
        assert pat.match(pkg), pkg
    for pkg in ("vim", "libc6", "linux-firmware", "docker.io", "nvidia-settings", "tailscale-archive-keyring"):
        assert not pat.match(pkg), pkg
