# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""docker/apparmor-noo-sandbox is Docker's default container profile with
exactly the user-namespace and mount rules Bubblewrap needs, instead of
`deny mount,`. Pins that shape: every denial docker-default carries is
still there, the three rules Bubblewrap needs are there, nothing else
was loosened — and the places that tell an operator about it (env.md,
the compose comment, the standalone slice) agree on the file and the
profile name. A loosened profile would fail nowhere at runtime: the
sandbox would simply run with more than it needs.

Parsing with the real 4.0 parser is scripts/check-apparmor-profile.sh
(needs docker); this test is the shape only.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROFILE = REPO_ROOT / "docker" / "apparmor-noo-sandbox"
COMPOSE = REPO_ROOT / "docker-compose.cluster.yml"
ENV_MD = REPO_ROOT / "docs" / "reference" / "env.md"
BUILD_RS = REPO_ROOT / "noo-cli" / "build.rs"
NAME = "noo-sandbox"

# docker-default's rules (moby profiles/apparmor/template.go, v27.5.1),
# every one of which the sandbox profile must keep verbatim.
DOCKER_DEFAULT_RULES = [
    "network,",
    "capability,",
    "file,",
    "umount,",
    "signal (receive) peer=unconfined,",
    "signal (receive) peer=runc,",
    "signal (receive) peer=crun,",
    "deny @{PROC}/* w,",
    "deny @{PROC}/{[^1-9],[^1-9][^0-9],[^1-9s][^0-9y][^0-9s],[^1-9][^0-9][^0-9][^0-9/]*}/** w,",
    "deny @{PROC}/sys/[^k]** w,",
    "deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,",
    "deny @{PROC}/sysrq-trigger rwklx,",
    "deny @{PROC}/kcore rwklx,",
    "deny /sys/[^f]*/** wklx,",
    "deny /sys/f[^s]*/** wklx,",
    "deny /sys/fs/[^c]*/** wklx,",
    "deny /sys/fs/c[^g]*/** wklx,",
    "deny /sys/fs/cg[^r]*/** wklx,",
    "deny /sys/firmware/** rwklx,",
    "deny /sys/devices/virtual/powercap/** rwklx,",
    "deny /sys/kernel/security/** rwklx,",
]
BWRAP_RULES = ["userns,", "mount,", "pivot_root,"]


def _rules() -> list[str]:
    """Rule lines, comments stripped, inside the profile block."""
    out = []
    for raw in PROFILE.read_text().splitlines():
        line = raw.split("#", 1)[0].strip() if not raw.strip().startswith("#include") else raw.strip()
        if line:
            out.append(line)
    return out


def test_it_is_docker_default_with_bubblewraps_rules_instead_of_deny_mount() -> None:
    rules = _rules()
    assert f"profile {NAME} flags=(attach_disconnected,mediate_deleted) {{" in rules
    assert "#include <tunables/global>" in rules and "#include <abstractions/base>" in rules
    for r in DOCKER_DEFAULT_RULES:
        assert r in rules, f"docker-default rule missing: {r}"
    for r in BWRAP_RULES:
        assert r in rules, f"Bubblewrap rule missing: {r}"
    assert "deny mount," not in rules, "deny mount, is the rule Bubblewrap cannot live under"
    # the signal and ptrace scoping name THIS profile, as docker-default names itself
    assert f"signal (send,receive) peer={NAME}," in rules
    assert f"ptrace (trace,read,tracedby,readby) peer={NAME}," in rules


def test_nothing_else_is_loosened() -> None:
    """Every non-deny rule is one docker-default has or one Bubblewrap needs:
    no `capability sys_admin`-style widening, no extra signal or ptrace peers,
    no file grants beyond `file,`."""
    allowed = set(DOCKER_DEFAULT_RULES) | set(BWRAP_RULES) | {
        f"profile {NAME} flags=(attach_disconnected,mediate_deleted) {{",
        "#include <tunables/global>",
        "#include <abstractions/base>",
        f"signal (send,receive) peer={NAME},",
        f"ptrace (trace,read,tracedby,readby) peer={NAME},",
        "}",
    }
    extra = [r for r in _rules() if r not in allowed]
    assert not extra, f"rules not in docker-default and not Bubblewrap's: {extra}"


def test_the_operator_facing_places_agree_on_the_file_and_the_name() -> None:
    env_row = next((l for l in ENV_MD.read_text().splitlines() if l.startswith("| `NOO_SANDBOX_APPARMOR`")), "")
    assert env_row, "env.md has no NOO_SANDBOX_APPARMOR row"
    assert "docker/apparmor-noo-sandbox" in env_row and f"`{NAME}`" in env_row, env_row
    compose = COMPOSE.read_text()
    assert "apparmor=${NOO_SANDBOX_APPARMOR:-docker-default}" in compose
    assert "docker/apparmor-noo-sandbox" in compose, "the compose comment must point an operator at the profile"
    # shipped with the CLI's deploy files: a --dist controller has no git checkout to find it in
    assert re.search(r'^\s*"docker/apparmor-noo-sandbox",', BUILD_RS.read_text(), re.M), "add it to STANDALONE_FILES in noo-cli/build.rs"
    # the install line the profile's own header gives is the one the docs and the verify remedy give
    header = PROFILE.read_text()
    assert f"sudo install -m 0644 docker/apparmor-noo-sandbox /etc/apparmor.d/{NAME}" in header
    assert f"sudo apparmor_parser -r /etc/apparmor.d/{NAME}" in header
    verify_rs = (REPO_ROOT / "noo-cli" / "src" / "commands" / "cluster_verify.rs").read_text()
    assert f"/etc/apparmor.d/{NAME}" in verify_rs, "the sandbox executor row's remedy names the profile install"
