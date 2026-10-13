# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""docker/seccomp-sandbox.json is Docker's default profile with exactly the
user-namespace and mount syscalls Bubblewrap needs made unconditional.
Pins that shape, and that the sandbox services actually start with it —
without the profile the executor refuses every call, and the failure
would surface as a tool error rather than at commit time.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PROFILE = REPO_ROOT / "docker" / "seccomp-sandbox.json"
COMPOSE = REPO_ROOT / "docker-compose.cluster.yml"

NAMESPACE_SYSCALLS = {
    "clone", "clone3", "unshare", "setns",
    "mount", "umount2", "pivot_root", "mount_setattr", "open_tree", "move_mount",
}


def _profile() -> dict:
    return json.loads(PROFILE.read_text())


def test_default_action_is_still_deny():
    assert _profile()["defaultAction"] == "SCMP_ACT_ERRNO"


def test_namespace_syscalls_are_allowed_unconditionally_and_nowhere_else():
    unconditional = set()
    elsewhere = set()
    for rule in _profile()["syscalls"]:
        names = set(rule["names"]) & NAMESPACE_SYSCALLS
        if not names:
            continue
        if rule["action"] == "SCMP_ACT_ALLOW" and not rule.get("args") and not rule.get("includes") and not rule.get("excludes"):
            unconditional |= names
        else:
            elsewhere |= names
    assert unconditional == NAMESPACE_SYSCALLS
    assert elsewhere == set(), f"still gated or denied elsewhere: {sorted(elsewhere)}"


def test_the_dangerous_gates_survive_derivation():
    """Everything Docker keeps behind a capability stays there: the
    profile widens the namespace calls and nothing else."""
    gated = set()
    for rule in _profile()["syscalls"]:
        caps = (rule.get("includes") or {}).get("caps", [])
        if caps:
            gated |= set(rule["names"])
    for name in ("bpf", "perf_event_open", "reboot", "init_module", "delete_module", "open_by_handle_at", "ptrace", "settimeofday", "acct", "chroot"):
        assert name in gated, f"{name} lost its capability gate"


def test_derivation_is_reproducible_from_a_default_profile():
    import importlib.util

    spec = importlib.util.spec_from_file_location("derive_seccomp", REPO_ROOT / "scripts" / "derive-sandbox-seccomp.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fake_default = {
        "defaultAction": "SCMP_ACT_ERRNO",
        "syscalls": [
            {"names": ["read", "clone"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 0}]},
            {"names": ["mount", "unshare"], "action": "SCMP_ACT_ALLOW", "includes": {"caps": ["CAP_SYS_ADMIN"]}},
            {"names": ["clone3"], "action": "SCMP_ACT_ERRNO", "excludes": {"caps": ["CAP_SYS_ADMIN"]}},
        ],
    }
    out = mod.derive(fake_default)
    assert out["syscalls"][0] == {"names": mod.NAMESPACE_SYSCALLS, "action": "SCMP_ACT_ALLOW"}
    assert out["syscalls"][1:] == [{"names": ["read"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 0}]}]


def test_compose_starts_every_sandbox_service_with_the_profile():
    yaml = pytest.importorskip("yaml")
    services = yaml.safe_load(COMPOSE.read_text())["services"]
    sandboxes = {n: s for n, s in services.items() if n == "sandbox" or n.startswith("sandbox-")}
    sandboxes.pop("sandbox-base", None)  # the node-side skills base image, not this executor
    assert set(sandboxes) == {"sandbox", "sandbox-extra"}
    for name, svc in sandboxes.items():
        opts = svc.get("security_opt", [])
        assert "seccomp=./docker/seccomp-sandbox.json" in opts, f"{name}: {opts}"
        assert "no-new-privileges:true" in opts, name
        assert svc.get("cap_drop") == ["ALL"], name
        assert svc.get("read_only") is True, name
        env = svc.get("environment", [])
        assert any(str(e).startswith("NOO_SANDBOX_ISOLATION=") for e in env), f"{name}: {env}"
    # The replicas answer to the same name the gateway dials.
    extra_net = sandboxes["sandbox-extra"]["networks"]
    assert "sandbox" in extra_net["noo-sandbox"]["aliases"]
    assert "container_name" not in sandboxes["sandbox-extra"]
