#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Derive docker/seccomp-sandbox.json from Docker's default seccomp profile.

The sandbox container runs each `python_exec` call under Bubblewrap so
that one call's process tree, filesystem view and network are its own
(see src/noomesh/sandbox/app.py). Bubblewrap needs an unprivileged user
namespace plus the mount calls that are legal INSIDE one, and Docker's
default profile only allows those to a container holding CAP_SYS_ADMIN —
which the sandbox deliberately does not have (`cap_drop: ALL`).

This script takes the upstream default profile and moves exactly the
namespace-and-mount syscalls into an unconditional allow entry. Every
other rule — the ERRNO default, the ptrace/keyctl/bpf/perf gates, the
capability-conditioned admin calls — is left as Docker ships it. The
result is checked in; regenerate when Docker's default profile moves:

    scripts/derive-sandbox-seccomp.py            # fetches upstream
    scripts/derive-sandbox-seccomp.py default.json  # from a local copy

tests/test_sandbox_seccomp_profile.py pins the shape of the output.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

UPSTREAM = "https://raw.githubusercontent.com/moby/profiles/main/seccomp/default.json"
OUT = Path(__file__).resolve().parents[1] / "docker" / "seccomp-sandbox.json"

# What an unprivileged user namespace needs, and nothing more: creating the
# namespaces (clone/clone3/unshare/setns) and the mount family Bubblewrap
# uses to build the private root. Inside the new user namespace the kernel
# itself still refuses anything the namespace owner is not capable of.
NAMESPACE_SYSCALLS = [
    "clone",
    "clone3",
    "unshare",
    "setns",
    "mount",
    "umount2",
    "pivot_root",
    "mount_setattr",
    "open_tree",
    "move_mount",
]


def derive(profile: dict) -> dict:
    out = []
    for rule in profile["syscalls"]:
        names = [n for n in rule["names"] if n not in NAMESPACE_SYSCALLS]
        if not names:
            continue
        if len(names) != len(rule["names"]):
            rule = {**rule, "names": names}
        out.append(rule)
    out.insert(0, {"names": list(NAMESPACE_SYSCALLS), "action": "SCMP_ACT_ALLOW"})
    return {**profile, "syscalls": out}


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        raw = Path(argv[1]).read_text()
    else:
        with urllib.request.urlopen(UPSTREAM, timeout=30) as resp:  # noqa: S310 - fixed https URL
            raw = resp.read().decode()
    derived = derive(json.loads(raw))
    OUT.write_text(json.dumps(derived, indent=1) + "\n")
    print(f"wrote {OUT} ({len(derived['syscalls'])} syscall rules)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
