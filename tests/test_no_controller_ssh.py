# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Nothing in this repo spawns `ssh` or `scp` at a node.

an earlier change retired controller→node SSH. Every lane moved to a rail over
2026-09: the dispatch rail (`cluster exec`/`logs`/`reconnect`/
`sync-model-files`), the artifact rail (weights, images, the sandbox base,
ollama models), and CA-signed bundles the node collects (provisioning,
certs, teardown, fleet secrets). The last holdouts — the `cluster-executor`
sidecar, `noo cluster set-primary`'s Postgres promotion, and eleven
`noo-py cluster` verbs — went on 2026-09-11 (§3f R24).

This is a source check, not a behaviour one, and that is the point: the
lane comes back by someone writing `Command::new("ssh")`, and no
behavioural test notices a branch nothing takes yet.

TWO FAILURES OF THE PREVIOUS VERSION OF THIS FILE, both worth stating
because they are the reason it is shaped like this now:

  1. It scoped itself to `noo-cli/src` and SAID SO, filing the rest as
     an earlier change. `src/noomesh/cluster/cli.py` kept seven `_ssh_pai` call
     sites — and a dozen more raw `subprocess.run(["ssh", ...])` ones the
     followup's count had missed — reachable as `noo-py cluster …` the
     whole time. A documented gap is still a gap.
  2. Inside its own scope it matched `Command::new("ssh")` only.
     `cluster set-primary` spawned ssh through the crate's
     `spawn_inherited(g, "ssh", …)` helper and sailed through every run.
     The counting method found what it was looking for.

So: match the PROGRAM NAME wherever it appears as a spawn argument, in
both languages, and cover both trees.

If a lane is ever genuinely needed again, add it to ALLOWED with the reason
and the proposal that reopened the question. An empty allow-list is the
claim; this test is what makes it checkable.
"""

from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
RUST_TREES = [REPO / "noo-cli/src", REPO / "gateway-rust/src"]
PY_TREE = REPO / "src/noomesh"

# Reason per entry, keyed "<path>:<line>" or "<path>". Must only ever get
# shorter.
ALLOWED: dict[str, str] = {}

# Images are allowed an ssh CLIENT only for a BUILD-TIME fetch from a git
# host — never to dial a node. Same rule: a reason, and it only shrinks.
ALLOWED_IMAGE_SSH: dict[str, str] = {
    # Line-keyed, so it moves when anything above it moves: the `ARG
    # PYTHON_VERSION` block that pinned this file to `.python-version` pushed
    # this RUN from line 10 to 17, and this test is what said so. Re-check the
    # reason when you move it, rather than just bumping the number.
    "Dockerfile:24": (
        "build-time only: pyproject pulls noo-trellion over git+ssh, and this "
        "legacy top-level image is not part of the controller stack (no compose "
        "service builds it). Nothing at RUNTIME dials a node from here."
    ),
}

# Rust: any string literal "ssh"/"scp" passed as a program name. Covers
# Command::new("ssh"), spawn_inherited(g, "ssh", …), and whatever the next
# wrapper is called — a program name is a program name.
RUST_SPAWN = re.compile(r'\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*,\s*)*"(ssh|scp|sshpass)"\s*,')
RUST_COMMAND = re.compile(r'Command::new\(\s*"(ssh|scp|sshpass)"\s*\)')

# Python: "ssh"/"scp" as argv[0] of a subprocess list, plus the paramiko /
# asyncssh libraries, which need no argv at all.
PY_SPAWN = re.compile(r'\[\s*"(ssh|scp|sshpass)"|\[\s*\'(ssh|scp|sshpass)\'')
PY_LIB = re.compile(r'^\s*(?:import|from)\s+(paramiko|asyncssh|fabric)\b')


def _scan(root: pathlib.Path, suffix: str, patterns) -> list[str]:
    offenders: list[str] = []
    for f in sorted(root.rglob(f"*{suffix}")):
        rel = str(f.relative_to(REPO))
        if rel in ALLOWED:
            continue
        for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith(("//", "#", "///", "*")):
                continue  # a comment naming the removed lane is the point
            if f"{rel}:{n}" in ALLOWED:
                continue
            if any(p.search(line) for p in patterns):
                offenders.append(f"{rel}:{n}: {stripped}")
    return offenders


def test_the_scan_actually_reads_files() -> None:
    # Assert the corpus is real before asserting it is clean — a glob that
    # matches nothing passes every check in this file.
    for root in RUST_TREES:
        assert len(list(root.rglob("*.rs"))) > 20, f"{root} looks empty"
    assert len(list(PY_TREE.rglob("*.py"))) > 50, f"{PY_TREE} looks empty"
    # And assert the patterns match what they claim to.
    assert RUST_SPAWN.search('let rc = spawn_inherited(g, "ssh", &args);')
    assert RUST_COMMAND.search('Command::new("scp")')
    assert PY_SPAWN.search('subprocess.run(["ssh", "-o", "BatchMode=yes"])')
    assert PY_LIB.search("import paramiko")


def test_the_rust_crates_spawn_no_ssh_or_scp() -> None:
    offenders: list[str] = []
    for root in RUST_TREES:
        offenders += _scan(root, ".rs", (RUST_SPAWN, RUST_COMMAND))
    assert not offenders, (
        "the controller does not reach into nodes (§3f R24). Found:\n  "
        + "\n  ".join(offenders)
        + "\n\nUse a rail: dispatch (tasks.dispatch.<node>), the artifact "
        "manifest + model-cache, the node-agent HTTP endpoints, or a "
        "CA-signed bundle the node collects."
    )


def test_the_python_package_spawns_no_ssh_or_scp() -> None:
    offenders = _scan(PY_TREE, ".py", (PY_SPAWN, PY_LIB))
    assert not offenders, (
        "`noo-py` does not reach into nodes either. Found:\n  "
        + "\n  ".join(offenders)
        + "\n\nThe Rust front door owns every one of these verbs on a rail; "
        "the Python twins were deleted 2026-09-11."
    )


def test_no_ssh_client_is_installed_into_an_image() -> None:
    # The lane also comes back by an image quietly gaining the binaries.
    offenders: list[str] = []
    for f in sorted((REPO / "docker").glob("Dockerfile*")) + [REPO / "Dockerfile"]:
        if not f.is_file():
            continue
        for n, line in enumerate(f.read_text().splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            key = f"{f.relative_to(REPO)}:{n}"
            if key in ALLOWED_IMAGE_SSH:
                continue
            if re.search(r"\b(openssh-client|sshpass)\b", line):
                offenders.append(f"{key}: {line.strip()}")
    assert not offenders, (
        "an image installs an SSH client:\n  " + "\n  ".join(offenders)
        + "\n\nNo container in this stack dials a node over SSH."
    )


def test_the_allow_lists_are_empty_or_explained() -> None:
    # A silent allow-list is how the lane comes back one file at a time.
    assert not ALLOWED, f"the source allow-list must stay empty, got {ALLOWED}"
    for entry, reason in {**ALLOWED, **ALLOWED_IMAGE_SSH}.items():
        path = entry.split(":")[0]
        assert (REPO / path).is_file(), f"{path} is allow-listed but does not exist"
        assert len(reason) > 30, f"{entry} needs a real reason, got {reason!r}"
