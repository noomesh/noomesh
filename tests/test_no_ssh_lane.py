# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""No compose file may define a cluster-executor, and no service may mount SSH.

The controller→node SSH lane was removed on 2026-09-11 (security tracker
§3f R24). an earlier change had already declared it "retired" — and for
five months the `cluster-executor` container went on being started by the
DEFAULT profile, running as root, with the operator's `${HOME}/.ssh`
bind-mounted, ssh/scp/`sudo -n systemctl`-ing hosts it read out of the
`noo_cluster_proposals` table. A retirement that only a proposal document
knows about is not a retirement.

So this file is the claim made checkable. It is deliberately a source
check over the compose files rather than a behavioural one: the lane comes
back by someone re-adding a service or a `.ssh` volume, and no behavioural
test notices a container that is not there yet.

Watch the guard fail: add

    ssh-thing:
      volumes:
        - ${HOME}/.ssh:/root/.ssh:ro

to docker-compose.cluster.yml and both tests below go red.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
COMPOSE_FILES = sorted(REPO.glob("docker-compose*.yml"))

# Reason per entry. Must only ever get shorter, and an empty dict is the
# claim: nothing in this repo reaches a node over SSH.
ALLOWED_SSH_MOUNTS: dict[str, str] = {}


def _services(path: pathlib.Path) -> dict:
    # Tag-tolerant: an add-on overlay may carry `!reset`.
    from tests._compose_projection import load_raw, untag
    doc = untag(load_raw(path)) or {}
    svcs = doc.get("services") or {}
    assert isinstance(svcs, dict)
    return svcs


def test_compose_files_were_actually_parsed() -> None:
    # A guard that finds nothing because it looked nowhere is the repo's
    # favourite way to pass. Assert the corpus is real first.
    assert len(COMPOSE_FILES) >= 2, f"expected several compose files, got {COMPOSE_FILES}"
    total = sum(len(_services(p)) for p in COMPOSE_FILES)
    assert total > 20, f"parsed only {total} services — the parse is broken, not the fleet"


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
def test_no_cluster_executor_service(path: pathlib.Path) -> None:
    svcs = _services(path)
    offenders = [name for name in svcs if "executor" in name]
    assert not offenders, (
        f"{path.name} defines {offenders}. The cluster-executor and the "
        "controller→node SSH lane were removed 2026-09-11 (§3f R24). "
        "Nothing polls noo_cluster_proposals: a node whose agent answers is "
        "restarted over the agent rail, and one that does not raises an "
        "operator alert with the command to run ON the node."
    )


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
def test_no_service_mounts_ssh(path: pathlib.Path) -> None:
    offenders: list[str] = []
    for name, svc in _services(path).items():
        if f"{path.name}:{name}" in ALLOWED_SSH_MOUNTS:
            continue
        for vol in (svc or {}).get("volumes") or []:
            spec = vol if isinstance(vol, str) else str(vol.get("source", ""))
            if ".ssh" in spec:
                offenders.append(f"{name}: {spec}")
    assert not offenders, (
        f"{path.name} bind-mounts SSH material into a container:\n  "
        + "\n  ".join(offenders)
        + "\n\nNo container in this stack holds an SSH private key. If a lane "
        "genuinely needs one again, add it to ALLOWED_SSH_MOUNTS with the "
        "reason and the proposal that reopened the question."
    )


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
def test_no_service_mounts_the_whole_repo(path: pathlib.Path) -> None:
    # `.:/app/project:ro` handed the gateway and the worker the entire
    # checkout — secrets/, pki/, .env included — for code that never read
    # it. Mount the subdirectory a service actually consumes.
    offenders: list[str] = []
    for name, svc in _services(path).items():
        for vol in (svc or {}).get("volumes") or []:
            spec = vol if isinstance(vol, str) else str(vol.get("source", ""))
            if spec.split(":")[0].strip() == ".":
                offenders.append(f"{name}: {spec}")
    assert not offenders, (
        f"{path.name} mounts the repo root into a container:\n  "
        + "\n  ".join(offenders)
        + "\n\nThat includes secrets/ and pki/. Mount only the directories "
        "the service reads."
    )


def test_the_allow_list_is_empty_or_explained() -> None:
    # A silent allow-list is how the lane comes back one service at a time.
    for entry, reason in ALLOWED_SSH_MOUNTS.items():
        assert len(reason) > 30, f"{entry} needs a real reason, got {reason!r}"
