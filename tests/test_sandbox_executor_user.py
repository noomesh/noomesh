# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The sandbox runs code as an executor uid, never as its own server.

A non-root container process keeps no effective capability, so the
`cap_add: [SETUID, SETGID]` the sandbox carried since the first snapshot
never did anything: every /exec call ran as `nonroot`, the uid the
sandbox's leaf key is handed to. In `NOO_SANDBOX_ISOLATION=process` the
code could read that key and signal the server (the security-claims audit,
lane 4). Now compose starts the container as root under setpriv, which
keeps CAP_SETUID/SETGID/KILL ambient and execs uvicorn as nonroot, and the
server drops each call to one of 64 executor uids with every capability
cleared. These pins keep the three pieces — image user, compose launcher,
capability set — consistent with src/noomesh/sandbox/app.py.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.cluster.yml"
DOCKERFILE = ROOT / "docker" / "Dockerfile.sandbox"
SANDBOXES = ("sandbox", "sandbox-extra")

ENTRYPOINT = [
    "setpriv",
    "--reuid=nonroot",
    "--regid=nonroot",
    "--clear-groups",
    "--inh-caps=+setuid,+setgid,+kill",
    "--ambient-caps=+setuid,+setgid,+kill",
    "--",
]


def _services() -> dict:
    return yaml.safe_load(COMPOSE.read_text())["services"]


@pytest.mark.parametrize("name", SANDBOXES)
def test_the_launcher_keeps_exactly_the_three_capabilities_and_drops_to_nonroot(name):
    svc = _services()[name]
    # A NAME: Docker 27 resolves `user:` strings by name (test_compose_named_users).
    assert svc.get("user") == "root", svc.get("user")
    assert [str(t) for t in svc["entrypoint"]] == ENTRYPOINT, svc["entrypoint"]
    # PID 1 reaps: every bwrap call and every setsid() escape a timeout
    # killed left a zombie under uvicorn, each holding a pid for good.
    assert svc.get("init") is True, "init: true keeps zombies from eating the pids limit"
    assert [str(c).upper() for c in svc["cap_drop"]] == ["ALL"]
    assert sorted(str(c).upper() for c in svc["cap_add"]) == ["KILL", "SETGID", "SETUID"], svc["cap_add"]
    assert "no-new-privileges:true" in [str(s) for s in svc["security_opt"]]
    # The command is still uvicorn with the mTLS listener: the launcher
    # only prefixes it (test_sandbox_door_mtls pins the flags).
    assert [str(c) for c in svc["command"]][:4] == ["python", "-m", "uvicorn", "noomesh.sandbox.app:app"]


def test_the_entrypoint_grants_only_what_cap_add_allows():
    """The ambient set the launcher asks for is the cap_add set: a cap
    named here but not added would make setpriv fail at start, one added
    but not named would sit unused in the bounding set."""
    svc = _services()["sandbox"]
    ambient = {t.split("=", 1)[1] for t in ENTRYPOINT if t.startswith("--ambient-caps=")}.pop()
    asked = {c.lstrip("+").upper() for c in ambient.split(",")}
    assert asked == {str(c).upper() for c in svc["cap_add"]}


def test_the_image_declares_the_executor_user_and_still_ends_as_nonroot():
    text = DOCKERFILE.read_text()
    import noomesh.sandbox.app as sandbox

    passwd = re.search(rf"^RUN echo '{sandbox.EXECUTOR_USER}:x:(\d+):(\d+):", text, re.M)
    assert passwd, "Dockerfile.sandbox does not declare the executor user"
    uid, gid = int(passwd.group(1)), int(passwd.group(2))
    assert uid == gid == 65600, (uid, gid)
    assert re.search(rf"echo '{sandbox.EXECUTOR_USER}:x:{gid}:' >> /etc/group", text)
    # The range stays clear of nonroot (65532) and nobody (65534): no
    # executor uid may be the one the key is handed to.
    assert uid > 65534 and uid + sandbox.EXECUTOR_SLOTS - 1 < 2**31
    last_user = [l for l in text.splitlines() if l.upper().startswith("USER ")][-1]
    assert last_user.split()[1] == "nonroot", last_user


def test_the_key_stays_nonroots_so_the_executor_cannot_read_it():
    """SERVICE_KEY_READERS hands the sandbox leaf to uid 65532 at 0640; the
    executor uids are outside that uid and its group."""
    pki = (ROOT / "noo-cli" / "src" / "pki.rs").read_text()
    assert re.search(r'\("sandbox",\s*KeyReader::ContainerUid\(65532\)\)', pki)
