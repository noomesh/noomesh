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

The server's uid is its OWN (0.6.12). Docker without userns-remap counts
RLIMIT_NPROC per real uid across the host, so the sandbox's `nproc: 256`
bounds its threads only while no other service runs as that uid. As
`nonroot` (65532) it shared the count with redis, the monitoring set, the
voice doors, stunnel and the Python services; on pop-os (0.6.11) that was
exactly 256, every thread the server started failed and `/health` answered
500. The pins below derive the server's uid from the compose launcher and
the Dockerfile's passwd line, and every other uid from the tree's text.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.cluster.yml"
DOCKERFILE = ROOT / "docker" / "Dockerfile.sandbox"
SANDBOXES = ("sandbox", "sandbox-extra")

ENTRYPOINT = [
    "setpriv",
    "--reuid=sandbox-server",
    "--regid=sandbox-server",
    "--clear-groups",
    "--inh-caps=+setuid,+setgid,+kill",
    "--ambient-caps=+setuid,+setgid,+kill",
    "--",
]


def _services() -> dict:
    return yaml.safe_load(COMPOSE.read_text())["services"]


@pytest.mark.parametrize("name", SANDBOXES)
def test_the_launcher_keeps_exactly_the_three_capabilities_and_drops_to_the_server_user(name):
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


def test_the_image_declares_the_executor_user_and_ends_as_the_server_user():
    text = DOCKERFILE.read_text()
    import noomesh.sandbox.app as sandbox

    passwd = re.search(rf"echo '{sandbox.EXECUTOR_USER}:x:(\d+):(\d+):", text)
    assert passwd, "Dockerfile.sandbox does not declare the executor user"
    uid, gid = int(passwd.group(1)), int(passwd.group(2))
    assert uid == gid == 65600, (uid, gid)
    assert re.search(rf"echo '{sandbox.EXECUTOR_USER}:x:{gid}:' >> /etc/group", text)
    # The range stays clear of nonroot (65532) and nobody (65534), and of
    # the server's own uid: no executor uid may be the one the key is
    # handed to.
    assert uid > 65534 and uid + sandbox.EXECUTOR_SLOTS - 1 < 2**31
    _, server_uid = _server_user()
    assert not uid <= server_uid < uid + sandbox.EXECUTOR_SLOTS, (server_uid, uid)
    assert _last_user(text) == "sandbox-server"


# ── the server's own uid ────────────────────────────────────────────────

PKI = ROOT / "noo-cli" / "src" / "pki.rs"
PASSWD_LINE = re.compile(r"echo '([a-z_][a-z0-9_-]*):x:(\d+):(\d+):")


def _passwd(text: str) -> dict[str, int]:
    """The users a Dockerfile writes into /etc/passwd itself."""
    return {m.group(1): int(m.group(2)) for m in PASSWD_LINE.finditer(text)}


def _last_user(text: str) -> str:
    return [l for l in text.splitlines() if l.upper().startswith("USER ")][-1].split()[1]


def _server_user() -> tuple[str, int]:
    """(name, uid) the sandbox server runs as: the name the compose launcher
    drops to, resolved through the passwd line Dockerfile.sandbox writes."""
    entry = [str(t) for t in _services()["sandbox"]["entrypoint"]]
    reuid = [t.split("=", 1)[1] for t in entry if t.startswith("--reuid=")]
    regid = [t.split("=", 1)[1] for t in entry if t.startswith("--regid=")]
    assert len(reuid) == 1 and reuid == regid, entry
    users = _passwd(DOCKERFILE.read_text())
    assert reuid[0] in users, (
        f"the launcher drops to {reuid[0]!r}, which Dockerfile.sandbox does not declare: "
        f"the server would share the base image's uid with every other service ({users})")
    return reuid[0], users[reuid[0]]


def _shipped(pattern: str) -> list[Path]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [ROOT / f for f in out.splitlines() if re.search(pattern, f)]


def _other_uids() -> dict[int, list[str]]:
    """Every uid the tree says some OTHER process runs as or hands a key or a
    secret to, from the text: numeric USER / useradd / passwd lines in every
    other Dockerfile, numeric compose `user:` and `x-noo-uid`, and every
    `ContainerUid(N)` and uid constant in the PKI reader table except the
    sandbox's row."""
    seen: dict[int, list[str]] = {}

    def add(uid: int, where: str) -> None:
        seen.setdefault(uid, []).append(where)

    dockerfiles = _shipped(r"(^|/)Dockerfile[^/]*$|\.Dockerfile$")
    assert DOCKERFILE in dockerfiles and len(dockerfiles) > 5, dockerfiles
    for df in dockerfiles:
        if df == DOCKERFILE:
            continue
        text = df.read_text()
        for name, uid in _passwd(text).items():
            add(uid, f"{df.name} passwd {name}")
        for m in re.finditer(r"^USER\s+(\d+)", text, re.M):
            add(int(m.group(1)), f"{df.name} USER")
        for m in re.finditer(r"(?:useradd|adduser)[^\n]*?(?:-u|--uid)\s+(\d+)", text):
            add(int(m.group(1)), f"{df.name} useradd")
    composes = _shipped(r"(^|/)[^/]*compose[^/]*\.ya?ml$")
    assert COMPOSE in composes, composes
    for f in composes:
        services = (yaml.safe_load(f.read_text().replace("!reset", "").replace("!override", "")) or {}).get("services") or {}
        for svc, spec in services.items():
            if svc in SANDBOXES:
                continue
            user = str((spec or {}).get("user", "")).split(":")[0].strip()
            if user.isdigit():
                add(int(user), f"{f.name} {svc} user")
            for sec in (spec or {}).get("secrets") or []:
                if isinstance(sec, dict) and str(sec.get("x-noo-uid", "")).isdigit():
                    add(int(sec["x-noo-uid"]), f"{f.name} {svc} secret")
    pki = PKI.read_text()
    for m in re.finditer(r'\("([a-z0-9-]+)",\s*KeyReader::ContainerUid\((\w+)\)\)', pki):
        if m.group(1) == "sandbox":
            continue
        add(_pki_const(pki, m.group(2)), f"pki.rs reader {m.group(1)}")
    for m in re.finditer(r"pub const ([A-Z_]+_(?:UID|GID)): u32 = (\d+);", pki):
        if m.group(1) != "SANDBOX_SERVER_UID":
            add(int(m.group(2)), f"pki.rs {m.group(1)}")
    return seen


def _pki_const(pki: str, token: str) -> int:
    if token.isdigit():
        return int(token)
    m = re.search(rf"pub const {token}: u32 = (\d+);", pki)
    assert m, f"pki.rs names {token} but does not define it"
    return int(m.group(1))


def test_the_server_runs_as_a_uid_no_other_service_uses():
    """The image's USER, the compose launcher and the passwd line agree on
    one name, its uid is not nonroot's, and nothing else in the tree runs
    as it or is handed anything as it."""
    name, uid = _server_user()
    assert _last_user(DOCKERFILE.read_text()) == name, "the image's own USER is the server's too"
    groups = re.findall(rf"echo '{re.escape(name)}:x:(\d+):' >> /etc/group", DOCKERFILE.read_text())
    assert groups == [str(uid)], f"{name} has no group of its own (--regid needs one): {groups}"
    others = _other_uids()
    # The shared uid the server left: the one most of the tree hands keys to.
    shared = max(others, key=lambda u: len(others[u]))
    assert shared == 65532 and len(others[shared]) > 10, (shared, others.get(shared))
    assert uid != shared, f"the sandbox server runs as {name} = {uid}, the uid of {others[shared][:5]}…"
    assert uid not in others, f"uid {uid} is also used by {others[uid]}: nproc is counted per uid host-wide"
    assert uid not in (0, 65534), uid
    # The number appears in no other Dockerfile or compose file outside a
    # comment (the compose sandbox block explains the uid in one).
    for f in _shipped(r"(^|/)Dockerfile[^/]*$|\.Dockerfile$|(^|/)[^/]*compose[^/]*\.ya?ml$"):
        if f != DOCKERFILE:
            code = [l.split("#", 1)[0] for l in f.read_text().splitlines()]
            assert not any(re.search(rf"\b{uid}\b", l) for l in code), f"{f.name} uses {uid}"


def test_the_nproc_bound_is_kept_per_service():
    """`nproc: 256` stays: with the uid its own, it bounds this server."""
    for name in SANDBOXES:
        assert _services()[name]["ulimits"]["nproc"] == 256, name


def test_the_key_is_the_servers_so_the_executor_cannot_read_it():
    """SERVICE_KEY_READERS hands the sandbox leaf to the server's uid at
    0640 (`SANDBOX_SERVER_UID`); the executor uids are outside that uid and
    its group, and no other service's row names it."""
    _, uid = _server_user()
    pki = PKI.read_text()
    row = re.search(r'\("sandbox",\s*KeyReader::ContainerUid\((\w+)\)\)', pki)
    assert row, "pki.rs has no sandbox reader row"
    assert _pki_const(pki, row.group(1)) == uid, (row.group(0), uid)
    rows = [m.group(1) for m in re.finditer(r'\("([a-z0-9-]+)",\s*KeyReader::ContainerUid\((\w+)\)\)', pki)
            if _pki_const(pki, m.group(2)) == uid]
    assert rows == ["sandbox"], rows
