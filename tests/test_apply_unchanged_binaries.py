# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A restage that carries a binary the node already runs installs nothing and
restarts nothing for it.

The binary blocks of scripts/noo-apply.sh used to install unconditionally and
set the restart flag, so every `noo cluster provision` bounced the agent (and
the harness) even when the bytes were identical. Each block now asks
`binary_unchanged PAYLOAD INSTALLED`; true only with positive proof (the
installed file exists, is readable, and has the same sha256). A first install
or an unreadable/corrupt installed file takes the install path.

The helper and the agent/harness blocks are lifted out of the real script and
run with `install` stubbed (the real one wants root); the flags the
orchestration step reads (`need_restart`, `need_harness_restart`) and the
`applied` summary are what is asserted. The summary token `<kind>=unchanged`
must also never satisfy the controller's whole-token `applier_applied` lookup
for `<kind>`.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
APPLIER = (REPO / "scripts" / "noo-apply.sh").read_text()
ELF = b"\x7fELF" + b"\x02\x01\x01\x00" * 4 + b"payload"


def helper() -> str:
    m = re.search(r"# BEGIN binary_unchanged\n(.*?)# END binary_unchanged", APPLIER, re.S)
    assert m, "binary_unchanged is not delimited in noo-apply.sh"
    return m.group(1)


def block(kind: str) -> str:
    m = re.search(r'(if \[ -f "\$WORK/files/%s" \]; then\n.*?\n)fi\n' % re.escape(kind), APPLIER, re.S)
    assert m, f"{kind} block not found"
    return m.group(1) + "fi\n"


def run(tmp: Path, kind: str, installed_name: str, payload: bytes, installed: bytes | None, flag: str,
        unreadable: bool = False) -> dict[str, str]:
    work = tmp / "work"
    (work / "files").mkdir(parents=True, exist_ok=True)
    (work / "files" / kind).write_bytes(payload)
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    dst = bindir / installed_name
    if dst.exists():
        dst.chmod(0o755)
        dst.unlink()
    if installed is not None:
        dst.write_bytes(installed)
        if unreadable:
            dst.chmod(0)
    body = block(kind).replace("/usr/local/bin", str(bindir))
    script = f"""set -eu
WORK="{work}"; applied=""; binary_shas=""; need_restart=0; need_harness_restart=0
install() {{ eval "s=\\${{$(($#-1))}} d=\\${{$#}}"; cp "$s" "$d"; chmod 755 "$d"; }}
{helper()}
{body}
echo "applied=$applied"; echo "binary_shas=$binary_shas"; echo "need_restart=$need_restart"; echo "need_harness_restart=$need_harness_restart"
"""
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    out = dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l and l.split("=")[0] in
               ("applied", "binary_shas", "need_restart", "need_harness_restart"))
    out["installed_bytes"] = dst.read_bytes().hex() if os.access(dst, os.R_OK) else ""
    return out


KINDS = [("agent-binary", "noo-node-agent", "need_restart"),
         ("harness-binary", "noo-gateway", "need_harness_restart")]


@pytest.mark.parametrize("kind,name,flag", KINDS)
def test_first_install_installs_and_restarts(tmp_path: Path, kind: str, name: str, flag: str) -> None:
    o = run(tmp_path, kind, name, ELF, None, flag)
    assert o["applied"].split() == [kind]
    assert o[flag] == "1"
    assert o["installed_bytes"] == ELF.hex()
    assert o["binary_shas"].split() == [f"{kind}={hashlib.sha256(ELF).hexdigest()}"]


@pytest.mark.parametrize("kind,name,flag", KINDS)
def test_second_apply_of_the_same_bytes_is_unchanged_and_restarts_nothing(tmp_path: Path, kind: str, name: str, flag: str) -> None:
    first = run(tmp_path, kind, name, ELF, None, flag)
    assert first[flag] == "1"
    second = run(tmp_path, kind, name, ELF, ELF, flag)
    assert second["applied"].split() == [f"{kind}=unchanged"]
    assert second["need_restart"] == "0" and second["need_harness_restart"] == "0"
    # The node still states what it runs, so the controller can omit it next time.
    assert second["binary_shas"].split() == [f"{kind}={hashlib.sha256(ELF).hexdigest()}"]


@pytest.mark.parametrize("kind,name,flag", KINDS)
def test_different_bytes_install_and_restart(tmp_path: Path, kind: str, name: str, flag: str) -> None:
    o = run(tmp_path, kind, name, ELF, ELF + b"x", flag)
    assert o["applied"].split() == [kind]
    assert o[flag] == "1"
    assert o["installed_bytes"] == ELF.hex()


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read a mode-000 file")
@pytest.mark.parametrize("kind,name,flag", KINDS)
def test_an_unreadable_installed_file_is_installed_over_never_skipped(tmp_path: Path, kind: str, name: str, flag: str) -> None:
    o = run(tmp_path, kind, name, ELF, ELF, flag, unreadable=True)
    assert o["applied"].split() == [kind]
    assert o[flag] == "1"


def test_an_empty_installed_file_is_installed_over(tmp_path: Path) -> None:
    o = run(tmp_path, "agent-binary", "noo-node-agent", ELF, b"", "need_restart")
    assert o["applied"].split() == ["agent-binary"] and o["need_restart"] == "1"


def test_unchanged_marker_is_a_different_token_from_the_kind() -> None:
    # The controller's lookup (provision.rs `applier_applied`) matches whole
    # whitespace-separated tokens after `applied:`; this pins the property
    # from the producer's side.
    for kind in ("agent-binary", "harness-binary", "hostd-binary", "cli-binary"):
        tokens = f"applied: agent-env {kind}=unchanged".split()
        assert kind not in tokens


def test_every_binary_block_consults_the_helper_and_hostd_keeps_its_floor() -> None:
    for kind in ("agent-binary", "harness-binary", "hostd-binary"):
        assert re.search(r'binary_unchanged "\$WORK/files/%s"' % kind, APPLIER), kind
        assert f'applied="$applied {kind}=unchanged"' in APPLIER, kind
    assert 'applied="$applied cli-binary=unchanged"' in APPLIER
    assert 'echo "binary-sha:$binary_shas"' in APPLIER
    assert "hostd_generation_of" in APPLIER and "REVERTING" in APPLIER


def test_the_binary_sha_marker_is_spelled_the_same_by_producers_and_the_reader() -> None:
    # Linux applier and Mac fetch applier print it; the controller's bundle
    # builder reads it. A rename in one place would silently turn every
    # omission back into "carry", so the three spellings are pinned together.
    mac = (REPO / "noo-cli/src/commands/node_fetch.rs").read_text()
    prov = (REPO / "noo-cli/src/commands/provision.rs").read_text()
    assert 'echo "binary-sha:$binary_shas"' in APPLIER
    assert '" binary-sha: {}"' in mac
    assert 'rfind("binary-sha:")' in prov
