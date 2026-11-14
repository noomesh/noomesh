# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The applier states the sha of every INSTALLED binary kind, not only the
kinds the bundle carried.

The controller leaves a binary out of a bundle only when the node's last apply
report names its exact bytes (`node_runs_asset`, provision.rs). The applier
used to report only the kinds handled in that apply, so a kind left out of
bundle N went unreported in report N and was carried again in bundle N+1: the
skip flip-flopped roll by roll and looked like "always carried" (the 0.6.22
roll).

The real blocks are lifted out of scripts/noo-apply.sh and run with the
root-only tools stubbed, as tests/test_apply_unchanged_binaries.py does.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
APPLIER = (REPO / "scripts" / "noo-apply.sh").read_text()
ELF = b"\x7fELF" + b"\x02\x01\x01\x00" * 4


def lifted(name: str) -> str:
    m = re.search(rf"# BEGIN {name}\n(.*?)# END {name}", APPLIER, re.S)
    assert m, f"{name} is not delimited in noo-apply.sh"
    return m.group(1)


def harness_block() -> str:
    m = re.search(r'(if \[ -f "\$WORK/files/harness-binary" \]; then\n.*?\n)fi\n', APPLIER, re.S)
    assert m, "harness-binary block not found"
    return m.group(1) + "fi\n"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def reported(line: str) -> dict[str, str]:
    """Parse as the controller does: the pairs after the LAST `binary-sha:`."""
    at = line.rfind("binary-sha:")
    assert at >= 0, line
    return dict(p.split("=", 1) for p in line[at + len("binary-sha:"):].split() if "=" in p)


def apply(tmp: Path, carried: dict[str, bytes], installed: dict[str, bytes], cli_user: str | None = None,
          cli_installed: bytes | None = None) -> str:
    """Run the harness block (if the bundle carries it) and the report block.
    Returns the final `binary-sha:` line."""
    work, bindir, home = tmp / "work", tmp / "bin", tmp / "home"
    (work / "files").mkdir(parents=True, exist_ok=True)
    bindir.mkdir(exist_ok=True)
    for k, b in carried.items():
        (work / "files" / k).write_bytes(b)
    for name, b in installed.items():
        (bindir / name).write_bytes(b)
    if cli_user is not None:
        (work / "files" / "cli-user").write_text(cli_user + "\n")
    if cli_installed is not None:
        (home / ".local" / "bin").mkdir(parents=True, exist_ok=True)
        (home / ".local" / "bin" / "noo").write_bytes(cli_installed)
    blocks = (harness_block() if "harness-binary" in carried else "") + lifted("report_installed_binaries")
    body = blocks.replace("/usr/local/bin", str(bindir))
    script = f"""set -eu
WORK="{work}"; applied=""; binary_shas=""; need_restart=0; need_harness_restart=0
install() {{ eval "s=\\${{$(($#-1))}} d=\\${{$#}}"; cp "$s" "$d"; chmod 755 "$d"; }}
getent() {{ [ "$1" = passwd ] && [ "$2" = alice ] && echo "alice:x:1000:1000::{home}:/bin/bash"; }}
runuser() {{ [ "$1" = -u ] && [ "$2" = alice ] && [ "$3" = -- ] || {{ echo "runuser called wrong: $*" >&2; return 1; }}; shift 3; "$@"; }}
{lifted("binary_unchanged")}
{body}
[ -z "$binary_shas" ] || echo "binary-sha:$binary_shas"
"""
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""


def test_a_kind_the_bundle_left_out_is_still_reported(tmp_path: Path) -> None:
    hostd, agent = ELF + b"hostd-0.6.22", ELF + b"agent-0.6.22"
    harness_new = ELF + b"harness-0.6.23"
    # Bundle N carries only the harness; hostd and the agent are already installed.
    line = apply(tmp_path, {"harness-binary": harness_new},
                 {"noo-hostd": hostd, "noo-node-agent": agent, "noo-gateway": ELF + b"harness-0.6.22"})
    got = reported(line)
    assert got["hostd-binary"] == sha(hostd), "report N lost the hostd the bundle left out"
    assert got["agent-binary"] == sha(agent)
    assert got["harness-binary"] == sha(harness_new), "the carried kind reports the bytes it installed"
    # Bundle N+1: the controller's proof (node_runs_asset) needs exactly this
    # pair, so hostd can be left out again instead of flip-flopping.
    assert ("hostd-binary", sha(hostd)) in reported(line).items()


def test_a_carried_kind_is_not_restated(tmp_path: Path) -> None:
    harness_new = ELF + b"harness-new"
    line = apply(tmp_path, {"harness-binary": harness_new}, {"noo-gateway": ELF + b"harness-old"})
    assert line.count("harness-binary=") == 1, line
    assert reported(line)["harness-binary"] == sha(harness_new)


def test_nothing_installed_states_nothing(tmp_path: Path) -> None:
    assert apply(tmp_path, {}, {}) == ""


def test_a_symlink_states_nothing(tmp_path: Path) -> None:
    (tmp_path / "bin").mkdir()
    (tmp_path / "elsewhere").write_bytes(ELF + b"x")
    (tmp_path / "bin" / "noo-hostd").symlink_to(tmp_path / "elsewhere")
    assert "hostd-binary" not in reported(apply(tmp_path, {}, {"noo-node-agent": ELF + b"a"}))


def test_the_installed_cli_is_hashed_as_its_user(tmp_path: Path) -> None:
    cli = ELF + b"noo-cli"
    got = reported(apply(tmp_path, {}, {"noo-node-agent": ELF + b"a"}, cli_user="alice", cli_installed=cli))
    assert got["cli-binary"] == sha(cli)
    # Without the bundle naming the user, the CLI is not stated (never guessed).
    assert "cli-binary" not in reported(apply(tmp_path / "2", {}, {"noo-node-agent": ELF + b"a"}, cli_installed=cli))


def test_the_report_line_stays_inside_the_fetchers_tail() -> None:
    """noo-fetch posts the last 1500 bytes of the apply log; the binary-sha
    line is the last line and must fit whole, for every kind plus every vendor
    slot."""
    m = re.search(r'^VENDOR_SLOTS="([^"]*)"', APPLIER, re.M)
    slots = m.group(1).split() if m else []
    kinds = ["agent-binary", "hostd-binary", "cli-binary", "harness-binary", *slots]
    line = "binary-sha:" + "".join(f" {k}={'0' * 64}" for k in kinds)
    assert len(line) + 1 < 1500, f"{len(line)} bytes, {len(kinds)} kinds"
    fetch = (REPO / "scripts" / "noo-fetch.sh").read_text()
    assert "1500" in fetch, "the fetcher's tail size moved: re-check this bound"
