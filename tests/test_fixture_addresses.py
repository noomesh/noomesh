# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""Test fixtures and comments use documentation addresses.

This repository is public. A tailnet address (100.64.0.0/10) in it is either
an example or a real machine's address, and a real one does not belong
here. Rather than list the addresses to keep out (a list that would itself
publish them), every 100.64/10 address in a tracked file must sit in
100.64.0.0/24, the block this repository uses for examples.

Exceptions:
- 100.100.100.100, Tailscale's fixed service address: it is the same on
  every tailnet and names no machine;
- a line carrying `leak-ok: <reason>` (scripts/public-leak-scan.sh's waiver),
  e.g. a range-edge value that tests the /10 boundary itself.
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CGNAT = re.compile(r"(?<![0-9.])100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.\d{1,3}\.\d{1,3}(?![0-9])")
EXAMPLES = ipaddress.ip_network("100.64.0.0/24")
SERVICE = {"100.100.100.100"}
WAIVER = re.compile(r"leak-ok:\s*\S")


def tracked_text_files() -> list[Path]:
    out = subprocess.check_output(["git", "-C", str(ROOT), "ls-files"], text=True)
    return [ROOT / f for f in out.splitlines()]


def offending(lines: list[str]) -> list[tuple[int, str]]:
    hits = []
    for n, line in enumerate(lines, 1):
        if WAIVER.search(line):
            continue
        for m in CGNAT.finditer(line):
            ip = m.group(0)
            try:
                in_examples = ipaddress.ip_address(ip) in EXAMPLES
            except ValueError:
                in_examples = False
            if not in_examples and ip not in SERVICE:
                hits.append((n, ip))
    return hits


def test_every_tailnet_address_in_the_tree_is_a_documentation_address() -> None:
    bad = []
    for path in tracked_text_files():
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
            continue
        bad += [f"{path.relative_to(ROOT)}:{n}: {ip}" for n, ip in offending(lines)]
    assert not bad, "use 100.64.0.x for a tailnet address in a fixture or comment:\n" + "\n".join(bad)


def test_the_rule_refuses_an_address_outside_the_example_block() -> None:
    assert offending(["ip = '100.64.0.7'", "dns = '100.100.100.100'"]) == []
    assert offending(["ip = '100.64.1.7'"]) == [(1, "100.64.1.7")]  # leak-ok: the guard's own self-test value
    assert offending(["ip = '100.101.2.3'"]) == [(1, "100.101.2.3")]  # leak-ok: the guard's own self-test value
    assert offending(["edge = '100.127.255.254'  # leak-ok: the /10 range edge"]) == []
    assert offending(["edge = '100.127.255.254'  # leak-ok"]) == [(1, "100.127.255.254")], "a bare waiver waives nothing"  # leak-ok: the guard's own self-test value
    assert offending(["not tailnet: 100.128.0.1, 100.63.255.255"]) == []
