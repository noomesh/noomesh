# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Fleet logging opened no tailnet port: logs ride the gateway's :8080.

Fleet logging plan §1.2 / phase 6. A node ships to the controller through
`POST /api/cluster/nodes/{self}/logs` on the port its heartbeat already
uses; Loki is compose-network only and is never published. So the worker
grant in `config/tailscale-acl.hujson` is UNCHANGED by this program, and
so is the fixture `noo-cli/src/commands/tailnet_merge.rs` merges against
— which is the point of pinning both: a later "publish 3100/3101 for the
shipper" cannot slip into either without failing here.

Planted 2026-09-28: `tag:controller:3100` added to the worker grant → the
first test fails; `3100` added to the Rust fixture → the second.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACL = ROOT / "config/tailscale-acl.hujson"
MERGE_RS = ROOT / "noo-cli/src/commands/tailnet_merge.rs"

LOKI_PORTS = ("3100", "3101")


def _hujson_to_json(text: str) -> dict:
    """Enough HuJSON for this file: strip // and /* */ comments (outside
    strings) and trailing commas, then json.loads."""
    out, i, in_str = [], 0, False
    while i < len(text):
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\":
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            i = text.find("\n", i)
            if i < 0:
                break
            continue
        elif text.startswith("/*", i):
            i = text.find("*/", i) + 2
            continue
        else:
            out.append(c)
        i += 1
    cleaned = re.sub(r",(\s*[}\]])", r"\1", "".join(out))
    return json.loads(cleaned)


def _grants() -> list[dict]:
    doc = _hujson_to_json(ACL.read_text())
    acls = doc.get("acls") or []
    assert acls, "the tailnet policy declares no acls — the parse found nothing"
    return acls


def test_no_tailnet_grant_reaches_a_loki_port() -> None:
    """Every grant the MESH holds (nodes, members, kiosks). `autogroup:admin`
    → `*:*` is the operator's own devices and predates this program; it is
    a person's decision, not a port the shipper needs, and is left out."""
    for acl in _grants():
        if acl.get("src") == ["autogroup:admin"]:
            continue
        for dst in acl.get("dst", []):
            ports = dst.rsplit(":", 1)[1].split(",") if ":" in dst else []
            for p in ports:
                lo, _, hi = p.partition("-")
                if hi:
                    assert not any(int(lo) <= int(x) <= int(hi) for x in LOKI_PORTS), f"{dst} spans a Loki port"
                else:
                    assert lo not in LOKI_PORTS and lo != "*", f"{dst} grants a Loki port (or every port) — logs ride :8080 through the gateway"


def test_the_worker_grant_is_what_the_merge_fixture_declares() -> None:
    """The fixture `declared()` in tailnet_merge.rs is what every merge test
    reasons about; it must be the live declaration's worker grant, port for
    port, and name no Loki port."""
    src = MERGE_RS.read_text()
    m = re.search(r'\{"action": "accept", "src": \["tag:worker"\], "dst": \["tag:controller:([\d,]+)"\]\}', src)
    assert m, "tailnet_merge.rs's declared() fixture no longer carries the worker grant"
    fixture_ports = set(m.group(1).split(","))
    assert not fixture_ports & set(LOKI_PORTS), f"the fixture grants a Loki port: {fixture_ports}"

    worker = [a for a in _grants() if a.get("src") == ["tag:worker"]]
    assert len(worker) == 1, f"expected one tag:worker grant, found {len(worker)}"
    live_ports = set()
    for dst in worker[0]["dst"]:
        host, _, ports = dst.rpartition(":")
        assert host == "tag:controller", dst
        live_ports |= set(ports.split(","))
    assert live_ports == fixture_ports, f"live worker grant {sorted(live_ports)} != fixture {sorted(fixture_ports)}"
