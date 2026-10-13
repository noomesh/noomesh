# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The log label vocabulary is declared in three places that cannot see each other.

Fleet logging phase 6. The node-agent's shipper renders a FIXED label map
(`node-agent-go/internal/logship/entry.go`, `Labels.wire`), the gateway's
ingest route keeps exactly an allow-list and overwrites `node`
(`gateway-rust/src/routes/logs_ingest.rs`, `ALLOWED_LABELS` + `NODE_LABEL`),
and `docs/operating/monitoring.md` tells the operator which labels a query
can use. A key added to one and not the others is either dropped silently
at the gateway (the shipper's cardinality-safe set is the gateway's, not
a superset) or documented and never present.

The Go test `TestWireLabelsAreExactlyTheFixedKeys` proves what the shipper
sends; this proves the three declarations agree.

Planted 2026-09-28: `compose_service` removed from the doc table → the
doc assertion fails; `"stream"` renamed in `wire` → the Go/gateway
assertion fails.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests.source_scan import executable_source

ROOT = Path(__file__).resolve().parents[1]
ENTRY_GO = ROOT / "node-agent-go/internal/logship/entry.go"
INGEST_RS = ROOT / "gateway-rust/src/routes/logs_ingest.rs"
MONITORING_MD = ROOT / "docs/operating/monitoring.md"


def shipper_labels() -> set[str]:
    """The keys `Labels.wire` puts on the wire, `node` included."""
    src = executable_source(ENTRY_GO)
    body = src.split("func (l Labels) wire(", 1)[1].split("\n}\n", 1)[0]
    keys = set(re.findall(r'^\s*"([a-z_]+)":\s', body, re.M))  # the literal map
    keys |= set(re.findall(r'm\["([a-z_]+)"\]\s*=', body))  # the conditional ones
    assert keys, "Labels.wire builds no label map any more — the parse found nothing"
    return keys


def gateway_labels() -> set[str]:
    src = executable_source(INGEST_RS)
    m = re.search(r'pub const ALLOWED_LABELS: &\[&str\] = &\[([^\]]*)\];', src)
    assert m, "logs_ingest.rs no longer declares ALLOWED_LABELS"
    allowed = set(re.findall(r'"([a-z_]+)"', m.group(1)))
    node = re.search(r'pub const NODE_LABEL: &str = "([a-z_]+)";', src)
    assert node, "logs_ingest.rs no longer declares NODE_LABEL"
    assert allowed, "ALLOWED_LABELS is empty"
    return allowed | {node.group(1)}


def documented_labels() -> set[str]:
    text = MONITORING_MD.read_text()
    section = text.split("### The label vocabulary", 1)[1].split("\n### ", 1)[0]
    rows = re.findall(r"^\| `([a-z_]+)` \|", section, re.M)
    assert rows, "monitoring.md's label table has no rows under 'The label vocabulary'"
    return set(rows)


def test_the_shipper_sends_exactly_the_gateways_label_set() -> None:
    assert shipper_labels() == gateway_labels()


def test_the_documented_vocabulary_is_the_gateways() -> None:
    assert documented_labels() == gateway_labels()


def test_node_is_the_gateways_to_set() -> None:
    """`node` is on the wire for readability only; the gateway overwrites it
    from the verified identity, so it must never be in the client-side
    allow-list of things the gateway KEEPS."""
    src = executable_source(INGEST_RS)
    m = re.search(r'pub const ALLOWED_LABELS: &\[&str\] = &\[([^\]]*)\];', src)
    assert m and '"node"' not in m.group(1), "node must not be an allowed client label — the gateway sets it"
