# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""The node agent never deletes a JetStream consumer, and its grant never lets it.

Two halves of one contract (see test_nats_node_subject_parity.py for the
subjects the node publishes):

* the node grant (noo-cli/src/commands/nats_users.rs) never allows
  $JS.API.CONSUMER.DELETE: repairing a node's durable is the gateway's job;
* the agent never asks for one. nats.go deletes a consumer on
  Unsubscribe()/Drain() when its own js.Subscribe created it, and the agent
  rebinds on every reconnect. Until i677 (finding b, install matrix run 6) a
  fresh box's first subscribe created both durables, so every reconnect
  published $JS.API.CONSUMER.DELETE.TASKS.node_<id>_dispatch, refused as a
  "permissions violation" (and, had the grant allowed it, the node would have
  thrown away its pending dispatches). The executor now creates the consumer
  itself and only ever subscribes bound to it.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXECUTOR = ROOT / "node-agent-go" / "internal" / "jobs" / "executor.go"
NATS_USERS = ROOT / "noo-cli" / "src" / "commands" / "nats_users.rs"


def test_the_node_grant_never_allows_a_consumer_delete():
    src = NATS_USERS.read_text()
    allow_lines = [l for l in src.splitlines() if "allow: [" in l and "node_{id}_dispatch" in l]
    assert allow_lines, "the node grant's allow list was not found: this test checks nothing"
    for line in allow_lines:
        assert "CONSUMER.DELETE" not in line, line


def test_the_agent_never_deletes_and_never_lets_the_library_own_a_consumer():
    go = EXECUTOR.read_text()
    assert "DeleteConsumer(" not in go, "the node must never delete a consumer: the gateway repairs durables"
    subscribes = re.findall(r"js\.Subscribe\(([^\n]*)", go)
    assert subscribes, "no js.Subscribe found: this test checks nothing"
    for call in subscribes:
        assert "nats.Bind(stream, durable)" in call, (
            "a js.Subscribe that is not bound lets nats.go create the consumer, and then delete it "
            "on the next rebind: " + call
        )
