# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""i403: the gateway's copy of the node agent's golden `lanes` heartbeat.

The node agent writes and tests
`node-agent-go/internal/heartbeat/testdata/lanes_fixture.json`. The gateway's
class-table test reads a copy under `gateway-rust/src/coordinator/testdata/`,
because `include_str!` may only reach files the gateway's Docker builder
stage copies, and a node-agent test file does not belong in that image build.
Two copies of one contract drift unless something compares them: this does.
Change the agent's fixture, then copy it over, and both suites judge the same
heartbeat.
"""

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
AGENT = REPO / "node-agent-go/internal/heartbeat/testdata/lanes_fixture.json"
GATEWAY = REPO / "gateway-rust/src/coordinator/testdata/lanes_fixture.json"


def test_the_gateway_reads_the_agents_golden_lanes_byte_for_byte() -> None:
    assert AGENT.is_file(), f"the node agent's fixture is gone: {AGENT.relative_to(REPO)}"
    assert GATEWAY.is_file(), f"the gateway's copy is gone: {GATEWAY.relative_to(REPO)}"
    assert GATEWAY.read_bytes() == AGENT.read_bytes(), (
        f"{GATEWAY.relative_to(REPO)} differs from {AGENT.relative_to(REPO)}: "
        f"copy the agent's fixture over (cp {AGENT.relative_to(REPO)} {GATEWAY.relative_to(REPO)}) "
        "and make the gateway's lane test agree with it"
    )


def test_the_gateway_test_reads_the_copy_not_the_agent_file() -> None:
    src = (REPO / "gateway-rust/src/coordinator/classes.rs").read_text()
    assert 'include_str!("testdata/lanes_fixture.json")' in src
    assert 'include_str!("../../../node-agent-go' not in src, "outside the gateway's build context"
