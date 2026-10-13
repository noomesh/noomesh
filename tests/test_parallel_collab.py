# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for parallel multi-agent collaboration."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from noomesh.agents.parallel_collab import (
    BackendSlot,
    ParallelCollaboration,
    PeerMessage,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_backends(n: int = 2) -> list[BackendSlot]:
    return [
        BackendSlot(
            node_id=f"node-{i}",
            backend_type="vllm" if i % 2 == 0 else "ollama",
            base_url=f"http://10.0.0.{i}:8000",
            model=f"model-{i}",
        )
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# discover_backends
# ---------------------------------------------------------------------------

class TestDiscoverBackends:
    """Test backend discovery from the node registry."""

    def test_no_node_module(self):
        """The empty path is now the DEFAULT: cluster/node.py is archived
        (fu 58), so NODE_AVAILABLE is import-time False — no patch needed."""
        assert ParallelCollaboration.discover_backends() == []

    def test_no_healthy_nodes(self):
        """Returns empty when registry has no healthy nodes."""
        mock_registry = MagicMock()
        mock_registry.list_nodes.return_value = []
        with (
            patch("noomesh.agents.parallel_collab.NODE_AVAILABLE", True),
            patch("noomesh.agents.parallel_collab.get_node_registry", return_value=mock_registry),
        ):
            assert ParallelCollaboration.discover_backends() == []

    def test_discovers_running_backends(self):
        """Discovers backends from running nodes."""
        mock_node = MagicMock()
        mock_node.id = "gpu-01"
        mock_node.ip_address = "10.0.0.1"
        mock_node.running_backends = {"vllm": "llama3"}
        mock_node.agent_url = ""

        mock_registry = MagicMock()
        mock_registry.list_nodes.return_value = [mock_node]

        with (
            patch("noomesh.agents.parallel_collab.NODE_AVAILABLE", True),
            patch("noomesh.agents.parallel_collab.get_node_registry", return_value=mock_registry),
            patch("noomesh.agents.parallel_collab.BACKEND_PORTS", {"vllm": 8000}),
        ):
            slots = ParallelCollaboration.discover_backends()
            assert len(slots) == 1
            assert slots[0].node_id == "gpu-01"
            assert slots[0].backend_type == "vllm"
            assert slots[0].model == "llama3"
            assert "10.0.0.1" in slots[0].base_url


# ---------------------------------------------------------------------------
# _assign_agents
# ---------------------------------------------------------------------------

class TestAssignAgents:
    """Test round-robin agent assignment."""

    def test_round_robin_3_on_2(self):
        """3 agents on 2 backends: wraps around."""
        backends = _make_backends(2)
        roles = ["planner", "coder", "reviewer"]
        with patch("noomesh.factory.build_llm_client", return_value=MagicMock()):
            assignments = ParallelCollaboration._assign_agents(roles, backends)
        assert len(assignments) == 3
        assert assignments[0].backend.node_id == "node-0"
        assert assignments[1].backend.node_id == "node-1"
        assert assignments[2].backend.node_id == "node-0"  # wraps

    def test_round_robin_5_on_1(self):
        """5 agents all share 1 backend."""
        backends = _make_backends(1)
        roles = ["a", "b", "c", "d", "e"]
        with patch("noomesh.factory.build_llm_client", return_value=MagicMock()):
            assignments = ParallelCollaboration._assign_agents(roles, backends)
        assert all(a.backend.node_id == "node-0" for a in assignments)

    def test_each_gets_own_client(self):
        """Each assignment gets a fresh LLM client."""
        backends = _make_backends(1)
        roles = ["planner", "coder"]
        clients = []

        def _capture(*a, **kw):
            c = MagicMock()
            clients.append(c)
            return c

        with patch("noomesh.factory.build_llm_client", side_effect=_capture):
            assignments = ParallelCollaboration._assign_agents(roles, backends)
        assert len(clients) == 2
        assert assignments[0].llm_client is not assignments[1].llm_client


# ---------------------------------------------------------------------------
# _build_peer_context
# ---------------------------------------------------------------------------

class TestBuildPeerContext:
    """Test peer context formatting."""

    def test_excludes_self(self):
        """Own role is excluded from peer context."""
        peer_msgs = {
            "planner": [PeerMessage("planner", 1, "tokens", "my plan", 1.0)],
            "coder": [PeerMessage("coder", 1, "tokens", "my code", 1.0)],
        }
        ctx = ParallelCollaboration._build_peer_context(peer_msgs, "planner")
        assert "CODER" in ctx
        assert "PLANNER" not in ctx

    def test_empty_peers(self):
        """Returns empty string when no peers have output."""
        ctx = ParallelCollaboration._build_peer_context({}, "planner")
        assert ctx == ""

    def test_budget_truncation(self):
        """Long peer output gets truncated to budget."""
        long_text = "x" * 10000
        peer_msgs = {
            "coder": [PeerMessage("coder", 1, "tokens", long_text, 1.0)],
        }
        ctx = ParallelCollaboration._build_peer_context(peer_msgs, "planner")
        assert len(ctx) <= ParallelCollaboration.MAX_PEER_CONTEXT_CHARS + 100
        assert "..." in ctx

    def test_multiple_peers(self):
        """Multiple peers are included."""
        peer_msgs = {
            "planner": [PeerMessage("planner", 1, "tokens", "plan", 1.0)],
            "coder": [PeerMessage("coder", 1, "tokens", "code", 1.0)],
            "reviewer": [PeerMessage("reviewer", 1, "tokens", "review", 1.0)],
        }
        ctx = ParallelCollaboration._build_peer_context(peer_msgs, "planner")
        assert "CODER" in ctx
        assert "REVIEWER" in ctx
        assert "PLANNER" not in ctx


# ---------------------------------------------------------------------------
# _async_stream bridge
# ---------------------------------------------------------------------------

class TestAsyncStream:
    """Test the sync-to-async generator bridge."""

    @pytest.mark.asyncio
    async def test_yields_events(self):
        """Bridge correctly yields events from sync generator."""
        events = [
            {"type": "token", "content": "hello"},
            {"type": "token", "content": " world"},
            {"type": "tool_start", "name": "web_search", "args": {}},
            {"type": "tool_complete", "name": "web_search"},
            {"type": "token", "content": "done"},
        ]

        mock_agent = MagicMock()
        mock_agent.stream.return_value = iter(events)

        mock_session = MagicMock()

        collected = []
        async for event in ParallelCollaboration._async_stream(mock_agent, mock_session, "test"):
            collected.append(event)

        assert len(collected) == len(events)
        assert collected[0]["content"] == "hello"
        assert collected[2]["type"] == "tool_start"


# ---------------------------------------------------------------------------
# collaborate() mode routing
# ---------------------------------------------------------------------------

class TestCollaborateModeRouting:
    """Test that collaborate() routes to parallel or sequential correctly."""

    @pytest.mark.asyncio
    async def test_force_sequential(self):
        """force_sequential=True always uses sequential."""
        from noomesh.agents.multi_agent import AgentOrchestrator, AgentRole

        config = MagicMock()
        config.model_dump.return_value = {
            "agent": {"system_prompt": "", "max_tool_loops": 3, "tool_mode": "auto"},
            "tools": {"always_include": []},
        }

        orch = AgentOrchestrator(base_config=config)

        # Mock _sequential_collaborate to track it was called
        seq_called = False
        original_seq = None

        async def _mock_sequential(task, workflow):
            nonlocal seq_called
            seq_called = True
            return {AgentRole.PLANNER: "plan output"}

        orch._sequential_collaborate = _mock_sequential

        result = await orch.collaborate(
            "test task",
            [AgentRole.PLANNER],
            force_sequential=True,
        )
        assert seq_called
        assert AgentRole.PLANNER in result

    @pytest.mark.asyncio
    async def test_parallel_fallback_on_no_backends(self):
        """Falls back to sequential when no backends are discovered."""
        from noomesh.agents.multi_agent import AgentOrchestrator, AgentRole

        config = MagicMock()
        orch = AgentOrchestrator(base_config=config)

        seq_called = False

        async def _mock_sequential(task, workflow):
            nonlocal seq_called
            seq_called = True
            return {AgentRole.PLANNER: "seq output"}

        orch._sequential_collaborate = _mock_sequential

        with patch("noomesh.agents.multi_agent.PARALLEL_AVAILABLE", True), \
             patch("noomesh.agents.multi_agent.ParallelCollaboration") as MockPC:
            MockPC.discover_backends.return_value = []  # No backends

            result = await orch.collaborate("test", [AgentRole.PLANNER])

        assert seq_called


# ---------------------------------------------------------------------------
# collab_start participant records
# ---------------------------------------------------------------------------

class TestSlotRecord:
    """The gateway decides which peers may observe a collaboration from the
    ``backends`` list in ``collab_start`` (``ws_agent.rs::collab_relay``), so
    a peer slot has to be recorded as one."""

    def test_peer_assignment_is_recorded_as_a_peer_slot(self):
        from noomesh.agents.parallel_collab import (
            PeerAssignment, PeerSlot, slot_record,
        )

        peer = PeerSlot(agent_id="hermes-1", name="Hermes", roles=["analyst"],
                        gateway_url="https://localhost:8080")
        rec = slot_record(PeerAssignment(role="analyst", peer=peer))
        assert rec["backend_type"] == "peer"
        assert rec["node_id"] == "hermes-1"
        assert rec["role"] == "analyst"

    def test_internal_assignment_keeps_its_backend_fields(self):
        from noomesh.agents.parallel_collab import AgentAssignment, slot_record

        backend = _make_backends(1)[0]
        rec = slot_record(AgentAssignment(role="coder", backend=backend,
                                          llm_client=object()))
        assert rec["backend_type"] == backend.backend_type
        assert rec["node_id"] == backend.node_id

    def test_a_mixed_assignment_list_serialises(self):
        """The old comprehension read ``a.backend`` for every assignment, so
        this raised AttributeError inside a bare ``except: pass`` — and
        collab_start vanished for exactly the collaborations with a peer."""
        from noomesh.agents.parallel_collab import (
            AgentAssignment, PeerAssignment, PeerSlot, slot_record,
        )

        peer = PeerSlot(agent_id="hermes-1", name="Hermes", roles=["analyst"],
                        gateway_url="https://localhost:8080")
        assignments = [
            AgentAssignment(role="coder", backend=_make_backends(1)[0],
                            llm_client=object()),
            PeerAssignment(role="analyst", peer=peer),
        ]
        records = [slot_record(a) for a in assignments]
        assert [r["backend_type"] for r in records] == ["vllm", "peer"]
