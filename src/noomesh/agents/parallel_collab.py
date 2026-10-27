# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Parallel multi-agent collaboration via NATS streaming.

Agents think in parallel (even on a single backend — vLLM batches concurrent
requests), streaming token chunks through NATS so each agent perceives the
others' thinking in near real-time.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import structlog

from .. import json_fast as json

_logger = structlog.get_logger(__name__)


class _CollabConversationTracker:
    """Incrementally saves collab output to conversation store.

    Creates the conversation on start, appends each agent's output per
    iteration, and marks complete at the end.  Partial results survive
    crashes.
    """

    def __init__(self) -> None:
        self._store = None
        self._conv_id: str = ""
        #  via ConversationStoreProvider.
        try:
            from .._providers import default_conversation_store
            self._store = default_conversation_store().store()
        except Exception:
            _logger.debug("collab_tracker.store_unavailable", exc_info=True)

    async def on_start(self, collab_id: str, task: str, roles: list[str]) -> None:
        if not self._store:
            return
        try:
            self._conv_id = await self._store.create_conversation(
                user_id="collaboration",
                session_id=collab_id,
                metadata={"source": "collaboration", "roles": roles, "status": "running"},
            )
            await self._store.add_message(
                conversation_id=self._conv_id,
                role="user",
                content=task,
                metadata={"collab_id": collab_id, "roles": roles},
            )
        except Exception:
            _logger.debug("collab_tracker.start_failed", exc_info=True)

    async def on_agent_output(self, role: str, iteration: int, output: str) -> None:
        if not self._store or not self._conv_id or not output:
            return
        try:
            await self._store.add_message(
                conversation_id=self._conv_id,
                role="assistant",
                content=f"[{role} iter {iteration}]\n{output}",
                metadata={"role": role, "iteration": iteration},
            )
        except Exception:
            _logger.debug("collab_tracker.output_failed", exc_info=True)

    async def on_done(self, results: dict, outcomes: dict) -> None:
        if not self._store or not self._conv_id:
            return
        try:
            # Final combined summary
            parts = []
            for role, output in results.items():
                if output and output != "(timed out)":
                    parts.append(f"## {role.title()}\n\n{output}")
            if parts:
                await self._store.add_message(
                    conversation_id=self._conv_id,
                    role="assistant",
                    content="# Collaboration Summary\n\n" + "\n\n---\n\n".join(parts),
                    metadata={"type": "summary", "outcomes": outcomes},
                )
            _logger.info("collab_tracker.saved", conv_id=self._conv_id,
                         roles=list(results.keys()), chars=sum(len(v) for v in results.values()))
        except Exception:
            _logger.debug("collab_tracker.done_failed", exc_info=True)

# ---------------------------------------------------------------------------
# Optional dependency guards
# ---------------------------------------------------------------------------

try:
    from ..cluster.messaging import ClusterMessaging, get_messaging, NATS_AVAILABLE
except ImportError:
    NATS_AVAILABLE = False

    def get_messaging():  # type: ignore[misc]
        return None

#  via BackendResolver provider. Module-level alias
# preserves the existing `BACKEND_PORTS.get(...)` call-site syntax below.
from .._providers import default_backend_resolver as _default_backend_resolver
class _BackendPortsShim:
    def get(self, backend_type: str, default=None):
        port = _default_backend_resolver().port_for(backend_type)
        return port if port is not None else default
BACKEND_PORTS = _BackendPortsShim()

try:
    from ..cluster.node import NodeRegistry, get_node_registry  # noqa: F401
    NODE_AVAILABLE = True
except ImportError:
    NODE_AVAILABLE = False

    def get_node_registry():  # type: ignore[misc]
        return None


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BackendSlot:
    """A discovered backend running on a cluster node."""
    node_id: str
    backend_type: str       # "vllm" | "ollama" | "llamacpp"
    base_url: str
    model: str


@dataclass
class PeerSlot:
    """A registered external peer agent that can fill a role in a collab."""
    agent_id: str
    name: str
    roles: List[str]         # roles this peer can fill
    gateway_url: str         # PAI gateway URL for dispatching tasks to this peer


@dataclass
class AgentAssignment:
    """Maps a role to its assigned backend and LLM client."""
    role: str               # AgentRole.value
    backend: BackendSlot
    llm_client: Any         # LLMClient instance


@dataclass
class PeerAssignment:
    """Maps a role to an external peer agent instead of an internal backend."""
    role: str
    peer: PeerSlot


def slot_record(assignment: Any) -> Dict[str, Any]:
    """One entry of a ``collab_start`` event's ``backends`` list.

    A peer slot is marked ``backend_type: "peer"`` with the agent id in
    ``node_id``: that is how the gateway decides which connected peers may
    observe this collaboration's events (``ws_agent.rs::collab_relay``). Get
    it wrong and either a participant goes blind or a stranger reads the
    task text.
    """
    if isinstance(assignment, PeerAssignment):
        return {
            "node_id": assignment.peer.agent_id,
            "backend_type": "peer",
            "model": assignment.peer.name,
            "role": assignment.role,
        }
    return {
        "node_id": assignment.backend.node_id,
        "backend_type": assignment.backend.backend_type,
        "model": assignment.backend.model,
        "role": assignment.role,
    }


@dataclass
class PeerMessage:
    """A chunk of tokens (or signal) from one agent, visible to peers."""
    role: str
    iteration: int
    msg_type: str            # "tokens" | "conclusion" | "done"
    content: str
    timestamp: float


@dataclass
class AgentResult:
    """Final output from one agent in a parallel collaboration."""
    role: str
    output: str
    iterations: int
    backend_type: str
    node_id: str
    done_reason: str         # "converged" | "max_iterations" | "timeout" | "error"


# ---------------------------------------------------------------------------
# ParallelCollaboration
# ---------------------------------------------------------------------------

class ParallelCollaboration:
    """Run multiple agents in parallel with real-time token sharing via NATS."""

    MAX_ITERATIONS = 5
    GLOBAL_TIMEOUT = 300          # 5 min
    TOKEN_CHUNK_SIZE = 5          # publish every N tokens
    MAX_PEER_CONTEXT_CHARS = 4000
    DONE_SIGNAL = "[DONE]"

    def __init__(self, base_config: Any):
        self.base_config = base_config

    # ------------------------------------------------------------------
    # Backend discovery
    # ------------------------------------------------------------------

    @staticmethod
    def discover_backends() -> List[BackendSlot]:
        """Scan the node registry for running backends.

        Returns a list of ``BackendSlot`` for every backend currently
        running on a healthy node.  Works with 1+ backends.
        """
        if not NODE_AVAILABLE:
            return []

        registry = get_node_registry()
        if registry is None:
            return []

        slots: List[BackendSlot] = []
        for node in registry.list_nodes(healthy_only=True):
            for backend_type, model in node.running_backends.items():
                port = BACKEND_PORTS.get(backend_type)
                if port is None:
                    continue

                # Build URL via BackendResolver provider
                url = _default_backend_resolver().url_for(node, backend_type, port)

                slots.append(BackendSlot(
                    node_id=node.id,
                    backend_type=backend_type,
                    base_url=url,
                    model=model,
                ))

        return slots

    # ------------------------------------------------------------------
    # Peer agent discovery
    # ------------------------------------------------------------------

    @staticmethod
    def discover_peer_agents() -> List[PeerSlot]:
        """Always empty: peer delegation from this Python path is retired.

        It authenticated to the gateway with an admin-scoped JWT this module
        minted from ``NOO_JWT_SECRET`` — a token with no ``iss``/``aud``, which
        ``auth::verify_token`` has refused since those became required, so the
        lane was already dead. The worker no longer holds that secret at all.
        Collaboration runs in the gateway
        (``POST /api/agents/collaborate``), and a peer agent is reached over
        the A2A peer protocol, whose peer JWT is the real mechanism.
        """
        return []

    # ------------------------------------------------------------------
    # Agent assignment (internal + peer)
    # ------------------------------------------------------------------

    @staticmethod
    def _assign_agents(
        roles: List[str],
        backends: List[BackendSlot],
        peers: Optional[List[PeerSlot]] = None,
    ) -> List[Any]:  # List[AgentAssignment | PeerAssignment]
        """Assign roles to backends or peer agents.

        Peers are treated as generic work extensions — they don't need to
        advertise a matching role name. Any connected peer with *any* capability
        is a valid slot for any role. MESH offloads work to available peers and
        handles the rest internally. This keeps harnesses simple: they just
        advertise what they're good at (capabilities), not what internal MESH
        role they fill.

        Assignment priority:
          1. Use available peers to fill roles (round-robin over peers)
          2. Fill remaining roles from internal GPU backends (round-robin)
        """
        from ..factory import build_llm_client

        available_peers = list(peers) if peers else []
        assignments: List[Any] = []
        peer_idx = 0
        internal_idx = 0

        for role in roles:
            if available_peers and peer_idx < len(available_peers):
                # Assign to peer — peer handles whatever work MESH sends it
                peer = available_peers[peer_idx]
                peer_idx += 1
                assignments.append(PeerAssignment(role=role, peer=peer))
                _logger.info("collab_assign_peer", role=role,
                             agent_id=peer.agent_id,
                             capabilities=peer.capabilities)
            else:
                if not backends:
                    raise RuntimeError(
                        f"No backend available for role '{role}' and no peers left"
                    )
                backend = backends[internal_idx % len(backends)]
                internal_idx += 1
                client = build_llm_client(
                    base_url=backend.base_url,
                    model=backend.model,
                    backend_type=backend.backend_type,
                )
                assignments.append(AgentAssignment(
                    role=role, backend=backend, llm_client=client,
                ))
        return assignments

    # ------------------------------------------------------------------
    # Peer context
    # ------------------------------------------------------------------

    @staticmethod
    def _build_peer_context(
        peer_messages: Dict[str, List[PeerMessage]],
        own_role: str,
    ) -> str:
        """Format peers' accumulated tokens into a bounded context string.

        Excludes the agent's own messages.  Truncates to
        ``MAX_PEER_CONTEXT_CHARS`` total.
        """
        parts: List[str] = []
        budget = ParallelCollaboration.MAX_PEER_CONTEXT_CHARS

        for role, msgs in peer_messages.items():
            if role == own_role:
                continue
            text = "".join(m.content for m in msgs if m.msg_type == "tokens")
            if not text:
                continue
            header = f"[{role.upper()} thinking]:\n"
            available = budget - len(header) - 20  # margin for "...\n\n"
            if available <= 0:
                break
            if len(text) > available:
                text = text[:available] + "..."
            parts.append(header + text)
            budget -= len(parts[-1]) + 2  # newline gap

        return "\n\n".join(parts)

    # ------------------------------------------------------------------
    # Async stream bridge
    # ------------------------------------------------------------------

    @staticmethod
    async def _async_stream(agent: Any, session: Any, prompt: str):
        """Bridge sync ``agent.stream()`` to async world via a queue.

        ``agent.stream()`` is a synchronous generator yielding token events.
        We run it in a thread and re-yield events via an ``asyncio.Queue``.
        """
        queue: asyncio.Queue = asyncio.Queue()
        sentinel = object()

        def _run_sync():
            try:
                for event in agent.stream(session, prompt):
                    queue.put_nowait(event)
            finally:
                queue.put_nowait(sentinel)

        loop = asyncio.get_event_loop()
        thread_future = loop.run_in_executor(None, _run_sync)

        while True:
            event = await queue.get()
            if event is sentinel:
                break
            yield event

        # Propagate exceptions from the thread
        await thread_future

    # ------------------------------------------------------------------
    # Per-agent streaming loop
    # ------------------------------------------------------------------

    async def _streaming_agent_loop(
        self,
        assignment: AgentAssignment,
        task: str,
        peer_messages: Dict[str, List[PeerMessage]],
        done_event: asyncio.Event,
        collab_id: str,
        tracker: Optional[_CollabConversationTracker] = None,
    ) -> AgentResult:
        """Core per-agent loop: stream tokens, publish to NATS, inject peer context."""
        from ..factory import build_agent
        from ..agents.multi_agent import AGENT_SPECS, AgentRole

        role = assignment.role
        _logger.info("parallel_agent_start", role=role, backend=assignment.backend.backend_type,
                      node=assignment.backend.node_id)

        # Build a specialised agent with the assigned LLM client
        try:
            role_enum = AgentRole(role)
            spec = AGENT_SPECS[role_enum]
        except (ValueError, KeyError):
            spec = None

        if spec:
            config_dict = self.base_config.model_dump()
            config_dict["agent"]["system_prompt"] = spec.system_prompt
            config_dict["agent"]["max_tool_loops"] = spec.max_tool_loops
            if spec.preferred_tools:
                config_dict["tools"]["always_include"] = spec.preferred_tools
            from ..config import AppConfig
            specialized_config = AppConfig.model_validate(config_dict)
            agent = build_agent(specialized_config, llm_override=assignment.llm_client)
        else:
            agent = build_agent(self.base_config, llm_override=assignment.llm_client)

        session = agent.new_session()

        # NATS connection (optional — works without it)
        nats_client: Optional[ClusterMessaging] = None
        if NATS_AVAILABLE:
            try:
                nats_client = get_messaging()
                if nats_client and not nats_client.is_connected:
                    nats_client = None
            except Exception:
                _logger.debug("collab.nats_unavailable", exc_info=True)
                nats_client = None

        nats_subject = f"agent.collab.{collab_id}.{role}"
        output = ""

        async def _nats_pub(subject: str, data: dict):
            """Best-effort publish to NATS."""
            if not nats_client or not nats_client.js:
                return
            try:
                await nats_client.js.publish(subject, json.dumps(data).encode())
            except Exception:
                _logger.warning("collab.ctrl_done_publish_failed", collab_id=collab_id, exc_info=True)

        for iteration in range(1, self.MAX_ITERATIONS + 1):
            if done_event.is_set():
                break

            # Build prompt with latest peer context
            peer_ctx = self._build_peer_context(peer_messages, role)

            # Publish iteration_start event
            await _nats_pub(nats_subject, {
                "role": role, "iteration": iteration,
                "type": "iteration_start",
                "has_peer_context": bool(peer_ctx),
                "ts": time.time(),
            })

            if iteration == 1:
                prompt = task
                if peer_ctx:
                    prompt = f"{task}\n\n--- Other agents are also working on this ---\n{peer_ctx}"
            else:
                prompt = "Continue your work."
                if peer_ctx:
                    prompt += f"\n\n--- Peer progress ---\n{peer_ctx}"

            # Stream tokens, publishing chunks to NATS as they arrive
            token_buffer: List[str] = []
            full_output: List[str] = []
            prev_output_len = 0

            try:
                async for event in self._async_stream(agent, session, prompt):
                    etype = event.get("type", "")

                    if etype == "token":
                        content = event.get("content", "")
                        token_buffer.append(content)
                        full_output.append(content)

                        # Publish chunk every N tokens
                        if len(token_buffer) >= self.TOKEN_CHUNK_SIZE:
                            chunk = "".join(token_buffer)
                            token_buffer.clear()
                            peer_messages.setdefault(role, []).append(
                                PeerMessage(role, iteration, "tokens", chunk, time.time())
                            )
                            await _nats_pub(nats_subject, {
                                "role": role, "iteration": iteration,
                                "type": "tokens", "content": chunk,
                                "ts": time.time(),
                            })

                    elif etype == "tool_start":
                        tool_name = event.get("name", "unknown")
                        # Publish tool_call event
                        await _nats_pub(nats_subject, {
                            "role": role, "iteration": iteration,
                            "type": "tool_call", "tool": tool_name,
                            "ts": time.time(),
                        })

                        # === NATURAL BREAK POINT ===
                        # Inject accumulated peer context into session messages
                        fresh_peers = self._build_peer_context(peer_messages, role)
                        if fresh_peers:
                            # Determine which peers contributed
                            source_roles = [
                                r for r in peer_messages
                                if r != role and peer_messages[r]
                            ]
                            session.messages.append({
                                "role": "system",
                                "content": f"[Peer update] {fresh_peers}",
                            })
                            # Publish peer_inject event (visible cross-signal)
                            await _nats_pub(nats_subject, {
                                "role": role, "iteration": iteration,
                                "type": "peer_inject",
                                "from_roles": source_roles,
                                "chars": len(fresh_peers),
                                "ts": time.time(),
                            })

            except Exception as exc:
                _logger.error("parallel_agent_error", role=role, error=str(exc))
                return AgentResult(
                    role=role,
                    output=output or f"Error: {exc}",
                    iterations=iteration,
                    backend_type=assignment.backend.backend_type,
                    node_id=assignment.backend.node_id,
                    done_reason="error",
                )

            # Flush remaining token buffer to peers AND NATS (dashboard)
            if token_buffer:
                chunk = "".join(token_buffer)
                token_buffer.clear()
                peer_messages.setdefault(role, []).append(
                    PeerMessage(role, iteration, "tokens", chunk, time.time())
                )
                await _nats_pub(nats_subject, {
                    "role": role, "iteration": iteration,
                    "type": "tokens", "content": chunk,
                    "ts": time.time(),
                })

            output = "".join(full_output)

            # Save this iteration's NEW output to conversation store
            new_output = output[prev_output_len:]
            if new_output.strip():
                await tracker.on_agent_output(role, iteration, new_output)
            prev_output_len = len(output)

            # Check convergence
            if self.DONE_SIGNAL in output:
                _logger.info("parallel_agent_converged", role=role, iteration=iteration)
                # Publish done signal to NATS
                if nats_client and nats_client.js:
                    try:
                        payload = json.dumps({
                            "role": role, "iteration": iteration,
                            "type": "done", "content": "", "ts": time.time(),
                        }).encode()
                        await nats_client.js.publish(nats_subject, payload)
                    except Exception:
                        _logger.debug("collab.nats_done_publish_failed", role=role, exc_info=True)
                return AgentResult(
                    role=role,
                    output=output,
                    iterations=iteration,
                    backend_type=assignment.backend.backend_type,
                    node_id=assignment.backend.node_id,
                    done_reason="converged",
                )

        return AgentResult(
            role=role,
            output=output,
            iterations=self.MAX_ITERATIONS,
            backend_type=assignment.backend.backend_type,
            node_id=assignment.backend.node_id,
            done_reason="max_iterations",
        )

    # ------------------------------------------------------------------
    # Peer agent loop (external harness via /ws/agent)
    # ------------------------------------------------------------------

    async def _peer_agent_loop(
        self,
        assignment: "PeerAssignment",
        task: str,
        peer_messages: Dict[str, List[PeerMessage]],
        done_event: asyncio.Event,
        collab_id: str,
        tracker: Optional[_CollabConversationTracker] = None,
    ) -> AgentResult:
        """Retired: refuse, naming why (see :meth:`discover_peer_agents`).

        This used to POST the task to ``/api/agents/peer/{id}/task`` with a
        JWT minted here from ``NOO_JWT_SECRET`` and relay the peer's NATS
        stream. The gateway refused that token, and the worker no longer
        holds the secret.
        """
        # Unreachable while ``discover_peer_agents`` is empty; kept as a
        # refusal rather than a dispatch so a future caller that builds a
        # PeerAssignment by hand gets an explanation, not a 401.
        peer = assignment.peer
        return AgentResult(
            role=assignment.role,
            output=f"[Peer agent {peer.name} not dispatched: peer delegation from the Python "
                   "collaboration path is retired]",
            iterations=0,
            backend_type="peer", node_id=peer.agent_id,
            done_reason="error",
        )

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(
        self,
        task: str,
        roles: List[Any],  # List[AgentRole]
    ) -> Dict[str, AgentResult]:
        """Run all agents in parallel, returning their results.

        Args:
            task: The collaboration task description.
            roles: List of ``AgentRole`` enums to run concurrently.

        Returns:
            Dict mapping role name to ``AgentResult``.
        """
        backends = self.discover_backends()
        peers = self.discover_peer_agents()

        if not backends and not peers:
            raise RuntimeError("No running backends or peer agents discovered for collaboration")

        # If no internal backends but peers are available, still proceed.
        if not backends:
            _logger.warning("parallel_collab.no_internal_backends", peers=len(peers))
            # Provide a sentinel so _assign_agents doesn't divide-by-zero;
            # all roles will be assigned to peers (if they cover them).
            backends = []

        role_names = [r.value if hasattr(r, "value") else str(r) for r in roles]
        assignments = self._assign_agents(role_names, backends, peers=peers)

        collab_id = uuid.uuid4().hex[:12]
        done_event = asyncio.Event()
        peer_messages: Dict[str, List[PeerMessage]] = {}

        # Incremental conversation tracking
        tracker = _CollabConversationTracker()
        await tracker.on_start(collab_id, task, role_names)

        _logger.info(
            "parallel_collab_start",
            collab_id=collab_id,
            roles=role_names,
            backends=[f"{b.backend_type}@{b.node_id}" for b in backends],
        )

        # Publish collab_start to NATS so dashboards can initialise lanes
        nats_client: Optional[ClusterMessaging] = None  # type: ignore[assignment]
        if NATS_AVAILABLE:
            try:
                nats_client = get_messaging()
                if nats_client and not nats_client.is_connected:
                    nats_client = None
            except Exception:
                _logger.debug("collab.nats_unavailable", exc_info=True)
                nats_client = None

        ctrl_subject = f"agent.collab.{collab_id}.ctrl"
        if nats_client and nats_client.js:
            try:
                await nats_client.js.publish(ctrl_subject, json.dumps({
                    "type": "collab_start",
                    "collab_id": collab_id,
                    "task": task[:500],
                    "roles": role_names,
                    "backends": [slot_record(a) for a in assignments],
                    "ts": time.time(),
                }).encode())
            except Exception as exc:
                # This used to swallow an AttributeError: the comprehension
                # read ``a.backend`` for EVERY assignment, and a
                # ``PeerAssignment`` has ``.peer``. So collab_start was
                # silently dropped for exactly the collaborations that had a
                # peer in them — and the gateway now relays collab events to
                # a peer only when a collab_start names it, so a dropped
                # event is a peer that never sees its own collaboration.
                _logger.warning("collab_start_publish_failed",
                                collab_id=collab_id, error=str(exc))

        # Launch all agent loops concurrently — internal or peer depending on assignment type
        coros = [
            (
                self._peer_agent_loop(a, task, peer_messages, done_event, collab_id, tracker)
                if isinstance(a, PeerAssignment)
                else self._streaming_agent_loop(a, task, peer_messages, done_event, collab_id, tracker)
            )
            for a in assignments
        ]

        try:
            raw_results = await asyncio.wait_for(
                asyncio.gather(*coros, return_exceptions=True),
                timeout=self.GLOBAL_TIMEOUT,
            )
            # Separate successful results from exceptions
            results_list: List[AgentResult] = []
            for i, result in enumerate(raw_results):
                if isinstance(result, BaseException):
                    a = assignments[i]
                    _logger.error(
                        "parallel_agent_exception",
                        role=a.role, error=str(result),
                    )
                    tokens = peer_messages.get(a.role, [])
                    output = "".join(m.content for m in tokens if m.msg_type == "tokens")
                    is_peer = isinstance(a, PeerAssignment)
                    results_list.append(AgentResult(
                        role=a.role,
                        output=output or f"Error: {result}",
                        iterations=0,
                        backend_type="peer" if is_peer else a.backend.backend_type,
                        node_id=a.peer.agent_id if is_peer else a.backend.node_id,
                        done_reason="error",
                    ))
                else:
                    results_list.append(result)
        except asyncio.TimeoutError:
            _logger.warning("parallel_collab_timeout", collab_id=collab_id)
            done_event.set()
            # Collect whatever partial results we have
            results_list = []
            for a in assignments:
                tokens = peer_messages.get(a.role, [])
                output = "".join(m.content for m in tokens if m.msg_type == "tokens")
                # Same `a.backend` trap as collab_start had: a PeerAssignment
                # carries `.peer`, so a timed-out collaboration with a peer in
                # it used to raise here instead of returning partial results.
                slot = slot_record(a)
                results_list.append(AgentResult(
                    role=a.role,
                    output=output or "(timed out)",
                    iterations=0,
                    backend_type=slot["backend_type"],
                    node_id=slot["node_id"],
                    done_reason="timeout",
                ))

        results = {r.role: r for r in results_list}

        # Save final summary to conversation store
        await tracker.on_done(
            {r.role: r.output for r in results_list},
            {r.role: r.done_reason for r in results_list},
        )

        _logger.info(
            "parallel_collab_done",
            collab_id=collab_id,
            outcomes={r.role: r.done_reason for r in results_list},
        )

        # Publish collab_done to NATS
        if nats_client and nats_client.js:
            try:
                await nats_client.js.publish(ctrl_subject, json.dumps({
                    "type": "collab_done",
                    "collab_id": collab_id,
                    "outcomes": {r.role: r.done_reason for r in results_list},
                    "results": {
                        r.role: r.output[:2000] for r in results_list
                        if r.output and r.output != "(timed out)"
                    },
                    "ts": time.time(),
                }).encode())
            except Exception:
                _logger.warning("collab.ctrl_done_publish_failed", collab_id=collab_id, exc_info=True)

        return results
