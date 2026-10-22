# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Prompt skills, exec approval, agents, and workflow tools."""
from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Optional

from pydantic import Field

from ..tool_models import HttpMethod, RiskLevel, ToolDef, register

# ═══════════════════════════════════════════════════════════════
# Prompt Skills
# ═══════════════════════════════════════════════════════════════


@register
class PaiPromptSkillsList(ToolDef):
    """List available prompt skills (evolved and core templates)."""

    name: ClassVar[str] = "noo_prompt_skills_list"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/prompt-skills"
    tags: ClassVar[List[str]] = ["skills", "prompts"]

    def format_response(self, data: Any) -> str:
        if not isinstance(data, (dict, list)):
            return str(data)
        skills = data if isinstance(data, list) else data.get("skills", [])
        if not skills:
            return "No prompt skills available."
        lines = [f"Prompt skills ({len(skills)}):\n"]
        for s in skills:
            name = s.get("name", "?")
            desc = s.get("description", "")
            tags = ", ".join(s.get("tags", []))
            line = f"  {name}"
            if desc:
                line += f" — {desc}"
            if tags:
                line += f" [{tags}]"
            lines.append(line)
        return "\n".join(lines)


@register
class PaiPromptSkillsGet(ToolDef):
    """Get a specific prompt skill by name, including its full content."""

    name: ClassVar[str] = "noo_prompt_skills_get"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/prompt-skills/{skill_name}"
    tags: ClassVar[List[str]] = ["skills", "prompts"]

    skill_name: str = Field(description="Name of the prompt skill to retrieve")

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict):
            return str(data)
        name = data.get("name", "?")
        desc = data.get("description", "")
        role = data.get("role", "")
        content = data.get("content", "")
        lines = [f"# {name}"]
        if desc:
            lines.append(f"\n{desc}")
        if role:
            lines.append(f"\nRole: {role}")
        if content:
            lines.append(f"\n---\n{content}")
        return "\n".join(lines)


@register
class PaiPromptSkillsCreate(ToolDef):
    """Create a new prompt skill template. It is data until a person promotes it."""

    name: ClassVar[str] = "noo_prompt_skills_create"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/prompt-skills"
    tags: ClassVar[List[str]] = ["skills", "prompts"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    name_field: str = Field(alias="name", description="Unique skill name")
    description_field: str = Field(alias="description", description="Short description of the skill")
    tags_field: Optional[List[str]] = Field(default=None, alias="tags", description="Categorization tags")
    content: str = Field(description="The prompt skill template content")
    role: Optional[str] = Field(default=None, description="Agent role this skill applies to")

    class Config:
        populate_by_name = True


@register
class PaiPromptSkillsEvolve(ToolDef):
    """Propose (or with apply=true, write) an LLM-evolved prompt skill from an observation. A written skill is data until a person promotes it."""

    name: ClassVar[str] = "noo_prompt_skills_evolve"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/prompt-skills/evolve"
    tags: ClassVar[List[str]] = ["skills", "prompts", "ga"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    # The evolve add-on runs an LLM decision plus a moderation pass; the
    # gateway route allows 300 s, so the door must not give up first.
    timeout_secs: ClassVar[int] = 300

    observation: Optional[str] = Field(default=None, description="Observation to guide evolution")
    skill: Optional[str] = Field(default=None, description="Point the pass at one existing skill")
    role: Optional[str] = Field(default=None, description="Role to evolve skills for")
    apply: bool = Field(default=False, description="Write the proposal. Default false: return it and write nothing")


# ═══════════════════════════════════════════════════════════════
# Exec Approval
# ═══════════════════════════════════════════════════════════════


@register
class PaiApprovalPending(ToolDef):
    """List pending exec approval requests waiting for human review."""

    name: ClassVar[str] = "noo_approval_pending"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/approval/pending"
    tags: ClassVar[List[str]] = ["approval", "security"]

    def format_response(self, data: Any) -> str:
        if not isinstance(data, (dict, list)):
            return str(data)
        requests = data if isinstance(data, list) else data.get("pending", [])
        if not requests:
            return "No pending approval requests."
        lines = [f"Pending approvals ({len(requests)}):\n"]
        for r in requests:
            rid = r.get("request_id", r.get("id", "?"))
            tool = r.get("tool", r.get("action", "?"))
            risk = r.get("risk_level", "?")
            lines.append(f"  [{rid}] {tool} (risk: {risk})")
        return "\n".join(lines)


@register
class PaiApprovalStats(ToolDef):
    """Get approval queue statistics: pending, approved, denied counts."""

    name: ClassVar[str] = "noo_approval_stats"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/approval/stats"
    tags: ClassVar[List[str]] = ["approval", "security"]


# noo_approval_approve / noo_approval_deny are deliberately NOT tools. An approval
# decision is a human's: a model that could call them could approve its own
# High-risk call. Humans decide in the dashboard, with `noo approval`, or from a
# linked channel; the routes also refuse any agent, harness or MCP-door credential.


# ═══════════════════════════════════════════════════════════════
# Agents & Workflows
# ═══════════════════════════════════════════════════════════════


@register
class PaiAgentsCollaborate(ToolDef):
    """Start a multi-agent collaboration session. Agents with specified roles
    work together on the task, coordinated by the orchestrator."""

    name: ClassVar[str] = "noo_agents_collaborate"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/agents/collaborate"
    tags: ClassVar[List[str]] = ["agents", "collaboration"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    task: str = Field(description="Task description for the agent team")
    workflow: Optional[str] = Field(default=None, description="Workflow pattern: round_robin, debate, pipeline")
    roles: Optional[List[str]] = Field(default=None, description="Agent roles to include (e.g. researcher, coder, reviewer)")


@register
class PaiWorkflowRun(ToolDef):
    """Run a predefined workflow by name with optional inputs."""

    name: ClassVar[str] = "noo_workflow_run"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/workflows/run"
    tags: ClassVar[List[str]] = ["workflows"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM

    workflow_name: str = Field(description="Name of the workflow to run")
    inputs: Optional[Dict[str, Any]] = Field(default=None, description="Input parameters for the workflow")


@register
class PaiWorkflowList(ToolDef):
    """List available predefined workflows."""

    name: ClassVar[str] = "noo_workflow_list"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/workflows"
    tags: ClassVar[List[str]] = ["workflows"]


# ═══════════════════════════════════════════════════════════════
# Agent-to-agent messaging
# ═══════════════════════════════════════════════════════════════


@register
class NooAgentSend(ToolDef):
    """Send a message to another agent on the mesh. Addressed by agent id
    (e.g. "host3/claude-code-1"), or "thread" to post into an existing thread,
    or "*" to broadcast (operators and internal services only). Recorded and
    delivered over NATS; the sender is the caller's identity — user, node and
    harness are derived from the credential, never from this call."""

    name: ClassVar[str] = "noo_agent_send"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/agents/messages"
    tags: ClassVar[List[str]] = ["agents", "messaging", "external"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    to: str = Field(description='Recipient agent id, "thread" (needs thread_id) or "*" for broadcast')
    text: Optional[str] = Field(default=None, description="Plain-text body (use body for structured JSON)")
    body: Optional[Dict[str, Any]] = Field(default=None, description="Structured JSON body (overrides text)")
    kind: Optional[str] = Field(default=None, description="message | task | result | ack | note (default message)")
    thread_id: Optional[str] = Field(default=None, description="Reply into this thread; omitted = a new thread")
    refs: Optional[List[str]] = Field(default=None, description="Message ids this refers to")
    agent: Optional[str] = Field(default=None, description="Your agent instance name (e.g. claude-code-1)")
    harness: Optional[str] = Field(
        default=None,
        description=(
            "The software you say you are (e.g. claude-code). Recorded as an "
            "unverified claim beside the harness the gateway derives from your "
            "credential; it never replaces it"
        ),
    )


@register
class NooAgentInbox(ToolDef):
    """Read your account's agent messages, newest first: everything addressed
    to any name under your account (every window and label you run), plus
    the threads those names take part in. Narrow with to= (one name) or
    thread=. Read state is per reader: unread=true shows what THIS
    credential has not yet acknowledged, whatever a sibling window acked.
    Acknowledge with noo_agent_ack. Operators may name another account."""

    name: ClassVar[str] = "noo_agent_inbox"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/agents/messages"
    tags: ClassVar[List[str]] = ["agents", "messaging", "external"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    to: Optional[str] = Field(default=None, description="Agent id whose inbox to read (operators only; default = you)")
    thread: Optional[str] = Field(default=None, description="Only this thread")
    unread: Optional[bool] = Field(default=None, description="Only messages not yet acknowledged")
    since: Optional[str] = Field(default=None, description="RFC 3339 — only messages after this time")
    all: Optional[bool] = Field(
        default=None,
        description="Operators only: list every session's messages, not just yours.",
    )
    limit: Optional[int] = Field(default=None, description="Max messages (default 50)")


@register
class NooAgentWhoami(ToolDef):
    """Your own agent name on this session — the address other sessions use to message you."""

    name: ClassVar[str] = "noo_agent_whoami"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/agents/whoami"
    tags: ClassVar[List[str]] = ["agents", "messaging", "external"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW


@register
class NooAgentThread(ToolDef):
    """Read one conversation thread between agents (all messages in it)."""

    name: ClassVar[str] = "noo_agent_thread"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.GET
    path: ClassVar[str] = "/api/agents/messages"
    tags: ClassVar[List[str]] = ["agents", "messaging", "external"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    thread: str = Field(description="Thread id (thr_…)")
    limit: Optional[int] = Field(default=None, description="Max messages (default 50; use 500 for a full thread)")


@register
class NooAgentAck(ToolDef):
    """Acknowledge (mark read) a message addressed to you."""

    name: ClassVar[str] = "noo_agent_ack"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/agents/messages/{message_id}/ack"
    tags: ClassVar[List[str]] = ["agents", "messaging", "external"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.LOW

    message_id: str = Field(description="The message id (msg_…)")
