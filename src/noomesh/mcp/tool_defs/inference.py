# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Inference and coding tools — prompt execution, agentic runs, coding tasks."""
from __future__ import annotations

from typing import Any, ClassVar, List, Optional

from pydantic import Field

from ..tool_models import HttpMethod, RiskLevel, ToolDef, register


@register
class PaiInference(ToolDef):
    """Run a prompt through the cluster inference pipeline. Automatically resolves
    a backend (local-first, cloud fallback). Returns the model's response text."""

    name: ClassVar[str] = "noo_inference"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/inference"
    tags: ClassVar[List[str]] = ["core", "inference", "external"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    # Pin to a single agentic iteration. POST /api/inference goes to Rust's
    # native_inference, which by default runs the FULL agentic loop (tools +
    # iterations). When the *coordinator itself* invokes noo_inference as a
    # tool that re-enters the loop and times out at 120s every time. Forcing
    # max_iterations=1 makes this a single-turn LLM call as the description
    # promises (use noo_agentic_inference if recursive agentic behaviour is
    # actually desired).
    timeout_secs: ClassVar[int] = 120

    prompt: str = Field(description="The prompt to send for inference")
    model: Optional[str] = Field(default=None, description="Model name (auto-selected if omitted)")
    backend: Optional[str] = Field(default=None, description="Backend type: vllm, ollama, llamacpp")
    node: Optional[str] = Field(default=None, description=(
        "Pin to a specific cluster node by id (e.g. 'host9') — sends the "
        "prompt to the model running ON that node instead of auto-routing. "
        "Use when the user addresses a particular node ('ask host9 ...')."
    ))
    max_tokens: Optional[int] = Field(default=None, description="Maximum tokens to generate")
    temperature: Optional[float] = Field(default=None, description="Sampling temperature (0.0-2.0)")
    context: bool = Field(default=True, description=(
        "Set false for context-free generation — a function, a conversion, a "
        "draft from a spec in the prompt. The prompt goes to the model as the "
        "only message: the user's memory and documents are NOT included, and "
        "no conversation is recorded. Far cheaper (tens of prompt tokens "
        "instead of thousands). Leave true when the answer needs what the "
        "user has stored."
    ))

    def get_body(self) -> Optional[dict]:
        body = super().get_body() or {}
        body.setdefault("max_iterations", 1)
        body.setdefault("channel", "tool_call")
        return body

    def format_response(self, data: Any) -> str:
        if isinstance(data, dict):
            return data.get("response", data.get("text", str(data)))
        return str(data)


@register
class PaiAgenticInference(ToolDef):
    """Run a prompt through the coordinator's agentic loop. The coordinator plans,
    calls tools, and iterates until it has a complete answer. Returns the final
    response and a list of tool calls made during reasoning."""

    name: ClassVar[str] = "noo_agentic_inference"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/agent/run"
    tags: ClassVar[List[str]] = ["core", "inference", "agent", "external"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    timeout_secs: ClassVar[int] = 180

    prompt: str = Field(description="The prompt for the agentic coordinator")
    model: Optional[str] = Field(default=None, description="Model name (auto-selected if omitted)")
    backend: Optional[str] = Field(default=None, description="Backend type: vllm, ollama, llamacpp")
    max_iterations: Optional[int] = Field(default=None, description="Max agentic loop iterations")
    tools_enabled: bool = Field(default=True, description="Whether tools are available to the agent")

    def format_response(self, data: Any) -> str:
        if not isinstance(data, dict):
            return str(data)
        parts = []
        response = data.get("response", data.get("answer", ""))
        if response:
            parts.append(response)
        tool_calls = data.get("tool_calls", data.get("tools_used", []))
        if tool_calls:
            parts.append("\nTool calls:")
            for tc in tool_calls:
                if isinstance(tc, dict):
                    name = tc.get("name", tc.get("tool", "?"))
                    status = tc.get("status", tc.get("result", ""))
                    parts.append(f"  - {name}: {status}")
                else:
                    parts.append(f"  - {tc}")
        iterations = data.get("iterations")
        if iterations is not None:
            parts.append(f"\n({iterations} iterations)")
        return "\n".join(parts) if parts else str(data)


@register
class PaiCodingTask(ToolDef):
    """Submit a coding task to Claude Code (runs as async subprocess).
    Returns a task_id for tracking.

    `engine` must be "claude" (the default): the real Anthropic API, which
    costs API $. The "local" engine was removed when PR #316 deleted the
    gateway's Anthropic-compat endpoint that it depended on."""

    name: ClassVar[str] = "noo_coding_task"
    description: ClassVar[str] = __doc__
    method: ClassVar[HttpMethod] = HttpMethod.POST
    path: ClassVar[str] = "/api/coding/task"
    # NOT "external": this spawns a Claude Code subprocess on the
    # controller — arbitrary code execution. Internal /mcp only.
    tags: ClassVar[List[str]] = ["core", "coding"]
    risk_level: ClassVar[RiskLevel] = RiskLevel.MEDIUM
    parallelizable: ClassVar[bool] = False
    timeout_secs: ClassVar[int] = 300

    task: Optional[str] = Field(default=None, description="Description of the coding task to perform")
    command: Optional[str] = Field(default=None, description="Alternative field for task description")
    # Named task_description with alias because a field literally named
    # `description` shadows the ClassVar tool metadata in Pydantic v2 —
    # `cls.description` then raises AttributeError and every catalog
    # build (hub list_tools, get_enabled_tools, to_tool_schema) 500s.
    task_description: Optional[str] = Field(
        default=None,
        alias="description",
        description="Alias for 'task' (some models guess this name); use 'task' preferentially",
    )
    context: Optional[str] = Field(default=None, description="Additional context (file paths, constraints)")
    engine: Optional[str] = Field(
        default="claude",
        description=(
            "Which LLM runs the coding loop. Only 'claude' (Anthropic API, "
            "costs money) is valid; any other value is rejected."
        ),
    )

    def model_post_init(self, __context):
        """Accept 'command' or 'description' as alias for 'task'."""
        if not self.task and self.command:
            self.task = self.command
        if not self.task and self.task_description:
            self.task = self.task_description
        if not self.task:
            raise ValueError("Either 'task' or 'command' must be provided")

    def format_response(self, data: Any) -> str:
        if isinstance(data, dict):
            # Surface backend errors directly so the model + user see them.
            # Previously a missing task_id was masked by a "?" default and
            # missing success was not checked at all — empty {} responses
            # came back as "Coding task submitted: task_id=?" looking
            # successful when the gateway had no handler at all.
            err = data.get("error")
            if err or data.get("success") is False:
                return f"Coding task FAILED: {err or 'unknown error'}"
            task_id = data.get("task_id")
            if not task_id:
                return (
                    "Coding task FAILED: gateway returned no task_id "
                    "(backend handler likely missing or misconfigured). "
                    f"Raw response: {data}"
                )
            msg = data.get("message") or "task started"
            return f"Coding task submitted: task_id={task_id} — {msg}"
        return str(data)
