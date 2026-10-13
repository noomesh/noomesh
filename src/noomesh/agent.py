# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

from __future__ import annotations

import asyncio
from . import json_fast as json
import structlog
import threading
import time as _time
from dataclasses import dataclass
from typing import Any, Dict, Generator, List, Optional, Tuple

import httpx

from .llm.base import LLMClient
from .llm.ollama import OllamaError
from .memory import ContextLoader, MemoryManager, SessionMemory
from .tools import ToolRegistry, ToolSpec
from .events import publish_agent_step, publish_llm_call, publish_tool_execution
from .resilience import retry_llm_call, retry_tool_execution

_logger = structlog.get_logger(__name__)


@retry_llm_call(max_attempts=3, min_wait=2.0, max_wait=10.0)
def _resilient_llm_chat(llm, messages, tools):
    """LLM chat call wrapped with retry for transient failures."""
    return llm.chat(messages, tools=tools)


@retry_tool_execution(max_attempts=2, min_wait=1.0, max_wait=5.0)
def _resilient_tool_call(handler, args):
    """Tool handler call wrapped with retry for transient failures."""
    return handler(args)


# Background event loop for CLI mode (no running asyncio loop)
_cli_event_loop: Optional[asyncio.AbstractEventLoop] = None
_cli_event_loop_lock = threading.Lock()


def _ensure_cli_event_loop() -> asyncio.AbstractEventLoop:
    """Lazily start a daemon thread with its own event loop for CLI event publishing."""
    global _cli_event_loop
    if _cli_event_loop is not None and _cli_event_loop.is_running():
        return _cli_event_loop
    with _cli_event_loop_lock:
        if _cli_event_loop is not None and _cli_event_loop.is_running():
            return _cli_event_loop
        _cli_event_loop = asyncio.new_event_loop()
        t = threading.Thread(
            target=_cli_event_loop.run_forever,
            daemon=True,
            name="noo-events",
        )
        t.start()
        # Start the event bus on the background loop
        from .events import get_event_bus, log_event_handler
        bus = get_event_bus()
        bus.subscribe("*", log_event_handler)
        future = asyncio.run_coroutine_threadsafe(bus.start(), _cli_event_loop)
        try:
            future.result(timeout=2)
        except Exception:
            _logger.debug("Failed to start event bus on background loop")
        return _cli_event_loop


def _fire_and_forget(coro):
    """Schedule an async coroutine, using a background loop in CLI mode."""
    try:
        loop = asyncio.get_running_loop()
        task = loop.create_task(coro)
        task.add_done_callback(_handle_task_exception)
    except RuntimeError:
        # No running event loop — use background daemon loop
        try:
            loop = _ensure_cli_event_loop()
            asyncio.run_coroutine_threadsafe(coro, loop)
        except Exception:
            pass


def _handle_task_exception(task: asyncio.Task):
    """Log exceptions from fire-and-forget tasks instead of silencing them."""
    if task.cancelled():
        return
    exc = task.exception()
    if exc:
        _logger.debug("Background event task failed: %s", exc)


def _trigger_plugin_hook(hook_name: str, *args, **kwargs) -> None:
    """Trigger a plugin hook if a plugin manager is available."""
    try:
        from .factory import get_plugin_manager
        pm = get_plugin_manager()
        if pm:
            pm.trigger_hook(hook_name, *args, **kwargs)
    except Exception:
        pass  # Plugin hooks must never break the agent


TOOL_INSTRUCTIONS = (
    "If you need a tool, call it. Otherwise respond normally. "
    "When using tools, rely on their output and keep responses concise."
)


def _system_message(base_prompt: str, context: str) -> str:
    chunks = [base_prompt.strip(), TOOL_INSTRUCTIONS]
    if context:
        chunks.append("Context files:\n" + context)
    return "\n\n".join(chunks).strip()


def _parse_tool_calls(message: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any], str]]:
    """Parse tool calls from LLM response.

    Returns list of ``(name, args, tool_call_id)`` tuples.
    The ``tool_call_id`` is required by vLLM/OpenAI API for matching
    tool results back to their originating calls.
    """
    calls = []
    tool_calls = message.get("tool_calls") or []
    for call in tool_calls:
        fn = call.get("function") or {}
        name = fn.get("name")
        raw_args = fn.get("arguments")
        tc_id = call.get("id", "")
        if not tc_id:
            import uuid as _uuid
            tc_id = f"call_{_uuid.uuid4().hex[:8]}"
            call["id"] = tc_id  # backfill so assistant message also has it
        if not name:
            continue
        if isinstance(raw_args, str):
            try:
                args = json.loads(raw_args)
            except json.JSONDecodeError:
                args = {"raw": raw_args}
        elif isinstance(raw_args, dict):
            args = raw_args
        else:
            args = {}
        calls.append((name, args, tc_id))
    return calls


def _parse_json_tool_call(content: str) -> Optional[Tuple[str, Dict[str, Any], str]]:
    """Parse a JSON tool call from content (fallback for models that don't use native tool_calls)."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    if "tool" not in data:
        return None
    name = data.get("tool")
    args = data.get("arguments") or {}
    return name, args, ""  # no tool_call_id for JSON-parsed calls


class Agent:
    def __init__(
        self,
        llm: LLMClient,
        tools: ToolRegistry,
        system_prompt: str,
        context_loader: Optional[ContextLoader] = None,
        memory_manager: Optional[MemoryManager] = None,
        tool_selection_mode: str = "smart",
        tool_selection_max: int = 8,
        tool_selection_min_score: float = 0.1,
        tool_selection_scoring: str = "jaccard",
        tool_selection_always: Optional[List[str]] = None,
        tool_mode: str = "auto",
        max_tool_loops: int = 3,
    ) -> None:
        self.llm = llm
        self.tools = tools
        self.system_prompt = system_prompt
        self.context_loader = context_loader
        self.memory_manager = memory_manager
        self.tool_selection_mode = tool_selection_mode
        self.tool_selection_max = tool_selection_max
        self.tool_selection_min_score = tool_selection_min_score
        self.tool_selection_scoring = tool_selection_scoring
        self.tool_selection_always = tool_selection_always or []
        self.tool_mode = tool_mode
        self.max_tool_loops = max_tool_loops

    def _base_messages(self) -> List[Dict[str, Any]]:
        context = self.context_loader.load() if self.context_loader else ""
        system = _system_message(self.system_prompt, context)
        return [{"role": "system", "content": system}]

    def run(self, prompt: str) -> str:
        session = self.new_session()
        return self.step(session, prompt)

    def new_session(self) -> "SessionState":
        _trigger_plugin_hook("on_agent_start")
        return SessionState(
            messages=self._base_messages(),
            memory=self.memory_manager.new_session() if self.memory_manager else None,
        )

    def step(
        self,
        session: "SessionState",
        prompt: str,
        pinned_tools: Optional[List[str]] = None,
    ) -> str:
        memory_context = (
            self.memory_manager.retrieve(prompt, session.memory)
            if self.memory_manager
            else ""
        )
        memory_idx: Optional[int] = None
        if memory_context:
            session.messages.append({"role": "system", "content": memory_context})
            memory_idx = len(session.messages) - 1

        session.messages.append({"role": "user", "content": prompt})
        tools_payload = self._select_tools(prompt, pinned_tools)

        content_parts: List[str] = []
        for event in self._chat_loop(session.messages, tools_payload):
            if event["type"] == "token":
                content_parts.append(event["content"])
            elif event["type"] == "error":
                content_parts.append(event["message"])
        reply = "".join(content_parts)

        if memory_idx is not None:
            del session.messages[memory_idx]

        if self.memory_manager:
            self.memory_manager.record(session.memory, "user", prompt)
            self.memory_manager.record(session.memory, "assistant", reply)

        return reply

    def _chat_loop(
        self,
        messages: List[Dict[str, Any]],
        tools_payload: Optional[List[Dict[str, Any]]],
    ) -> Generator[Dict[str, Any], None, None]:
        tool_loops = 0
        while True:
            step_t0 = _time.perf_counter()
            _trigger_plugin_hook("on_llm_call", messages=messages, tools=tools_payload)
            llm_t0 = _time.perf_counter()
            response = _resilient_llm_chat(self.llm, messages, tools_payload)
            llm_duration = (_time.perf_counter() - llm_t0) * 1000
            message = response.get("message", {})
            content = message.get("content", "").strip()

            # Publish LLM call event
            _fire_and_forget(publish_llm_call(
                model=getattr(self.llm, "model", "unknown"),
                messages_count=len(messages),
                tools_count=len(tools_payload) if tools_payload else 0,
                duration_ms=llm_duration,
                success=True,
            ))

            tool_calls = _parse_tool_calls(message)
            if not tool_calls:
                json_call = _parse_json_tool_call(content)
                if json_call:
                    tool_calls = [json_call]

            assistant_message = {"role": "assistant", "content": content}
            if "tool_calls" in message:
                # Ensure every tool_call has an id — some models (Qwen via
                # vLLM) omit it, but the OpenAI API requires it when the
                # message is sent back in subsequent turns.
                fixed_calls = []
                for tc in message["tool_calls"]:
                    patched = {**tc}
                    if not patched.get("id"):
                        import uuid as _uuid
                        patched["id"] = f"call_{_uuid.uuid4().hex[:8]}"
                    if not patched.get("type"):
                        patched["type"] = "function"
                    fixed_calls.append(patched)
                assistant_message["tool_calls"] = fixed_calls
            messages.append(assistant_message)

            if not tool_calls or self.tool_mode != "auto":
                # Publish step event
                _fire_and_forget(publish_agent_step(
                    step_number=tool_loops + 1,
                    tools_called=[],
                    duration_ms=(_time.perf_counter() - step_t0) * 1000,
                ))
                yield {"type": "token", "content": content}
                return

            tool_loops += 1
            if tool_loops > self.max_tool_loops:
                yield {"type": "error", "message": "Error: tool loop limit reached."}
                return

            tools_called_names: List[str] = []
            for name, args, tc_id in tool_calls:
                _trigger_plugin_hook("on_tool_execute", tool_name=name, args=args)
                yield {"type": "tool_start", "name": name, "args": args}
                tool_t0 = _time.perf_counter()
                try:
                    tool = self.tools.get(name)
                except KeyError:
                    result = f"Error: unknown tool '{name}'."
                    _fire_and_forget(publish_tool_execution(
                        tool_name=name, args=args,
                        duration_ms=(_time.perf_counter() - tool_t0) * 1000,
                        success=False, error=result,
                    ))
                    yield {"type": "tool_error", "name": name, "error": result}
                else:
                    try:
                        result = _resilient_tool_call(tool.handler, args)
                    except Exception as exc:
                        result = f"Error: {exc}"
                        _fire_and_forget(publish_tool_execution(
                            tool_name=name, args=args,
                            duration_ms=(_time.perf_counter() - tool_t0) * 1000,
                            success=False, error=result,
                        ))
                        yield {"type": "tool_error", "name": name, "error": result}
                    else:
                        _fire_and_forget(publish_tool_execution(
                            tool_name=name, args=args,
                            duration_ms=(_time.perf_counter() - tool_t0) * 1000,
                            success=True,
                        ))
                        yield {"type": "tool_complete", "name": name}
                tools_called_names.append(name)
                tool_msg: Dict[str, Any] = {"role": "tool", "name": name, "content": result}
                if tc_id:
                    tool_msg["tool_call_id"] = tc_id
                messages.append(tool_msg)

            # Publish step event
            _fire_and_forget(publish_agent_step(
                step_number=tool_loops,
                tools_called=tools_called_names,
                duration_ms=(_time.perf_counter() - step_t0) * 1000,
            ))

    def chat(self) -> None:
        session = self.new_session()
        while True:
            try:
                user = input("you> ").strip()
            except (KeyboardInterrupt, EOFError):
                break
            if not user:
                continue
            if user.lower() in {"/exit", "/quit", "quit", "exit"}:
                break
            try:
                reply = self.step(session, user)
            except OllamaError as exc:
                print(f"[error] {exc}")
                continue
            except httpx.HTTPError as exc:
                print(f"[error] LLM request failed: {exc}")
                continue
            print(f"noo> {reply}")
        _trigger_plugin_hook("on_agent_stop")

    def stream(
        self,
        session: "SessionState",
        prompt: str,
        pinned_tools: Optional[List[str]] = None,
    ) -> Generator[Dict[str, Any], None, None]:
        memory_context = (
            self.memory_manager.retrieve(prompt, session.memory)
            if self.memory_manager
            else ""
        )
        memory_idx: Optional[int] = None
        if memory_context:
            session.messages.append({"role": "system", "content": memory_context})
            memory_idx = len(session.messages) - 1

        session.messages.append({"role": "user", "content": prompt})
        tools_payload = self._select_tools(prompt, pinned_tools)

        if tools_payload:
            content_parts: List[str] = []
            for event in self._chat_loop(session.messages, tools_payload):
                if event["type"] == "token":
                    content_parts.append(event["content"])
                yield event
            reply = "".join(content_parts)
            if memory_idx is not None:
                del session.messages[memory_idx]
            if self.memory_manager:
                self.memory_manager.record(session.memory, "user", prompt)
                self.memory_manager.record(session.memory, "assistant", reply)
            return

        full: List[str] = []
        for chunk in self.llm.chat_stream(session.messages, tools=None):
            message = chunk.get("message", {})
            delta = message.get("content", "")
            if not delta:
                continue
            full.append(delta)
            yield {"type": "token", "content": delta}

        reply = "".join(full).strip()
        session.messages.append({"role": "assistant", "content": reply})

        if memory_idx is not None:
            del session.messages[memory_idx]

        if self.memory_manager:
            self.memory_manager.record(session.memory, "user", prompt)
            self.memory_manager.record(session.memory, "assistant", reply)

    def _select_tools(
        self, prompt: str, pinned_tools: Optional[List[str]] = None
    ) -> Optional[List[Dict[str, Any]]]:
        selected = self.select_tool_specs(prompt, pinned_tools)
        if not selected:
            return None
        return [tool.to_ollama() for tool in selected]

    def select_tool_specs(
        self, prompt: str, pinned_tools: Optional[List[str]] = None
    ) -> List[ToolSpec]:
        if self.tool_mode != "auto":
            return []
        if self.tool_selection_mode == "all":
            return list(self.tools.list())
        if self.tool_selection_mode != "smart":
            return []

        always_include = list(self.tool_selection_always)
        if pinned_tools:
            always_include.extend(pinned_tools)

        selected = self.tools.select_for_prompt(
            prompt=prompt,
            max_tools=self.tool_selection_max,
            min_score=self.tool_selection_min_score,
            scoring=self.tool_selection_scoring,
            always_include=always_include,
        )
        return selected


@dataclass
class SessionState:
    messages: List[Dict[str, Any]]
    memory: Optional[SessionMemory]
