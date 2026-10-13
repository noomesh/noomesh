# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Parse tool calls from LLM responses.

Supports multiple formats that different models may use.
"""

from __future__ import annotations

from .. import json_fast as json
import re
from dataclasses import dataclass
from typing import Any, Optional

import structlog

logger = structlog.get_logger()


@dataclass
class ToolCall:
    """Parsed tool call from model output."""
    name: str
    arguments: dict[str, Any]
    raw_text: str  # Original text that was parsed

    def __str__(self) -> str:
        return f"ToolCall({self.name}, {self.arguments})"


class ToolCallParser:
    """Parse tool calls from various LLM output formats."""

    # Pattern for JSON code blocks
    JSON_BLOCK_PATTERN = re.compile(
        r'```(?:json)?\s*\n?({[\s\S]*?})\s*\n?```',
        re.IGNORECASE
    )

    # Pattern for function-call style: tool_name(arg1="val1", arg2="val2")
    FUNC_CALL_PATTERN = re.compile(
        r'(\w+_tool|\w+_search|local_files)\s*\(\s*([^)]*)\s*\)',
        re.IGNORECASE
    )

    # Pattern for XML-style: <tool_call name="...">...</tool_call>
    XML_PATTERN = re.compile(
        r'<tool_call\s+name=["\'](\w+)["\']>\s*([\s\S]*?)\s*</tool_call>',
        re.IGNORECASE
    )

    # Pattern for action blocks used by some models
    ACTION_PATTERN = re.compile(
        r'(?:Action|Tool|Use):\s*(\w+)\s*\n(?:Input|Args|Arguments):\s*(.+?)(?=\n(?:Action|Tool|Use|Observation|$))',
        re.IGNORECASE | re.DOTALL
    )

    def parse(self, text: str) -> list[ToolCall]:
        """Parse all tool calls from text."""
        calls = []

        # Try bare JSON object first (model outputs raw JSON without code block)
        calls.extend(self._parse_bare_json(text))

        # Try JSON blocks (most structured)
        calls.extend(self._parse_json_blocks(text))

        # Try XML-style
        calls.extend(self._parse_xml_style(text))

        # Try function-call style
        calls.extend(self._parse_func_style(text))

        # Try action blocks
        calls.extend(self._parse_action_blocks(text))

        # Deduplicate by name+args (keep first occurrence)
        seen = set()
        unique_calls = []
        for call in calls:
            key = (call.name, json.dumps(call.arguments, sort_keys=True))
            if key not in seen:
                seen.add(key)
                unique_calls.append(call)

        if unique_calls:
            logger.info("tool_calls_parsed", count=len(unique_calls),
                       tools=[c.name for c in unique_calls])

        return unique_calls

    def _parse_bare_json(self, text: str) -> list[ToolCall]:
        """Parse bare JSON objects that look like tool calls (no code block markers).

        Handles models that output tool calls as raw JSON:
          {"name": "noo_cluster_status", "arguments": {}}
        """
        stripped = text.strip()
        if not stripped.startswith("{"):
            return []

        try:
            data = json.loads(stripped)
            tool_call = self._extract_tool_from_json(data)
            if tool_call:
                tool_call.raw_text = stripped
                return [tool_call]
        except json.JSONDecodeError:
            pass

        return []

    def _parse_json_blocks(self, text: str) -> list[ToolCall]:
        """Parse JSON code blocks for tool calls."""
        calls = []

        for match in self.JSON_BLOCK_PATTERN.finditer(text):
            json_str = match.group(1)
            try:
                data = json.loads(json_str)

                # Handle various JSON formats
                tool_call = self._extract_tool_from_json(data)
                if tool_call:
                    tool_call.raw_text = match.group(0)
                    calls.append(tool_call)

            except json.JSONDecodeError:
                continue

        return calls

    def _extract_tool_from_json(self, data: dict) -> Optional[ToolCall]:
        """Extract tool call from parsed JSON."""
        # Format 1: {"tool": "name", "args": {...}}
        if "tool" in data:
            return ToolCall(
                name=data["tool"],
                arguments=data.get("args", data.get("arguments", data.get("parameters", {}))),
                raw_text=""
            )

        # Format 2: {"name": "tool_name", "arguments": {...}}
        if "name" in data and ("arguments" in data or "parameters" in data):
            return ToolCall(
                name=data["name"],
                arguments=data.get("arguments", data.get("parameters", {})),
                raw_text=""
            )

        # Format 3: {"function_call": {"name": ..., "arguments": ...}}
        if "function_call" in data:
            fc = data["function_call"]
            args = fc.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {"input": args}
            return ToolCall(
                name=fc.get("name", ""),
                arguments=args,
                raw_text=""
            )

        # Format 4: {"tool_call": {...}}
        if "tool_call" in data:
            return self._extract_tool_from_json(data["tool_call"])

        # Format 5: Direct tool format {"python_tool": {"code": "..."}}
        for tool_name in ["python_tool", "web_search", "local_files"]:
            if tool_name in data:
                args = data[tool_name]
                if isinstance(args, str):
                    # Handle {"python_tool": "code here"}
                    if tool_name == "python_tool":
                        args = {"code": args}
                    elif tool_name == "web_search":
                        args = {"query": args}
                    else:
                        args = {"input": args}
                return ToolCall(name=tool_name, arguments=args, raw_text="")

        return None

    def _parse_xml_style(self, text: str) -> list[ToolCall]:
        """Parse XML-style tool calls."""
        calls = []

        for match in self.XML_PATTERN.finditer(text):
            name = match.group(1)
            content = match.group(2).strip()

            # Try to parse content as JSON
            try:
                args = json.loads(content)
            except json.JSONDecodeError:
                # Treat as simple string input
                args = self._infer_args(name, content)

            calls.append(ToolCall(
                name=name,
                arguments=args,
                raw_text=match.group(0)
            ))

        return calls

    def _parse_func_style(self, text: str) -> list[ToolCall]:
        """Parse function-call style: tool_name(arg="value")."""
        calls = []

        for match in self.FUNC_CALL_PATTERN.finditer(text):
            name = match.group(1).lower()
            args_str = match.group(2).strip()

            if not args_str:
                continue

            # Parse arguments
            args = self._parse_func_args(args_str)
            if args:
                calls.append(ToolCall(
                    name=name,
                    arguments=args,
                    raw_text=match.group(0)
                ))

        return calls

    def _parse_func_args(self, args_str: str) -> dict:
        """Parse function-style arguments."""
        args = {}

        # Try JSON first
        try:
            return json.loads(args_str)
        except Exception:
            pass

        # Try key=value pairs
        # Match: key="value" or key='value' or key=value
        pattern = re.compile(r'(\w+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|(\S+))')
        for match in pattern.finditer(args_str):
            key = match.group(1)
            value = match.group(2) or match.group(3) or match.group(4)
            args[key] = value

        # If no matches, treat whole thing as single argument
        if not args and args_str:
            # Infer argument name based on common patterns
            if "code" in args_str.lower() or "def " in args_str or "import " in args_str:
                args = {"code": args_str}
            else:
                args = {"query": args_str}

        return args

    def _parse_action_blocks(self, text: str) -> list[ToolCall]:
        """Parse ReAct-style action blocks."""
        calls = []

        for match in self.ACTION_PATTERN.finditer(text):
            name = match.group(1).lower()
            input_text = match.group(2).strip()

            # Normalize common names
            name_map = {
                "python": "python_tool",
                "search": "web_search",
                "websearch": "web_search",
                "files": "local_files",
                "file": "local_files",
            }
            name = name_map.get(name, name)

            args = self._infer_args(name, input_text)

            calls.append(ToolCall(
                name=name,
                arguments=args,
                raw_text=match.group(0)
            ))

        return calls

    def _infer_args(self, tool_name: str, content: str) -> dict:
        """Infer argument structure based on tool name."""
        if tool_name == "python_tool":
            return {"code": content}
        elif tool_name == "web_search":
            return {"query": content}
        elif tool_name == "local_files":
            # Try to parse as JSON or infer action
            try:
                return json.loads(content)
            except Exception:
                if content.startswith("/") or content.startswith("."):
                    return {"action": "read", "path": content}
                return {"action": "read", "path": content}
        else:
            return {"input": content}

    def has_tool_calls(self, text: str) -> bool:
        """Quick check if text likely contains tool calls."""
        indicators = [
            "```json",
            '"tool"',
            '"name"',
            "tool_call",
            "function_call",
            "python_tool",
            "web_search",
            "local_files",
            "Action:",
            "Tool:",
            "<tool_call",
        ]
        text_lower = text.lower()
        return any(ind.lower() in text_lower for ind in indicators)


# Global parser instance
_parser: Optional[ToolCallParser] = None


def get_tool_parser() -> ToolCallParser:
    """Get or create the global tool parser."""
    global _parser
    if _parser is None:
        _parser = ToolCallParser()
    return _parser
