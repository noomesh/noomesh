# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for LLM tool call parsing.

Spec: The parser extracts tool calls from 4 formats (tried in order):
  1. JSON code blocks: ```json {"tool": "name", "args": {...}} ```
  2. XML style: <tool_call name="...">...</tool_call>
  3. Function call: tool_name(arg="value")
  4. Action blocks: Action: name\\nInput: ...

Deduplication: identical (name, args) pairs keep only first occurrence.
"""
import pytest

from noomesh.gateway.tool_parser import ToolCallParser


@pytest.fixture
def parser():
    return ToolCallParser()


# ── I/O Spec: format → parsed tool call ───────────────────────────
_PARSE_SPEC = [
    # id              input_text                                                                    expected_name    expected_arg_key  expected_arg_val
    ("json_tool",     '```json\n{"tool": "web_search", "args": {"query": "Python"}}\n```',         "web_search",    "query",          "Python"),
    ("json_name",     '```json\n{"name": "python_tool", "arguments": {"code": "x=1"}}\n```',      "python_tool",   "code",           "x=1"),
    ("json_func",     '```json\n{"function_call": {"name": "web_search", "arguments": {"query": "test"}}}\n```', "web_search", "query", "test"),
    ("json_direct",   '```json\n{"python_tool": {"code": "print(1)"}}\n```',                       "python_tool",   "code",           "print(1)"),
    ("xml_json",      '<tool_call name="web_search">{"query": "AI"}</tool_call>',                  "web_search",    "query",          "AI"),
    ("xml_string",    '<tool_call name="python_tool">x = 1 + 2</tool_call>',                      "python_tool",   "code",           "x = 1 + 2"),
    ("action_block",  "Action: web_search\nInput: Python tutorials\n",                             "web_search",    "query",          "Python tutorials"),
    ("func_style",    'web_search(query="test query")',                                            "web_search",    "query",          "test query"),
]


class TestParseSpec:
    @pytest.mark.parametrize(
        "input_text,expected_name,expected_key,expected_val",
        [row[1:] for row in _PARSE_SPEC],
        ids=[row[0] for row in _PARSE_SPEC],
    )
    def test_parses_to_expected(self, parser, input_text, expected_name, expected_key, expected_val):
        calls = parser.parse(input_text)
        assert len(calls) >= 1
        call = calls[0]
        assert call.name == expected_name
        assert call.arguments[expected_key] == expected_val


class TestJsonBlockParsing:
    """Test JSON code block parsing."""

    def test_parse_tool_format(self, parser):
        text = '```json\n{"tool": "web_search", "args": {"query": "Python"}}\n```'
        calls = parser.parse(text)
        assert len(calls) == 1
        assert calls[0].name == "web_search"
        assert calls[0].arguments["query"] == "Python"

    def test_parse_name_arguments_format(self, parser):
        text = '```json\n{"name": "python_tool", "arguments": {"code": "print(1)"}}\n```'
        calls = parser.parse(text)
        assert len(calls) == 1
        assert calls[0].name == "python_tool"
        assert calls[0].arguments["code"] == "print(1)"

    def test_parse_function_call_format(self, parser):
        text = '```json\n{"function_call": {"name": "web_search", "arguments": {"query": "test"}}}\n```'
        calls = parser.parse(text)
        assert len(calls) == 1
        assert calls[0].name == "web_search"

    def test_parse_direct_tool_format(self, parser):
        text = '```json\n{"python_tool": {"code": "x = 1"}}\n```'
        calls = parser.parse(text)
        assert len(calls) == 1
        assert calls[0].name == "python_tool"
        assert calls[0].arguments["code"] == "x = 1"

    def test_invalid_json_skipped(self, parser):
        text = '```json\n{invalid json}\n```'
        calls = parser.parse(text)
        assert len(calls) == 0


class TestXmlParsing:
    """Test XML-style tool call parsing."""

    def test_parse_xml_with_json_content(self, parser):
        text = '<tool_call name="web_search">{"query": "Python"}</tool_call>'
        calls = parser.parse(text)
        assert len(calls) == 1
        assert calls[0].name == "web_search"
        assert calls[0].arguments["query"] == "Python"

    def test_parse_xml_with_string_content(self, parser):
        text = '<tool_call name="python_tool">print("hello")</tool_call>'
        calls = parser.parse(text)
        assert len(calls) == 1
        assert calls[0].name == "python_tool"
        assert calls[0].arguments["code"] == 'print("hello")'


class TestActionBlockParsing:
    """Test ReAct-style action block parsing."""

    def test_parse_action_block(self, parser):
        text = "Action: web_search\nInput: Python tutorials\n"
        calls = parser.parse(text)
        assert len(calls) == 1
        assert calls[0].name == "web_search"
        assert calls[0].arguments["query"] == "Python tutorials"

    def test_action_name_normalization(self, parser):
        text = "Action: python\nInput: x = 1\n"
        calls = parser.parse(text)
        assert len(calls) == 1
        assert calls[0].name == "python_tool"


class TestDeduplication:
    """Test that duplicate tool calls are removed."""

    def test_dedup_identical_calls(self, parser):
        # Same call in both JSON block and XML
        text = (
            '```json\n{"tool": "web_search", "args": {"query": "test"}}\n```\n'
            '<tool_call name="web_search">{"query": "test"}</tool_call>'
        )
        calls = parser.parse(text)
        assert len(calls) == 1


class TestHasToolCalls:
    """Test quick tool call detection."""

    def test_has_json_tool_call(self, parser):
        assert parser.has_tool_calls('```json\n{"tool": "test"}\n```')

    def test_no_tool_calls(self, parser):
        assert not parser.has_tool_calls("Hello, how can I help you?")

    def test_has_action_indicator(self, parser):
        assert parser.has_tool_calls("Action: search\nInput: query")


class TestInferArgs:
    """Test argument inference from tool name."""

    def test_infer_python_tool(self, parser):
        args = parser._infer_args("python_tool", "x = 1 + 2")
        assert args == {"code": "x = 1 + 2"}

    def test_infer_web_search(self, parser):
        args = parser._infer_args("web_search", "Python tutorials")
        assert args == {"query": "Python tutorials"}

    def test_infer_unknown_tool(self, parser):
        args = parser._infer_args("custom_tool", "some content")
        assert args == {"input": "some content"}


class TestFuncStyleParsing:
    """Test function-call style parsing."""

    def test_parse_key_value_args(self, parser):
        text = 'web_search(query="Python tutorials")'
        calls = parser.parse(text)
        assert len(calls) == 1
        assert calls[0].name == "web_search"
        assert calls[0].arguments["query"] == "Python tutorials"
