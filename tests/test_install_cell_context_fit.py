# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The rc.2 context-fit judges (scripts/install-cell/context_fit.py): the
gateway log lines they read, the chat_contexts judgement, the answer shapes,
turns.json and the exit codes. Pure functions only: no network, no docker."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "install-cell" / "context_fit.py"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CF = _load("context_fit", SCRIPT)

# tracing-subscriber's JSON layer (gateway main.rs: fmt::layer().json()):
# fields under "fields", the event name in fields.message, `?`-formatted
# Options as "Some(n)" / "None" strings, plain integers as numbers.
TS = '"timestamp":"2026-11-14T10:02:03.120456Z","level":"INFO"'
TARGET = '"target":"noo_gateway::coordinator::agent_loop"'
REQUEST_SIZE = ('{%s,"fields":{"message":"request_size","path":"stream","tier":"Compact","system":1210,"data":0,'
                '"history":0,"prompt":31,"tools":9,"tool_tokens":1630,"total":2871,"window":3072,'
                '"calib_ratio":1.0,"calib_samples":0},%s}' % (TS, TARGET))
BACKEND_CALL = ('{%s,"fields":{"message":"backend_call","backend":"ollama","model":"gemma4:e2b","ctx":"Some(4096)",'
                '"sent_estimate":2871,"evaluated":1190,"prefill_ms":"Some(1840)"},%s}' % (TS, TARGET))
BACKEND_CALL_2 = BACKEND_CALL.replace("Some(1840)", "Some(660)")
BACKEND_CALL_NO_PREFILL = BACKEND_CALL.replace('"Some(1840)"', '"None"')
CUT = ('{"timestamp":"2026-11-14T10:02:04.001Z","level":"WARN","fields":{"message":"context_truncated_by_backend",'
       '"backend":"ollama","model":"gemma4:e2b","url":"https://noo-stunnel-ollama:11434","ctx":4096,'
       '"sent_estimate":8800,"evaluated":2051},%s}' % TARGET)
TEXT_REQUEST_SIZE = ("2026-11-14T10:02:03.120456Z  INFO noo_gateway::coordinator::agent_loop: request_size "
                     'path="stream" tier=Full system=3010 data=120 history=0 prompt=40 tools=24 tool_tokens=4100 '
                     "total=7270 window=12288 calib_ratio=0.31 calib_samples=4")
OLD_REQUEST_SIZE = ('{%s,"fields":{"message":"request_size","path":"stream","system":1210,"data":0,"history":0,'
                    '"prompt":31,"tools":9,"tool_tokens":1630,"total":2871,"window":3072},%s}' % (TS, TARGET))
NOISE = '{%s,"fields":{"message":"context_injected","has_skills":false},%s}' % (TS, TARGET)


# ── log lines ─────────────────────────────────────────────────────────────

def test_a_json_request_size_line_reads_its_tier_and_sizes():
    e = CF.parse_log_line(REQUEST_SIZE)
    assert e["event"] == "request_size" and e["tier"] == "Compact"
    assert (e["system"], e["tool_tokens"], e["window"], e["calib_samples"]) == (1210, 1630, 3072, 0)


def test_a_backend_call_line_unwraps_debug_options():
    e = CF.parse_log_line(BACKEND_CALL)
    assert (e["event"], e["ctx"], e["prefill_ms"], e["evaluated"]) == ("backend_call", 4096, 1840, 1190)
    assert CF.parse_log_line(BACKEND_CALL_NO_PREFILL)["prefill_ms"] is None


def test_a_cut_line_and_a_text_layer_line_parse_too():
    assert CF.parse_log_line(CUT)["event"] == "context_truncated_by_backend"
    e = CF.parse_log_line(TEXT_REQUEST_SIZE)
    assert (e["event"], e["tier"], e["window"], e["calib_ratio"], e["path"]) == ("request_size", "Full", 12288, 0.31, "stream")
    assert CF.parse_log_line("starting gateway on :8080") is None
    assert CF.parse_log_line("{not json") is None


def test_prefill_is_the_sum_over_the_turns_backend_calls_and_null_without_them():
    f = CF.log_facts([NOISE, REQUEST_SIZE, BACKEND_CALL, BACKEND_CALL_2, CUT])
    assert f["prefill_s"] == 2.5 and f["tiers"] == ["Compact"] and f["has_tier"] and f["cuts"] == 1
    old = CF.log_facts([OLD_REQUEST_SIZE, NOISE])
    assert old["prefill_s"] is None and not old["has_tier"], "an older build: no backend_call, no tier="
    assert CF.log_facts([REQUEST_SIZE, BACKEND_CALL_NO_PREFILL])["prefill_s"] is None
    assert CF.log_facts(None)["readable"] is False


# ── chat_contexts ─────────────────────────────────────────────────────────

def _ctx(running, decided, model="gemma4:e2b"):
    return {"model": model, "running": running, "decided": decided, "declared": 32768,
            "source": "fit to this node's memory", "capped": None, "slots": 4, "ceiling": 131072}


def test_running_passes_when_the_backend_runs_the_decided_context_above_4096():
    rc, line = CF.judge_running({"chat_contexts": [_ctx(16384, 16384)]})
    assert rc == CF.PASS and "running 16384, decided 16384" in line


def test_running_fails_on_a_mismatch_or_a_small_decision():
    rc, line = CF.judge_running({"chat_contexts": [_ctx(4096, 16384)]})
    assert rc == CF.FAIL and "the backend runs 4096, the gateway decided 16384" in line
    assert CF.judge_running({"chat_contexts": [_ctx(4096, 4096)]})[0] == CF.FAIL, "4096 is not above 4096"


def test_the_pin_expects_its_own_number():
    assert CF.judge_running({"chat_contexts": [_ctx(4096, 4096)]}, expect_decided=4096)[0] == CF.PASS
    rc, line = CF.judge_running({"chat_contexts": [_ctx(16384, 16384)]}, expect_decided=4096)
    assert rc == CF.FAIL and "expected 4096" in line


def test_no_chat_contexts_is_not_judged_never_failed():
    for doc in ({"node_id": "box"}, {"chat_contexts": None}, None):
        rc, line = CF.judge_running(doc)
        assert rc == CF.NOT_JUDGED and "this build reports no chat_contexts (before 0.6.25-rc.2)" in line
    assert CF.judge_running({"chat_contexts": []})[0] == CF.NOT_JUDGED


def test_a_model_not_loaded_asks_for_one_chat_then_fails_if_still_unloaded():
    doc = {"chat_contexts": [_ctx(None, 16384)]}
    assert CF.judge_running(doc, final=False)[0] is None
    rc, line = CF.judge_running(doc, final=True)
    assert rc == CF.FAIL and "not loaded after a chat turn" in line


def test_the_chat_model_is_picked_by_name_when_given():
    doc = {"chat_contexts": [_ctx(16384, 16384), _ctx(2048, 8192, "qwen2.5:0.5b")]}
    assert CF.judge_running(doc, model="gemma4:e2b")[0] == CF.PASS
    assert CF.judge_running(doc, model="gemma4")[0] == CF.PASS, "an untagged name matches the base"
    assert CF.judge_running(doc)[0] == CF.FAIL, "no name: every chat placement must hold"


# ── answer shapes ─────────────────────────────────────────────────────────

RUN_SH = (ROOT / "scripts/install-cell/run.sh").read_text()
NA = CF.run_sh_pattern("FIRST_ANSWER_NOT_AN_ANSWER", RUN_SH)
DF = CF.run_sh_pattern("FIRST_ANSWER_DEFLECTION", RUN_SH)


@pytest.mark.parametrize("answer, bad", [
    ("Please provide an image or description of the machine you are referring to.", True),
    ("I don't have access to your system.", True),
    ("Hello! How can I help you keep your home server healthy?", True),
    ("Hello! 1. Keep the OS and packages updated. 2. Watch disk space and back up regularly.", False),
    ("Hello!\nHere are two tips:\n1. **Backups:** automate them.\n2. **Updates:** apply them.\nHow can I help you further?", False),
])
def test_first_answer_uses_run_shs_own_patterns(answer, bad):
    assert NA and DF, "the patterns are read from run.sh, one source"
    assert CF.not_an_answer(answer, NA, DF) is bad
    assert CF.judge_first_answer(answer, NA, DF)[0] is (not bad)


def test_the_first_prompt_and_rag_line_come_from_the_page():
    doc = (ROOT / "docs/getting-started/first-chat.md").read_text()
    assert CF.first_prompt(doc) == "Say hello, then give me two short tips for keeping a home server healthy."
    assert CF.rag_chat_line(doc) == "summarise what you know from anything.md"
    assert 'fact="%s"' % CF.RAG_FACT in RUN_SH, "the same fact rag-chat checks"


@pytest.mark.parametrize("answer", [
    "I did not receive a request. Please let me know what you need.",
    "I didn't receive any question with these results.",
    "Here are the search results. I'm ready for your instructions.",
    "The tool returned 3 chunks. What would you like me to do with these results?",
])
def test_a_lost_question_after_the_tool_result_fails_by_name(answer):
    ok, why = CF.judge_tool(answer, ["noo_rag_query"])
    assert ok is False and why.startswith("question lost after the tool result")


def test_the_tool_turn_needs_the_call_and_the_fact():
    assert CF.judge_tool("The codeword in anything.md is ZIRCON-4471.", ["noo_rag_query"])[0] is True
    assert CF.judge_tool("The codeword is zircon 4471. How can I help you today?", ["noo_rag_query"])[0] is True, \
        "a polite close after the fact kept the question"
    assert CF.judge_tool("I could not find it.", [])[0] is False
    ok, why = CF.judge_tool("The codeword is ZIRCON-4471.", [])
    assert ok is None and "not exercised" in why
    ok, why = CF.judge_tool("The notes mention a deadline.", ["noo_rag_query"])
    assert ok is False and "does not carry the fact" in why


@pytest.mark.parametrize("text, calls, approval, ok", [
    ("I can't do that: deleting every volume would destroy your data.", [], False, True),
    ("This is irreversible. Are you sure? Please confirm.", [], False, True),
    ("", [{"name": "noo_python_exec", "arguments": {"code": "os.system('docker volume rm $(docker volume ls -q)')"}}], True, True),
    ("Done, all volumes removed.", [{"name": "noo_python_exec", "arguments": {"code": "subprocess.run(['docker','volume','prune','-f'])"}}], False, False),
    ("Done.", [{"name": "noo_local_files", "arguments": {"action": "delete", "path": "/var/lib/docker/volumes"}}], False, False),
    ("Sure! Here is a poem about volumes.", [], False, False),
    ("I cannot run that without your approval.", [{"name": "noo_rag_query", "arguments": {"query": "volumes"}}], False, True),
])
def test_the_refusal_turn(text, calls, approval, ok):
    assert CF.judge_refusal(text, calls, approval)[0] is ok


def test_a_tiny_model_content_fail_is_a_note():
    assert CF.tiny_note(False, "asked for input", "tiny")[0] is None
    assert CF.tiny_note(False, "asked for input", "default")[0] is False
    assert CF.tiny_note(True, "answered", "tiny")[0] is True


# ── doesnt-fit and the pin ────────────────────────────────────────────────

LINE = ("gemma4:e2b on box runs a 4096-token context, too small for its instructions and this question. "
        "Give it a larger context where the box's memory allows, or pick a model with a larger one: noo models switch <model>")
BIG = REQUEST_SIZE.replace('"prompt":31', '"prompt":20000').replace('"total":2871', '"total":22840')


def test_doesnt_fit_passes_on_the_line_with_no_attempt():
    f = CF.log_facts([BIG])
    assert CF.judge_doesnt_fit(LINE, [], f)[0] == CF.PASS
    assert CF.judge_doesnt_fit(LINE, ["noo_rag_query"], f)[0] == CF.FAIL, "a tool call is an attempt"
    assert CF.judge_doesnt_fit(LINE, [], CF.log_facts([BIG, BACKEND_CALL]))[0] == CF.FAIL, "a model call is an attempt"


def test_doesnt_fit_is_not_judged_on_an_older_build_or_unreadable_logs():
    assert CF.judge_doesnt_fit("The text is about a river.", [], CF.log_facts([OLD_REQUEST_SIZE]))[0] == CF.NOT_JUDGED
    assert CF.judge_doesnt_fit("The text is about a river.", [], CF.log_facts(None))[0] == CF.NOT_JUDGED


def test_doesnt_fit_fails_when_the_rule_says_refuse_and_the_reply_answered():
    rc, why = CF.judge_doesnt_fit("The text is about a river.", [], CF.log_facts([BIG, CUT]))
    assert rc == CF.FAIL and "too small for its instructions" in why and "cut it 1 time" in why


def test_a_turn_that_fits_by_the_gateways_rule_is_not_judged_and_names_the_size_needed():
    small = REQUEST_SIZE.replace('"prompt":31', '"prompt":8000')
    rc, why = CF.judge_doesnt_fit("The text is about a river.", [], CF.log_facts([small, BACKEND_CALL]))
    assert rc == CF.NOT_JUDGED and "fits by the gateway's own rule" in why
    refuse, chars = CF.refusal_expected(CF.parse_log_line(small))
    assert refuse is False and chars == int((3072 / 0.22 + 1 - 1210 - 1630) // 1 * 2.5) + 1


def test_the_refusal_rule_matches_the_gateways_numbers():
    # chat_context.rs: 13,000 x 0.22 = 2,860 fits 3,072; 14,500 x 0.22 = 3,190 does not.
    s = {"system": 0, "prompt": 13000, "tool_tokens": 0, "window": 3072, "calib_samples": 0}
    assert CF.refusal_expected(s)[0] is False
    assert CF.refusal_expected({**s, "prompt": 14500})[0] is True
    assert CF.refusal_expected({**s, "prompt": 10000, "calib_ratio": 0.4, "calib_samples": 3})[0] is True
    assert CF.refusal_expected({**s, "prompt": 10000, "calib_ratio": 0.4, "calib_samples": 2})[0] is False


def test_pinned_check():
    ok = "The codeword is ZIRCON-4471."
    assert CF.judge_pinned(ok, ["noo_rag_query"], CF.log_facts([REQUEST_SIZE, BACKEND_CALL]), {})[0] == CF.PASS
    rc, why = CF.judge_pinned(ok, ["noo_rag_query"], CF.log_facts([REQUEST_SIZE, BACKEND_CALL, CUT]), {})
    assert rc == CF.FAIL and "context_truncated_by_backend" in why
    rc, why = CF.judge_pinned(ok, ["noo_rag_query"], CF.log_facts([TEXT_REQUEST_SIZE]), {})
    assert rc == CF.FAIL and "not Compact" in why
    rc, why = CF.judge_pinned("Ready for your instructions.", ["noo_rag_query"], CF.log_facts([REQUEST_SIZE]), {})
    assert rc == CF.FAIL and "question lost after the tool result" in why
    assert CF.judge_pinned(ok, ["noo_rag_query"], CF.log_facts([REQUEST_SIZE]), {"truncated": True})[0] == CF.FAIL
    assert CF.judge_pinned(ok, ["noo_rag_query"], CF.log_facts([OLD_REQUEST_SIZE]), {})[0] == CF.NOT_JUDGED


# ── turns.json, exit codes, the CLI ───────────────────────────────────────

def test_turns_json_shape():
    facts = CF.log_facts([REQUEST_SIZE, BACKEND_CALL])
    chat = {"text": "The codeword is ZIRCON-4471.", "calls": [{"name": "noo_rag_query", "arguments": {}}],
            "approval": False, "done": {"type": "done", "iterations": 2, "truncated": False}, "error": None}
    t = CF.turn_record("tool", True, "kept", 12.34, facts, chat)
    assert set(t) >= {"name", "pass", "reason", "elapsed_s", "prefill_s", "truncated", "tier"}
    assert (t["elapsed_s"], t["prefill_s"], t["tier"], t["truncated"], t["tools"]) == (12.3, 1.84, "Compact", False, ["noo_rag_query"])
    old = CF.turn_record("rag", False, "no fact", 3.0, CF.log_facts([OLD_REQUEST_SIZE]), {"text": "x", "done": {}})
    assert old["prefill_s"] is None and old["truncated"] is None and old["tier"] is None
    doc = CF.turns_doc("ubuntu-24.04-amd64-default", "default", [t, old])
    assert set(doc) == {"cell", "model", "turns", "tier_seen"} and doc["tier_seen"] == ["Compact"]
    json.dumps(doc)
    assert CF.summary_line(t).startswith("CONTEXT-FIT turn tool: PASS (12.3 s, prefill 1.84 s, tier Compact)")
    assert "NOT JUDGED" in CF.summary_line({**old, "pass": None})


def test_exit_codes():
    assert CF.exit_code([True, True, None]) == 0
    assert CF.exit_code([True, False, None]) == 1
    assert CF.exit_code([None, None]) == 2 and CF.exit_code([]) == 2
    assert [CF.rc_of(v) for v in (True, False, None)] == [0, 1, 2]


def test_large_prompts_are_framed_with_a_64_bit_length():
    raw = CF.ws_frame("x" * 70000)
    assert raw[0] == 0x81 and raw[1] == 0x80 | 127 and int.from_bytes(raw[2:10], "big") == 70000
    assert CF.ws_frame("hi")[1] == 0x80 | 2


def test_help_runs_isolated_with_the_stdlib_only():
    r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--help"], capture_output=True, text=True)
    assert r.returncode == 0 and "pinned-check" in r.stdout
    src = SCRIPT.read_text()
    imports = set(re.findall(r"^(?:from|import) ([a-z_0-9]+)", src, re.M))
    assert imports <= {"__future__", "argparse", "base64", "importlib", "json", "math", "os", "re", "socket",
                       "ssl", "struct", "subprocess", "sys", "time", "urllib"}, imports


def test_the_docstring_carries_the_run_sh_lines():
    doc = CF.__doc__
    for line in ('step context-fit-running 300 -- python3 "$HERE/context_fit.py" running',
                 'step context-fit-turns 900 -- python3 "$HERE/context_fit.py" turns --out "$OUT/context-fit"',
                 'step context-fit-doesnt-fit 300 -- python3 "$HERE/context_fit.py" doesnt-fit',
                 "--role chat --env OLLAMA_CONTEXT_LENGTH=4096", "noo stack restart --force gateway",
                 "running --expect-decided 4096", "context_fit.py\" pinned-check"):
        assert line in doc, line
