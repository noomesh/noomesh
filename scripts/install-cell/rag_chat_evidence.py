#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""Evidence for a missed rag `noo chat` turn: which of "the model ignored a
good tool result", "the tool result was empty or an error" and "the context
never carried the document" it was.

run.sh's probe-rag-chat step runs the JUDGED `noo chat --message ...` exactly
as before, then (on a miss, and always on the default-model cell) calls

  rag_chat_evidence.py --since <epoch t0> [--replay PROMPT]

which prints, for run.sh to pass through the cell's redactor into
logs/rag-chat-evidence.log:

  - the gateway's lines for the window (docker logs --since t0): the judged
    turn's conversation id is read from the first coordinator_chat_stream_start
    line in the window (the cell's own turn; `noo chat` mints cli-<ts>-<pid>
    and the judged call stays a plain, non-json call), then every line
    carrying that id plus the lines naming context_injected, request_size,
    tool_call_, context_window_truncated, stall and coordinator_chat_stream.
    Each is printed as its JSON fields with prompt/reply/output-shaped fields
    dropped (agent_evidence.scrub); a non-JSON line is reduced to its event word;
  - with --replay: the same question asked once more over POST
    /api/inference/chat with a conversation id of our own, the raw SSE kept
    (tool_result events carry a 500-char output preview). A replay, not the
    judged turn: it shows what the route does with the question now.

A probe: it always exits 0.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # python3 -I does not add the script's directory

import agent_evidence as ae  # noqa: E402

# kb_tool_deferred carries no conversation_id (agent_loop.rs), so only its
# name keeps it: without it every cell's evidence dropped it and read 0.
EVENTS = re.compile(r"context_injected|request_size|tool_call_|context_window_truncated|stall"
                    r"|coordinator_chat_stream|kb_tool_deferred", re.IGNORECASE)
START = re.compile(r"coordinator_chat_stream_start")
MAX_LINES = 120
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# name=value (value a quoted string or one token) for the names agent_evidence drops.
BODY_FIELD = re.compile(r"\b(" + ae.DROP.pattern.strip("^$()")+ r")=(\"(?:[^\"\\]|\\.)*\"|\S+)", re.IGNORECASE)


def conversation_id(lines: list[str]) -> str:
    """The conversation id of the first coordinator_chat_stream_start line."""
    for raw in lines:
        if not START.search(raw):
            continue
        try:
            d = json.loads(raw.strip())
        except ValueError:
            m = re.search(r"conversation_id[=:\"' ]+([A-Za-z0-9_.:-]+)", raw)
            if m:
                return m.group(1)
            continue
        f = d.get("fields") if isinstance(d, dict) else None
        cid = (f or d).get("conversation_id") if isinstance(f or d, dict) else None
        if cid:
            return str(cid)
    return ""


def view(raw: str, cid: str) -> str | None:
    raw = raw.strip()
    if not raw or not (EVENTS.search(raw) or (cid and cid in raw)):
        return None
    try:
        d = json.loads(raw)
    except ValueError:
        # tracing's text format: keep the line (its event and key=value field
        # list: has_rag, dropped, chars ...), minus colour codes and any
        # prompt/reply/output-shaped field's value, cut to 400 chars.
        plain = ANSI.sub("", raw)
        plain = BODY_FIELD.sub(lambda m: m.group(1) + "=[dropped]", plain)
        return plain[:400]
    if not isinstance(d, dict):
        return None
    return json.dumps(ae.scrub(d), ensure_ascii=False)[:700]


def gateway_lines(since: float) -> tuple[str, list[str]]:
    name = os.environ.get("NOO_CONTAINER_PREFIX", "noo") + "-gateway"
    text, why = ae.docker("logs", "--since", f"{since:.0f}", name, timeout=60)
    if text is None:
        return "", [f"gateway log not readable: {why}"]
    raw = text.splitlines()
    cid = conversation_id(raw)
    kept = [v for v in (view(l, cid) for l in raw) if v]
    if len(kept) > MAX_LINES:
        kept = kept[:30] + [f"... {len(kept) - MAX_LINES} lines between ..."] + kept[-(MAX_LINES - 30):]
    return cid, kept or ["no matching gateway line in the window"]


def chat_contexts() -> list[str]:
    """`noo --json cluster show <this node>`: its chat_contexts array only."""
    import socket
    import subprocess
    try:
        p = subprocess.run(["timeout", "60", "noo", "--json", "cluster", "show", socket.gethostname()],
                           capture_output=True, text=True, timeout=75)
        doc = json.loads(p.stdout)
        return [json.dumps(doc.get("chat_contexts"), ensure_ascii=False)[:3000]]
    except Exception as e:
        return [f"chat_contexts not readable: {type(e).__name__}: {e}"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", type=float, required=True)
    ap.add_argument("--replay", default="")
    a = ap.parse_args()
    cid, lines = gateway_lines(a.since)
    print(f"RAG-CHAT EVIDENCE: judged turn's conversation_id={cid or 'not found in the gateway log'}")
    print("RAG-CHAT EVIDENCE: gateway lines for the window (context_injected, request_size, tool_call_*, "
          "context_window_truncated, stall, coordinator_chat_stream*, and every line with that id; "
          "prompt/reply/output fields dropped)")
    for l in lines:
        print("  gw: " + l)
    print("RAG-CHAT EVIDENCE: noo --json cluster show: chat_contexts")
    for l in chat_contexts():
        print("  " + l)
    if a.replay:
        import time
        import ws_chat
        since, rid = time.time() - 1, f"cell-evidence-{os.getpid()}"
        print(f"RAG-CHAT EVIDENCE: replay over POST /api/inference/chat, conversation_id={rid}: raw SSE")
        for l in ws_chat.chat_sse(a.replay, rid):
            print("  sse: " + l)
        _, gw = gateway_lines(since)
        print("RAG-CHAT EVIDENCE: gateway lines for the replay")
        for l in gw:
            print("  gw: " + l)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
