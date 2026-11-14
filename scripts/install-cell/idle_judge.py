#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""Judge the idle series: with nobody chatting, the chat model must not be
loaded at t0 + 40 min.

Until noomesh #1191 the gateway's node_dispatch_health probe sent ollama an
empty-model chat every ~300 s, which the agent filled with the held chat model
and ollama treated as a load: the model never unloaded (install matrix run
43611137767: gemma4:e2b still loaded at +40 min, expiry refreshed). #1191
probes ollama through the agent's new GET /backend-alive/<backend> route. So
the judgement applies only to a build whose node agent carries that route
(the route string is in the binary); an older build is reported UNJUDGED with
that reason, never PASS.

  idle_judge.py --t40 memory-idle-t40.json --agent-bin /usr/local/bin/noo-node-agent

Prints one `IDLE JUDGED: …` line. Exit 0 for PASS or unjudged, 1 for FAIL.
An unreadable sample is a FAIL (nothing proves the model unloaded).
Embedders (harrier, and EMBEDDING_MODEL / PAGEINDEX_EMBEDDING_MODEL when set)
are not chat models: their own keep_alive is the gateway's 30 min.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

ROUTE = b"/backend-alive/"
EMBEDDERS = ("harrier",)


def agent_has_route(path: str) -> tuple[bool | None, str]:
    try:
        with open(path, "rb") as f:
            return ROUTE in f.read(), path
    except OSError as e:
        return None, f"{path}: {e.strerror or e}"


def embedder_names() -> tuple[str, ...]:
    extra = [os.environ.get(k, "").strip() for k in ("EMBEDDING_MODEL", "PAGEINDEX_EMBEDDING_MODEL")]
    return EMBEDDERS + tuple(e for e in extra if e)


def is_embedder(model: str) -> bool:
    base = model.split(":", 1)[0].lower()
    return any(base == e.split(":", 1)[0].lower() for e in embedder_names())


def judge(t40: dict | None, has_route: bool | None, why_route: str) -> tuple[str, int]:
    if has_route is None:
        return f"IDLE JUDGED: unjudged: the node agent could not be read ({why_route})", 0
    if not has_route:
        return "IDLE JUDGED: unjudged: this build's node agent has no /backend-alive route (before #1191)", 0
    if t40 is None:
        return "IDLE JUDGED: FAIL: no +40 min sample was taken", 1
    idle = str(t40.get("idle") or "")
    if idle.startswith("unknown"):
        return f"IDLE JUDGED: FAIL: the +40 min sample could not read the backends ({idle})", 1
    chat = [m.get("model", "?") for m in (t40.get("models_loaded") or []) if not is_embedder(str(m.get("model", "")))]
    if chat:
        return f"IDLE JUDGED: FAIL: chat model(s) still loaded at +40 min with nobody chatting: {', '.join(chat)}", 1
    return "IDLE JUDGED: PASS: no chat model loaded at +40 min with nobody chatting", 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--t40", required=True)
    ap.add_argument("--agent-bin", required=True)
    a = ap.parse_args(argv)
    has, why = agent_has_route(a.agent_bin)
    try:
        t40 = json.load(open(a.t40))
    except (OSError, ValueError):
        t40 = None
    line, rc = judge(t40, has, why)
    print(line)
    return rc


if __name__ == "__main__":
    sys.exit(main())
