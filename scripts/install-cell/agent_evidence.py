#!/usr/bin/env python3
"""What the gateway and the Ollama daemons were doing when a probe's agent
turn (`noo inference agent`, POST /api/agent/run) was killed by its timeout.

0.6.25-rc.4 matrix run 1, ubuntu-24.04-amd64-slots4: the agent turn never
answered in 300 s, where four rc.3 runs on the same cell answered, and the cell
kept nothing that could tell a failover from a stall. On a timeout run.sh now
calls this, which prints:

  - the gateway's own lines for the window (probe start to kill) that say
    which backend served and what it answered: backend_resolved, backend_call,
    request_size, llm_http_error (with attempt=), "LLM connection failed",
    llm_backend_fallback, tier/cut lines and the agent run's own lines. Each
    is printed as its JSON fields with every prompt-, message- and
    text-shaped field DROPPED: no prompt or reply text leaves the cell;
  - for every running noo-ollama* container: its OLLAMA_NUM_PARALLEL and
    `ollama ps` at kill time (which daemon held the chat model, and since when).

A probe: it always exits 0, and says so when something cannot be read.

  agent_evidence.py --since <epoch seconds>
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess

KEEP = re.compile(
    r"backend_resolved|backend_call|request_size|llm_http_error|LLM connection failed|llm_backend_fallback"
    r"|context_cut|tier=|\"tier\"|agent_run|agentic|/api/agent/run|turn_failed|stream_error|timed? ?out",
    re.IGNORECASE)
# Field names whose values can carry what the person typed or the model said.
# Anchored: tracing's JSON names the EVENT in fields.message (kept), and a
# loose "text" would also drop "context".
DROP = re.compile(r"^(prompt\w*|system_prompt|messages|content|text|query|question|answer|reply|body"
                  r"|tool_args|arguments|input|output)$", re.IGNORECASE)
MAX_LINES = 60


def docker(*args: str, timeout: float = 30) -> tuple[str | None, str]:
    """Run docker, then `sudo -n docker` (the runner user may not be in the
    docker group yet). (stdout, why-not)."""
    for pre in ([], ["sudo", "-n"]):
        try:
            p = subprocess.run(pre + ["docker", *args], capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            why = f"{type(e).__name__}: {e}"
            continue
        if p.returncode == 0:
            return p.stdout + p.stderr, ""
        why = (p.stderr or p.stdout).strip()[:200]
    return None, why


def scrub(fields: dict) -> dict:
    out = {}
    for k, v in fields.items():
        if DROP.search(str(k)):
            out[k] = "[dropped]"
        elif isinstance(v, dict):
            out[k] = scrub(v)
        elif isinstance(v, str) and len(v) > 200:
            out[k] = v[:200] + "…"
        else:
            out[k] = v
    return out


def line_view(raw: str) -> str | None:
    """One gateway log line as kept: JSON lines keep their scrubbed fields; a
    non-JSON line is kept only when it matches KEEP, cut to 300 chars, and
    never when it looks like it carries a prompt."""
    raw = raw.strip()
    if not raw:
        return None
    try:
        d = json.loads(raw)
    except ValueError:
        # A plain line can't be scrubbed field by field: keep only its event
        # words, never free text.
        m = KEEP.search(raw)
        return f"(non-JSON line matching {m.group(0)!r}, text not kept)" if m else None
    if not isinstance(d, dict):
        return None
    flat = json.dumps(d, ensure_ascii=False)
    if not KEEP.search(flat):
        return None
    view = scrub(d)
    return json.dumps(view, ensure_ascii=False)[:600]


def gateway_lines(since: float) -> list[str]:
    name = os.environ.get("NOO_CONTAINER_PREFIX", "noo") + "-gateway"
    text, why = docker("logs", "--since", f"{since:.0f}", name, timeout=60)
    if text is None:
        return [f"gateway log not readable: {why}"]
    kept = [v for v in (line_view(l) for l in text.splitlines()) if v]
    if len(kept) > MAX_LINES:
        kept = kept[:20] + [f"... {len(kept) - MAX_LINES} lines between ..."] + kept[-(MAX_LINES - 20):]
    return kept or ["no matching gateway line in the window"]


def ollama_state() -> list[str]:
    names, why = docker("ps", "--format", "{{.Names}}")
    if names is None:
        return [f"docker ps not readable: {why}"]
    out = []
    for c in sorted(n for n in names.split() if re.match(r"^noo-ollama", n)):
        par, _ = docker("exec", c, "printenv", "OLLAMA_NUM_PARALLEL")
        ps, why = docker("exec", c, "ollama", "ps", timeout=30)
        out.append(f"{c}: OLLAMA_NUM_PARALLEL={(par or '').strip() or 'unset'}")
        out.extend(f"  {l}" for l in (ps or f"ollama ps failed: {why}").strip().splitlines()[:8])
    return out or ["no noo-ollama* container running"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", type=float, required=True)
    a = ap.parse_args()
    print("AGENT EVIDENCE: gateway lines from the probe's start to its kill (prompt and reply fields dropped)")
    for l in gateway_lines(a.since):
        print("  gw: " + l)
    print("AGENT EVIDENCE: Ollama daemons at kill time")
    for l in ollama_state():
        print("  " + l)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
