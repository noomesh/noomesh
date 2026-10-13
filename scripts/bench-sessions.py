#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Concurrent-session benchmark against a live gateway.

Runs N sessions at once for R rounds, each POSTing one prompt to
/api/inference, and reports latency percentiles, throughput and how many
tool calls the runs made. The point is a number BEFORE and AFTER a change
(worker replicas, tools on nodes) rather than an assumption about where
the knee is.

Auth, in order: --token, $NOO_TOKEN, --user/--password (or $NOO_BENCH_USER /
$NOO_BENCH_PASSWORD → POST /auth/token), else the noo CLI's stored
credential (~/.config/mesh/credentials.json, access_token).

    python3 scripts/bench-sessions.py --gateway https://noo-controller.example:8080 \
        --cacert ~/.config/noo/host8-ca.crt --sessions 8 --rounds 3

stdlib only, so it runs from any box with python3 and a route to the gateway.
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import statistics
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

DEFAULT_PROMPT = "In one sentence: what is the current status of this cluster? Use a tool if one helps."


def _ctx(cacert: str | None, insecure: bool) -> ssl.SSLContext:
    if insecure:
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        return c
    return ssl.create_default_context(cafile=cacert) if cacert else ssl.create_default_context()


def _post(url: str, body: dict, headers: dict, ctx: ssl.SSLContext, timeout: float) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={"content-type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}


def _token(args, ctx) -> str | None:
    if args.token:
        return args.token
    if os.environ.get("NOO_TOKEN"):
        return os.environ["NOO_TOKEN"]
    user = args.user or os.environ.get("NOO_BENCH_USER")
    pw = args.password or os.environ.get("NOO_BENCH_PASSWORD")
    if user and pw:
        st, body = _post(f"{args.gateway}/auth/token", {"username": user, "password": pw}, {}, ctx, 20)
        if st == 200 and body.get("access_token"):
            return body["access_token"]
        print(f"login failed: HTTP {st} {body}", file=sys.stderr)
        return None
    cred = Path.home() / ".config" / "mesh" / "credentials.json"
    if cred.exists():
        try:
            return json.loads(cred.read_text()).get("access_token")
        except Exception:
            pass
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gateway", default=os.environ.get("NOO_GATEWAY_URL", "https://localhost:8080"))
    ap.add_argument("--cacert", default=os.environ.get("NOO_TLS_CA"))
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification (diagnostics only)")
    ap.add_argument("--sessions", type=int, default=4, help="concurrent sessions per round")
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--prompt", default=DEFAULT_PROMPT)
    ap.add_argument("--timeout", type=float, default=180.0)
    ap.add_argument("--token")
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    ctx = _ctx(args.cacert, args.insecure)
    tok = _token(args, ctx)
    if not tok:
        print("no credential: pass --token, set NOO_TOKEN, --user/--password, or `noo auth login` first", file=sys.stderr)
        return 2
    headers = {"Authorization": f"Bearer {tok}"}
    url = f"{args.gateway.rstrip('/')}/api/inference"

    def one(i: int) -> dict:
        t0 = time.perf_counter()
        st, body = _post(url, {"prompt": args.prompt, "channel": "bench", "conversation_id": f"bench-{os.getpid()}-{i}-{int(t0)}"}, headers, ctx, args.timeout)
        dt = time.perf_counter() - t0
        data = body.get("data", {}) if isinstance(body, dict) else {}
        return {
            "ok": st == 200 and body.get("success", False),
            "status": st,
            "secs": dt,
            "tool_calls": len(data.get("tool_calls") or []),
            "iterations": data.get("iterations"),
            "node": data.get("backend"),
            "error": None if st == 200 else (body.get("error") or body),
        }

    results: list[dict] = []
    for r in range(args.rounds):
        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=args.sessions) as ex:
            batch = list(ex.map(one, range(args.sessions)))
        wall = time.perf_counter() - t0
        results.extend(batch)
        oks = [b for b in batch if b["ok"]]
        secs = sorted(b["secs"] for b in oks) or [0.0]
        p50 = statistics.median(secs)
        p95 = secs[min(len(secs) - 1, int(round(0.95 * (len(secs) - 1))))]
        if not args.json:
            print(f"round {r + 1}/{args.rounds}: {len(oks)}/{len(batch)} ok  wall {wall:.1f}s  "
                  f"p50 {p50:.1f}s  p95 {p95:.1f}s  {len(oks) / wall if wall else 0:.2f} sessions/s  "
                  f"tool calls {sum(b['tool_calls'] for b in oks)}")
            for b in batch:
                if not b["ok"]:
                    print(f"  ✗ HTTP {b['status']}: {str(b['error'])[:160]}")
    oks = [b for b in results if b["ok"]]
    secs = sorted(b["secs"] for b in oks) or [0.0]
    summary = {
        "gateway": args.gateway,
        "sessions": args.sessions,
        "rounds": args.rounds,
        "ok": len(oks),
        "failed": len(results) - len(oks),
        "p50_secs": round(statistics.median(secs), 2),
        "p95_secs": round(secs[min(len(secs) - 1, int(round(0.95 * (len(secs) - 1))))], 2),
        "max_secs": round(max(secs), 2),
        "tool_calls": sum(b["tool_calls"] for b in oks),
        "nodes": sorted({b["node"] for b in oks if b["node"]}),
    }
    if args.json:
        print(json.dumps(summary))
    else:
        print(f"total: {summary['ok']} ok / {summary['failed']} failed  p50 {summary['p50_secs']}s  "
              f"p95 {summary['p95_secs']}s  max {summary['max_secs']}s  tool calls {summary['tool_calls']}  "
              f"backends {', '.join(summary['nodes']) or '-'}")
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
