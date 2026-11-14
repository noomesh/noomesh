#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Cold-load delays on a one-machine install (operator 2026-11-14): what a
person waits for when the models are NOT resident, against the same calls
warm.

    coldload.py --out FILE --cell NAME --prompt TEXT [--gateway URL]

run.sh's probe-coldload runs it AFTER first-answer (the idle series before
it is untouched). In order:

  1. unload: every model `ollama ps` lists in every running ollama*
     container is stopped with `docker exec <c> ollama stop <model>` (on
     standalone the chat model and harrier both sit in noo-ollama-embed),
     then `ollama ps` again says whether the box is really cold;
  2. ONE embed through the gateway as an external client calls it:
     POST /api/external/embeddings with a service key minted for this run
     (`noo --json security service-key issue ... --scopes embeddings`; the
     key is held in memory, never printed or written, and revoked at the
     end), then ONE `noo chat --message PROMPT` (first-answer's call),
     timing first output and completion;
  3. the same embed and chat again, warm.

Writes FILE (coldload.json) and prints a table. A timing that could not be
taken is recorded with its reason, never as 0. Standard library only.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import importlib.util
import json
import os
import select
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
KEY_CONSUMER = "install-cell-coldload"
EMBED_PATH = "/api/external/embeddings"
EMBED_TEXT = "The delivery deadline for the Kestrel project is the 14th of March."


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MB = _load("memory_baseline")


# ---------------------------------------------------------------- pure parts

def cold_verdict(after: dict[str, dict]) -> str:
    """{container: ollama-ps answer} after the stops -> one line. Unknown
    when any container could not be read: never "cold" by default."""
    unknown = [f"{c} ({a['unknown']})" for c, a in after.items() if "unknown" in a]
    still = [f"{c}:{m}" for c, a in after.items() for m in a.get("models") or []]
    if still:
        return "no: still loaded: " + ", ".join(still)
    if unknown:
        return "unknown: " + "; ".join(unknown)
    if not after:
        return "unknown: no ollama container running"
    return "yes: nothing loaded after the stops"


def key_from_issue_json(text: str) -> str | None:
    """The raw key from `noo --json security service-key issue`, or None."""
    try:
        body = json.loads(text[text.index("{"):text.rindex("}") + 1])
    except ValueError:
        return None
    k = body.get("key") if isinstance(body, dict) else None
    return k if isinstance(k, str) and k else None


def scrub(text: str, secret: str | None) -> str:
    return text.replace(secret, "[REDACTED]") if secret else text


# ---------------------------------------------------------------- IO

def ollama_containers(host) -> tuple[list[str], str | None]:
    out, why = host.cmd("docker", "ps", "--format", "{{.Names}}")
    if out is None:
        return [], f"docker ps failed ({why})"
    return sorted(n for n in out.split() if MB.backend_of(n) == "ollama"), None


def ps(host, containers: list[str]) -> dict[str, dict]:
    return {c: MB.ask_ollama_container(host, {"name": c}) for c in containers}


def unload(host, containers: list[str]) -> tuple[list[dict], dict[str, dict]]:
    stops = []
    for c, a in ps(host, containers).items():
        if "unknown" in a:
            stops.append({"container": c, "model": None, "ok": False, "why": f"ollama ps unreadable: {a['unknown']}"})
            continue
        for m in a["models"]:
            out, why = host.cmd("docker", "exec", c, "ollama", "stop", m, timeout=120)
            stops.append({"container": c, "model": m, "ok": out is not None, **({"why": why} if out is None else {})})
    time.sleep(3)  # ollama releases the runner just after `stop` returns
    return stops, ps(host, containers)


def ssl_context(gateway: str) -> ssl.SSLContext | None:
    if not gateway.startswith("https:"):
        return None
    return ssl.create_default_context(cafile=_load("ws_chat").cluster_ca())


def embed(gateway: str, key: str | None, ctx) -> dict:
    if not key:
        return {"ok": False, "why": "not run: no service key could be minted"}
    req = urllib.request.Request(gateway.rstrip("/") + EMBED_PATH, method="POST",
                                 data=json.dumps({"input": [EMBED_TEXT]}).encode(),
                                 headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=900) as r:
            body = json.load(r)
            secs = time.monotonic() - t0
            vec = ((body.get("data") or [{}])[0] or {}).get("embedding") or []
            ok = bool(vec)
            return {"ok": ok, "seconds": round(secs, 2), "http_status": r.status, "model": body.get("model"),
                    "dims": len(vec), **({} if ok else {"why": "200 without a vector"})}
    except urllib.error.HTTPError as e:
        return {"ok": False, "seconds_to_error": round(time.monotonic() - t0, 2), "http_status": e.code,
                "why": scrub(e.read(300).decode(errors="replace"), key)}
    except Exception as e:  # noqa: BLE001 - any failure is a reason
        return {"ok": False, "seconds_to_error": round(time.monotonic() - t0, 2), "why": scrub(str(e), key)}


def chat(prompt: str, timeout: int = 900) -> dict:
    t0 = time.monotonic()
    try:
        p = subprocess.Popen(["noo", "chat", "--message", prompt], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    except OSError as e:
        return {"ok": False, "why": f"noo chat: {e}"}
    buf, first = b"", None
    fd = p.stdout.fileno()
    while True:
        if time.monotonic() - t0 > timeout:
            p.kill()
            p.wait()
            return {"ok": False, "seconds_to_error": timeout, "why": f"timed out after {timeout} s"}
        ready, _, _ = select.select([fd], [], [], 1.0)
        if not ready:
            continue
        chunk = os.read(fd, 4096)
        if not chunk:
            break
        if first is None and chunk.strip():
            first = time.monotonic() - t0
        buf += chunk
    rc = p.wait()
    secs = time.monotonic() - t0
    text = buf.decode(errors="replace")
    out = {"ok": rc == 0 and bool(text.strip()), "seconds": round(secs, 2), "rc": rc, "tail": text.strip()[-300:]}
    if first is not None:
        out["first_output_s"] = round(first, 2)
    if not out["ok"]:
        out["why"] = f"noo chat exited {rc}" if rc else "noo chat printed nothing"
    return out


def mint_key() -> tuple[str | None, str | None]:
    note = "install matrix cold-load probe; revoked by the probe"
    try:
        r = subprocess.run(["noo", "--json", "security", "service-key", "issue", KEY_CONSUMER,
                            "--scopes", "embeddings", "--note", note],
                           capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"noo security service-key issue: {e}"
    key = key_from_issue_json(r.stdout)
    if r.returncode != 0 or not key:
        # The output is never echoed whole: it may hold the key.
        last = (r.stderr.strip().splitlines() or ["no stderr"])[-1]
        return None, f"service-key issue exited {r.returncode}: {scrub(last, key)[:200]}"
    return key, None


def revoke_key() -> tuple[bool, str | None]:
    try:
        r = subprocess.run(["noo", "security", "service-key", "revoke", KEY_CONSUMER, "-y"],
                           capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    return r.returncode == 0, None if r.returncode == 0 else (r.stderr.strip().splitlines() or ["?"])[-1][:200]


def _secs(t: dict) -> str:
    if "seconds" in t:
        return f"{t['seconds']:.1f}"
    return "-"


def render(doc: dict) -> str:
    L = [f"COLD LOAD: cell {doc['meta'].get('cell')}, at {doc['meta'].get('timestamp')}",
         f"unload: " + (", ".join(f"{s['container']}:{s['model']} {'stopped' if s['ok'] else 'NOT stopped: ' + s.get('why', '?')}"
                                  for s in doc["unload"]) or "nothing was loaded"),
         f"cold before the timings: {doc['cold_confirmed']}", "",
         f"{'measurement':12} {'seconds':>9} {'first out':>10}  result"]
    for k in ("cold_embed", "warm_embed", "cold_chat", "warm_chat"):
        t = doc["timings"][k]
        fo = f"{t['first_output_s']:.1f}" if "first_output_s" in t else "-"
        L.append(f"{k:12} {_secs(t):>9} {fo:>10}  {'ok' if t.get('ok') else 'FAILED: ' + t.get('why', '?')}")
    L.append(f"service key: minted={doc['key']['minted']} revoked={doc['key'].get('revoked')}"
             + (f" ({doc['key']['why']})" if doc['key'].get('why') else ""))
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--cell", required=True)
    ap.add_argument("--prompt", required=True)
    ap.add_argument("--gateway", default=os.environ.get("NOO_GATEWAY_URL") or "https://localhost:8080")
    a = ap.parse_args(argv)
    host = MB.Host()
    containers, c_why = ollama_containers(host)
    stops, after = unload(host, containers)
    doc: dict = {
        "schema": 1,
        "meta": {"cell": a.cell, "prompt": a.prompt, "gateway": a.gateway, "embed_path": EMBED_PATH,
                 "timestamp": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "order": "unload, cold embed, cold chat, warm embed, warm chat"},
        "unload": stops,
        "cold_confirmed": cold_verdict(after) if not c_why else f"unknown: {c_why}",
        "timings": {},
    }
    key, why = mint_key()
    doc["key"] = {"minted": key is not None, **({"why": why} if why else {})}
    try:
        try:
            ctx = ssl_context(a.gateway)
        except Exception as e:  # noqa: BLE001 - recorded as the embeds' reason
            ctx = None
            no_ca = {"ok": False, "why": f"not run: no cluster CA for {a.gateway}: {e}"}
            doc["timings"]["cold_embed"], doc["timings"]["warm_embed"] = no_ca, dict(no_ca)
        if "cold_embed" not in doc["timings"]:
            doc["timings"]["cold_embed"] = embed(a.gateway, key, ctx)
        doc["timings"]["cold_chat"] = chat(a.prompt)
        doc["loaded_after_cold"] = MB.models_loaded(list(ps(host, containers).values()))
        if "warm_embed" not in doc["timings"]:
            doc["timings"]["warm_embed"] = embed(a.gateway, key, ctx)
        doc["timings"]["warm_chat"] = chat(a.prompt)
        doc["loaded_after_warm"] = MB.models_loaded(list(ps(host, containers).values()))
    finally:
        if key is not None:
            ok, rwhy = revoke_key()
            doc["key"]["revoked"] = ok
            if rwhy:
                doc["key"]["why"] = f"revoke failed: {rwhy}"
        text = scrub(json.dumps(doc, indent=1), key)
        with open(a.out, "w") as f:
            f.write(text)
    sys.stdout.write(scrub(render(doc), key))
    return 0 if all(t.get("ok") for t in doc["timings"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
