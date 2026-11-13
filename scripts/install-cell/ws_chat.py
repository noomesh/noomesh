# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Ask the console's chat (the /ws/coordinator socket) one question, as the
browser does: mint a single-use ticket at POST /api/ws-ticket with the CLI's
stored access token, open <socket>?ticket=, send {"prompt": ...}, collect the
reply until "done". Prints the reply text. Stdlib only: the install cell has
python3 and nothing else.

usage: ws_chat.py PROMPT [GATEWAY_URL]   (default https://localhost:8080)

TLS is not verified: the cell asks its own gateway on localhost, and this is a
probe that reads an answer, not a trust check.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.parse
import urllib.request


def token() -> str:
    p = os.path.expanduser("~/.config/mesh/credentials.json")
    with open(p, encoding="utf-8") as f:
        return json.load(f)["access_token"]


def mint_ticket(base: str, tok: str, ctx: ssl.SSLContext) -> str:
    req = urllib.request.Request(
        base + "/api/ws-ticket",
        data=json.dumps({"socket": "/ws/coordinator"}).encode(),
        headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
        return json.load(r)["ticket"]


def frame(text: str) -> bytes:
    payload = text.encode()
    mask = os.urandom(4)
    n = len(payload)
    head = b"\x81" + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n))
    return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def read_exact(s, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("socket closed")
        buf += chunk
    return buf


def read_frame(s) -> tuple[int, bytes]:
    b0, b1 = read_exact(s, 2)
    n = b1 & 0x7F
    if n == 126:
        n = struct.unpack(">H", read_exact(s, 2))[0]
    elif n == 127:
        n = struct.unpack(">Q", read_exact(s, 8))[0]
    return b0 & 0x0F, read_exact(s, n)


def ask(prompt: str, base: str = "https://localhost:8080", timeout: float = 300) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ticket = mint_ticket(base, token(), ctx)
    u = urllib.parse.urlsplit(base)
    raw = socket.create_connection((u.hostname, u.port or 443), timeout=30)
    s = ctx.wrap_socket(raw, server_hostname=u.hostname)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((
        f"GET /ws/coordinator?ticket={urllib.parse.quote(ticket)} HTTP/1.1\r\n"
        f"Host: {u.netloc}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ).encode())
    head = b""
    while b"\r\n\r\n" not in head:
        head += read_exact(s, 1)
    if b" 101 " not in head.split(b"\r\n", 1)[0]:
        raise RuntimeError("handshake refused: " + head.split(b"\r\n", 1)[0].decode(errors="replace"))
    s.sendall(frame(json.dumps({"prompt": prompt})))
    out, tools, end = [], [], time.time() + timeout
    s.settimeout(60)
    while time.time() < end:
        op, data = read_frame(s)
        if op == 0x8:
            break
        if op != 0x1:
            continue
        try:
            ev = json.loads(data)
        except ValueError:
            continue
        # The gateway's shape_event: a string payload arrives as {"type", "text"},
        # an object payload is flattened beside "type".
        kind = ev.get("type")
        if kind == "content" and isinstance(ev.get("text"), str):
            out.append(ev["text"])
        elif kind == "content_clear":
            out.clear()
        elif kind == "tool_call":
            tools.append(str(ev.get("name") or ev.get("tool") or "?"))
        elif kind == "error":
            out.append(f"\n[error: {ev.get('text', ev)}]")
        elif kind == "done":
            if ev.get("error"):
                out.append(f"\n[done error: {ev['error']}]")
            break
    s.close()
    return "".join(out) + "\n[tools called: " + (", ".join(tools) or "none") + "]"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: ws_chat.py PROMPT [GATEWAY_URL]")
    try:
        print(ask(sys.argv[1], *(sys.argv[2:3] or [])))
    except Exception as e:  # a probe: say what happened, never a traceback wall
        print(f"WS CHAT: could not ask the console chat: {type(e).__name__}: {e}")
