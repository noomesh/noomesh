"""example-addon: the reference add-on of docs/development/addons.md.

It shows the connect path, both ways, with nothing but its delivered files:
  in   the gateway calls GET /api/example-addon/status with its own bearer;
       we verify it (sha256 in the noo_addon_caller_keys view) before
       answering, and read who the call acts for from X-Noo-Requester-Sub;
  out  we exchange our own key (a FILE, never the environment) at
       POST /api/addon/token for a short-lived token, and would call the
       gateway with it.
Standard library plus psycopg. No shell is assumed in the image.
"""
import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psycopg

WORK = "/run/example-addon"
GATEWAY = os.environ.get("EXAMPLE_ADDON_GATEWAY_URL", "https://gateway:8080").rstrip("/")
ROUTES = {"/api/example-addon/status"}  # == routes.json (tests/test_contract.py)

_gw_ctx = ssl.create_default_context(cafile=f"{WORK}/ca.crt")
_token, _info, _until = None, {}, 0.0


def gateway_token():
    """Our token, exchanged from our key; re-exchanged a minute before expiry.
    A 401 from the exchange means the key is revoked or rotated: it raises,
    and the caller reports it instead of retrying in a loop."""
    global _token, _info, _until
    if _token and time.time() < _until - 60:
        return _token, _info
    with open(f"{WORK}/addon-key") as f:
        key = f.read().strip()
    req = urllib.request.Request(f"{GATEWAY}/api/addon/token", method="POST",
                                 headers={"Authorization": f"Bearer {key}"})
    with urllib.request.urlopen(req, context=_gw_ctx, timeout=10) as r:
        body = json.load(r)
    _token, _until = body["token"], time.time() + body["expires_in"]
    _info = {k: body[k] for k in ("consumer", "scopes", "expires_in")}
    return _token, _info


def caller_is_gateway(bearer: str) -> bool:
    """The gateway's bearer, verified: its sha256 has a row in the view our
    runtime role may read because system.json declares verify_callers."""
    if not bearer:
        return False
    digest = hashlib.sha256(bearer.encode()).hexdigest()
    with open(f"{WORK}/db/url") as f:
        url = f.read().strip()
    with psycopg.connect(url, connect_timeout=5) as conn:
        row = conn.execute("SELECT consumer FROM noo_addon_caller_keys WHERE key_hash = %s", (digest,)).fetchone()
    return row is not None


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"status": "ok"})
        if self.path not in ROUTES:
            return self._send(404, {"error": "not found"})
        auth = self.headers.get("Authorization", "")
        bearer = auth[7:] if auth.startswith("Bearer ") else ""
        try:
            if not caller_is_gateway(bearer):
                return self._send(401, {"error": "caller is not the gateway"})
        except Exception as e:  # the view unreadable: refuse, never assume
            return self._send(503, {"error": f"cannot verify the caller: {type(e).__name__}"})
        try:
            _tok, info = gateway_token()
            outbound = {"exchanged": True, **info}
        except urllib.error.HTTPError as e:
            outbound = {"exchanged": False, "status": e.code}
        self._send(200, {
            "addon": "example-addon",
            "requested_for": self.headers.get("X-Noo-Requester-Sub") or "the gateway itself",
            "outbound": outbound,
        })

    def log_message(self, fmt, *args):  # no request bodies or headers in logs
        pass


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", 8090), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(f"{WORK}/leaf.crt", f"{WORK}/leaf.key")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
