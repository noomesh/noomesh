# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A worker reply still reaches the gateway when NATS reloads mid-request (i69).

Runs a REAL nats-server with the worker grant exactly as `perms_for` renders
it (parsed out of noo-cli's Rust), sends a request from a gateway-inboxed
client, reloads the server's authorization while the worker is still
working, then has the worker reply.

nats-server keeps `allow_responses` entries in a per-connection map that a
config reload replaces (`reloadAuthorization` -> `RegisterUser` ->
`setPermissions`). On pop-os 2026-10-14 that refused a 12 s
`worker.rag.query` reply as a `Publish Violation` on `_INBOX_gw.…` and the
caller never got the answer. The control test proves the reload in this
harness really does wipe dynamic reply permission, so the main test cannot
pass merely because no reload happened.

Needs a `nats-server` binary: `$NOO_TEST_NATS_SERVER`, else `nats-server` on
PATH. Skipped (visibly) when neither exists — CI has no server; run it
locally before touching the worker grant.
"""

import asyncio
import os
import re
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path

import pytest

nats = pytest.importorskip("nats")

ROOT = Path(__file__).resolve().parent.parent
GRANTS = ROOT / "noo-cli/src/commands/nats_users.rs"
GW_CREDS = ROOT / "gateway-rust/src/nats_credentials.rs"

SERVER = os.environ.get("NOO_TEST_NATS_SERVER") or shutil.which("nats-server")
pytestmark = pytest.mark.skipif(not SERVER, reason="no nats-server binary (set NOO_TEST_NATS_SERVER)")


def _const(path: Path, name: str) -> str:
    m = re.search(rf'pub(?:\(crate\))? const {name}: &str = "([^"]+)";', path.read_text())
    assert m, name
    return m.group(1)


def _worker_permissions() -> str:
    """The Role::Worker block of perms_for, as nats-server config text."""
    text = GRANTS.read_text()
    m = re.search(r"Role::Worker => format!\((.*?)\n        \),", text, re.S)
    assert m, "Role::Worker grant not found"
    lines = []
    for raw in m.group(1).splitlines():
        raw = raw.strip()
        if not raw.startswith('"') and not raw.startswith("{ind}"):
            continue
        raw = raw.lstrip('"')
        raw = re.sub(r'\\n\\?"?$', "", raw)
        line = (raw.replace("{ind}", "")
                .replace('\\"', '"')
                .replace("{{", "{").replace("}}", "}")
                .replace("{RESPONSE_EXPIRES}", _const(GRANTS, "RESPONSE_EXPIRES"))
                .replace("{GATEWAY_REPLY_INBOX}", _const(GRANTS, "GATEWAY_REPLY_INBOX")))
        assert "{" not in line or line.rstrip().endswith("{") or "}" in line, line
        lines.append(line)
    out = "\n".join(lines)
    assert "allow_responses" in out and "worker.>" in out, out
    return out


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _conf(port: int, filler_password: str) -> str:
    # `filler` exists only so a reload has an authorization change to apply,
    # as a provision's re-render does on a live box.
    return f"""
port: {port}
host: "127.0.0.1"
accounts {{
  NOO: {{
    users: [
      {{ user: "gateway", password: "gw", permissions: {{ publish: {{ allow: [">"] }}, subscribe: {{ allow: [">"] }} }} }}
      {{ user: "other", password: "ot", permissions: {{ publish: {{ allow: [">"] }}, subscribe: {{ allow: [">"] }} }} }}
      {{ user: "filler", password: "{filler_password}" }}
      {{ user: "worker", password: "wk", permissions: {{
{_worker_permissions()}
      }} }}
    ]
  }}
}}
"""


@pytest.fixture
def server(tmp_path):
    port = _free_port()
    conf = tmp_path / "nats.conf"
    conf.write_text(_conf(port, "f0"))
    log = tmp_path / "nats.log"
    proc = subprocess.Popen([SERVER, "-c", str(conf), "-l", str(log)])
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        proc.kill()
        pytest.fail("nats-server did not start")

    reloads = {"n": 0}

    def reload():
        reloads["n"] += 1
        conf.write_text(_conf(port, f"f{reloads['n']}"))
        proc.send_signal(signal.SIGHUP)
        want = reloads["n"] + 1  # "Reloaded server configuration" count
        end = time.monotonic() + 10
        while time.monotonic() < end:
            if log.read_text().count("Reloaded: authorization users") >= reloads["n"]:
                return
            time.sleep(0.05)
        raise AssertionError(f"server did not reload authorization ({want}):\n{log.read_text()}")

    yield port, reload, log
    proc.terminate()
    proc.wait(timeout=10)


async def _round_trip(port, reload, requester_user, requester_pw, inbox_prefix):
    """Request -> (worker holds it) -> reload -> worker replies. Returns (reply|None, worker errors)."""
    errors: list[str] = []

    async def on_err(e):
        errors.append(str(e))

    url = f"nats://127.0.0.1:{port}"
    worker = await nats.connect(url, user="worker", password="wk", inbox_prefix=b"_INBOX_worker",
                                error_cb=on_err, allow_reconnect=False)
    requester = await nats.connect(url, user=requester_user, password=requester_pw,
                                   inbox_prefix=inbox_prefix.encode(), allow_reconnect=False)
    got_request = asyncio.Event()
    may_reply = asyncio.Event()

    async def handler(msg):
        got_request.set()
        await may_reply.wait()          # a slow answer: still working when NATS reloads
        await msg.respond(b"answer")

    await worker.subscribe("worker.rag.query", queue="workers", cb=handler)
    await worker.flush()
    req = asyncio.create_task(requester.request("worker.rag.query", b"q", timeout=5))
    await asyncio.wait_for(got_request.wait(), 5)
    await asyncio.get_running_loop().run_in_executor(None, reload)
    may_reply.set()
    try:
        reply = (await req).data
    except nats.errors.TimeoutError:
        reply = None
    await worker.flush()
    await asyncio.sleep(0.2)  # the violation arrives asynchronously
    await requester.close()
    await worker.close()
    return reply, errors


async def test_worker_reply_to_the_gateway_survives_a_reload(server):
    port, reload, _log = server
    reply, errors = await _round_trip(port, reload, "gateway", "gw", _const(GW_CREDS, "INBOX_PREFIX"))
    assert reply == b"answer", f"the gateway never got the worker's answer; worker errors: {errors}"
    assert not [e for e in errors if "permissions violation" in e], errors


async def test_control_a_reload_does_wipe_dynamic_reply_permission(server):
    # A requester whose inbox the worker holds no static grant for relies on
    # allow_responses alone — and loses its answer across the same reload.
    # If this ever passes, the harness is not reloading and the test above
    # proves nothing.
    port, reload, log = server
    reply, errors = await _round_trip(port, reload, "other", "ot", "_INBOX_other")
    assert reply is None
    assert any("permissions violation" in e for e in errors), errors
    assert "Publish Violation" in log.read_text()
