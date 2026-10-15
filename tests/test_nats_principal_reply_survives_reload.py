# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A remote principal's reply still reaches the gateway when NATS reloads mid-request (i69, i70).

Runs a REAL nats-server with the worker and node grants exactly as
`perms_for` renders them (parsed out of noo-cli's Rust), sends a request on
the reply inbox the gateway uses for that principal, reloads the server's
authorization while the responder is still working, then has it reply.

nats-server keeps `allow_responses` entries in a per-connection map that a
config reload replaces (`reloadAuthorization` -> `RegisterUser` ->
`setPermissions`). On pop-os 2026-10-14 that refused a 12 s
`worker.rag.query` reply as a `Publish Violation` on `_INBOX_gw.…` and the
caller never got the answer (i69, fixed for the worker). Nodes and the
add-ons were left on `allow_responses` (i70); each principal now holds a
static publish on its OWN reply prefix:

- worker — and the add-ons, which present the worker principal
  (noo-trellion, noo-trellion-intel): `_INBOX_gw.worker.>`
- node <id>: `_INBOX_gw.node.<token>.>`

The control tests prove the reload in this harness really does wipe dynamic
reply permission, so the main tests cannot pass merely because no reload
happened; the least-privilege tests prove no principal can answer into
another's prefix.

Needs a `nats-server` binary: `$NOO_TEST_NATS_SERVER`, else `nats-server` on
PATH. Skipped (visibly) when neither exists — CI has no server; run it
locally before touching a reply grant.
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

NODES = ("host8", "host9")


def _const(path: Path, name: str) -> str:
    m = re.search(rf'pub(?:\(crate\))? const {name}: &str = "([^"]+)";', path.read_text())
    assert m, name
    return m.group(1)


WORKER_PREFIX = _const(GW_CREDS, "WORKER_REPLY_PREFIX")
NODE_ROOT = _const(GW_CREDS, "NODE_REPLY_ROOT")
GW_DEFAULT = _const(GW_CREDS, "INBOX_PREFIX")


def _node_prefix(node: str) -> str:
    return f"{NODE_ROOT}.{node}"  # the ids used here are already one token


def _permissions(role: str, node_id: str = "") -> str:
    """The Role::<role> block of perms_for, as nats-server config text."""
    text = GRANTS.read_text()
    m = re.search(rf"Role::{role} => format!\((.*?)\n        \),", text, re.S)
    assert m, f"Role::{role} grant not found"
    subs = {
        "{RESPONSE_EXPIRES}": _const(GRANTS, "RESPONSE_EXPIRES"),
        "{WORKER_REPLY_INBOX}": _const(GRANTS, "WORKER_REPLY_INBOX"),
        "{NODE_REPLY_ROOT}": _const(GRANTS, "NODE_REPLY_ROOT"),
        "{id}": node_id,
        "{tok}": node_id,
    }
    lines = []
    for raw in m.group(1).splitlines():
        raw = raw.strip()
        if not raw.startswith('"') and not raw.startswith("{ind}"):
            continue
        raw = raw.lstrip('"')
        raw = re.sub(r'\\n\\?"?$', "", raw)
        line = raw.replace("{ind}", "").replace('\\"', '"')
        for k, v in subs.items():
            line = line.replace(k, v)
        line = line.replace("{{", "{").replace("}}", "}")
        assert not re.search(r"\{[A-Za-z_]+\}", line), f"unsubstituted placeholder: {line}"
        lines.append(line)
    out = "\n".join(lines)
    assert "allow_responses" in out, out
    return out


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _conf(port: int, filler_password: str) -> str:
    # `filler` exists only so a reload has an authorization change to apply,
    # as a provision's re-render does on a live box.
    nodes = "\n".join(
        f'      {{ user: "node-{n}", password: "{n}", permissions: {{\n{_permissions("Node", n)}\n      }} }}'
        for n in NODES
    )
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
{_permissions("Worker")}
      }} }}
{nodes}
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
        pytest.fail(f"nats-server did not start:\n{log.read_text() if log.exists() else ''}")

    reloads = {"n": 0}

    def reload():
        reloads["n"] += 1
        conf.write_text(_conf(port, f"f{reloads['n']}"))
        proc.send_signal(signal.SIGHUP)
        end = time.monotonic() + 10
        while time.monotonic() < end:
            if log.read_text().count("Reloaded: authorization users") >= reloads["n"]:
                return
            time.sleep(0.05)
        raise AssertionError(f"server did not reload authorization ({reloads['n']}):\n{log.read_text()}")

    yield port, reload, log
    proc.terminate()
    proc.wait(timeout=10)


# (responder user, password, its own inbox prefix, subject it answers)
WORKER = ("worker", "wk", "_INBOX_worker", "worker.rag.query")
# An add-on request: trellion-intel answers `worker.graph.*` presenting the
# worker principal (docker-compose.trellion.yml NATS_WORKER_USER).
ADDON = ("worker", "wk", "_INBOX_worker", "worker.graph.recluster")
NODE8 = ("node-host8", "host8", "_INBOX_node_host8", "harness.run.host8")
NODE9_TASK = ("node-host9", "host9", "_INBOX_node_host9", "harness.task.host9")


async def _round_trip(port, reload, responder, requester_user, requester_pw, reply_prefix):
    """Request -> (responder holds it) -> reload -> responder replies.

    Returns (reply|None, responder errors). `reply_prefix` is the prefix the
    gateway addresses the reply to — its scoped inbox for that principal.
    """
    user, pw, own_inbox, subject = responder
    errors: list[str] = []

    async def on_err(e):
        errors.append(str(e))

    url = f"nats://127.0.0.1:{port}"
    resp = await nats.connect(url, user=user, password=pw, inbox_prefix=own_inbox.encode(),
                              error_cb=on_err, allow_reconnect=False)
    requester = await nats.connect(url, user=requester_user, password=requester_pw,
                                   inbox_prefix=reply_prefix.encode(), allow_reconnect=False)
    got_request = asyncio.Event()
    may_reply = asyncio.Event()
    seen_reply_subject: list[str] = []

    async def handler(msg):
        seen_reply_subject.append(msg.reply)
        got_request.set()
        await may_reply.wait()          # a slow answer: still working when NATS reloads
        await msg.respond(b"answer")

    await resp.subscribe(subject, queue="q", cb=handler)
    await resp.flush()
    req = asyncio.create_task(requester.request(subject, b"q", timeout=5))
    await asyncio.wait_for(got_request.wait(), 5)
    assert seen_reply_subject[0].startswith(reply_prefix + "."), seen_reply_subject
    await asyncio.get_running_loop().run_in_executor(None, reload)
    may_reply.set()
    try:
        reply = (await req).data
    except nats.errors.TimeoutError:
        reply = None
    await resp.flush()
    await asyncio.sleep(0.2)  # the violation arrives asynchronously
    await requester.close()
    await resp.close()
    return reply, errors


def _violations(errors):
    return [e for e in errors if "permissions violation" in e.lower()]


@pytest.mark.parametrize(
    "responder, prefix",
    [
        pytest.param(WORKER, WORKER_PREFIX, id="worker"),
        pytest.param(ADDON, WORKER_PREFIX, id="addon-trellion-intel"),
        pytest.param(NODE8, _node_prefix("host8"), id="node-harness-run"),
        pytest.param(NODE9_TASK, _node_prefix("host9"), id="node-harness-task"),
    ],
)
async def test_a_reply_to_the_gateway_survives_a_reload(server, responder, prefix):
    port, reload, _log = server
    reply, errors = await _round_trip(port, reload, responder, "gateway", "gw", prefix)
    assert reply == b"answer", f"the gateway never got {responder[0]}'s answer; errors: {errors}"
    assert not _violations(errors), errors


async def test_control_a_reload_does_wipe_dynamic_reply_permission(server):
    # A requester whose inbox the worker holds no static grant for relies on
    # allow_responses alone — and loses its answer across the same reload.
    # If this ever passes, the harness is not reloading and the tests above
    # prove nothing.
    port, reload, log = server
    reply, errors = await _round_trip(port, reload, WORKER, "other", "ot", "_INBOX_other")
    assert reply is None
    assert _violations(errors), errors
    assert "Publish Violation" in log.read_text()


async def test_control_a_node_has_no_grant_on_the_gateway_default_inbox(server):
    # The same node request on the gateway's DEFAULT inbox (what the gateway
    # sent before i70) is refused after a reload: the node's static grant is
    # its own prefix, not `_INBOX_gw.>`.
    port, reload, _log = server
    reply, errors = await _round_trip(port, reload, NODE8, "gateway", "gw", GW_DEFAULT)
    assert reply is None
    assert _violations(errors), errors


@pytest.mark.parametrize(
    "user, pw, target",
    [
        pytest.param("node-host9", "host9", _node_prefix("host8") + ".x", id="node-into-another-node"),
        pytest.param("node-host8", "host8", WORKER_PREFIX + ".x", id="node-into-worker"),
        pytest.param("node-host8", "host8", GW_DEFAULT + ".x", id="node-into-gateway-default"),
        pytest.param("worker", "wk", _node_prefix("host8") + ".x", id="worker-into-node"),
        pytest.param("worker", "wk", GW_DEFAULT + ".x", id="worker-into-gateway-default"),
    ],
)
async def test_no_principal_may_publish_on_another_ones_prefix(server, user, pw, target):
    port, _reload, _log = server
    errors: list[str] = []

    async def on_err(e):
        errors.append(str(e))

    url = f"nats://127.0.0.1:{port}"
    gw = await nats.connect(url, user="gateway", password="gw", allow_reconnect=False)
    got: list[bytes] = []

    async def collect(msg):
        got.append(msg.data)

    await gw.subscribe(target, cb=collect)
    await gw.flush()
    nc = await nats.connect(url, user=user, password=pw, error_cb=on_err, allow_reconnect=False)
    await nc.publish(target, b"forged")
    await nc.flush()
    await asyncio.sleep(0.2)
    await nc.close()
    await gw.close()
    assert not got, f"{user} delivered a message on {target}"
    assert _violations(errors), f"{user} publishing on {target} was not refused: {errors}"


async def test_and_each_may_publish_on_its_own(server):
    # The positive half, so the refusals above cannot pass because the
    # principals can publish nothing at all.
    port, _reload, _log = server
    url = f"nats://127.0.0.1:{port}"
    for user, pw, target in [
        ("worker", "wk", WORKER_PREFIX + ".x"),
        ("node-host8", "host8", _node_prefix("host8") + ".x"),
        ("node-host9", "host9", _node_prefix("host9") + ".x"),
    ]:
        errors: list[str] = []

        async def on_err(e, errors=errors):
            errors.append(str(e))

        gw = await nats.connect(url, user="gateway", password="gw", allow_reconnect=False)
        got: list[bytes] = []

        async def collect(msg, got=got):
            got.append(msg.data)

        await gw.subscribe(target, cb=collect)
        await gw.flush()
        nc = await nats.connect(url, user=user, password=pw, error_cb=on_err, allow_reconnect=False)
        await nc.publish(target, b"ok")
        await nc.flush()
        await asyncio.sleep(0.2)
        await nc.close()
        await gw.close()
        assert got == [b"ok"], f"{user} could not publish on its own prefix {target}: {errors}"
