# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The kiosk browser's CDP broker: a pipe, not a port (followup 188).

`noo-kiosk-cdp broker` starts the browser with `--remote-debugging-pipe`
and is the only holder of that pipe. These run the real helper against a
fake browser that speaks CDP on fds 3 and 4, so no Chromium is needed:

- the pipe reaches the child even when its ends sit on fds 3 and 4 in the
  parent (the close-on-exec trap that killed the first spike);
- page.json carries what the page said, and a page that cannot be asked
  writes nothing, so `probe` goes stale and the watchdog strikes;
- the control socket checks its caller before reading a byte and knows one
  verb.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
import textwrap
import time
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HELPER = REPO / "noo-cli" / "src" / "commands" / "kiosk_assets" / "noo-kiosk-cdp"

# A browser in miniature: CDP on fd 3 (in) and fd 4 (out), NUL-framed.
FAKE_BROWSER = textwrap.dedent(
    """
    import json, os, sys
    reloads = sys.argv[1]
    r, w = os.fdopen(3, "rb", buffering=0), 4
    buf = b""
    while True:
        chunk = r.read(65536)
        if not chunk:
            break
        buf += chunk
        while b"\\0" in buf:
            raw, buf = buf.split(b"\\0", 1)
            m = json.loads(raw)
            meth, out = m["method"], {}
            if meth == "Target.getTargets":
                out = {"targetInfos": [
                    {"type": "page", "targetId": "omnibox", "url": "chrome://omnibox-popup/"},
                    {"type": "page", "targetId": "T1", "url": "http://127.0.0.1:8088/kiosk.html?view=health"},
                ]}
            elif meth == "Target.attachToTarget":
                assert m["params"] == {"targetId": "T1", "flatten": True}, m
                out = {"sessionId": "S1"}
            elif meth == "Runtime.evaluate":
                assert m.get("sessionId") == "S1", m
                e = m["params"]["expression"]
                v = (1793405596688 if "Heartbeat" in e else "stack-v0.6.16" if "Build" in e
                     else {"ms": 12, "quality": "high"})
                out = {"result": {"type": "object", "value": v}}
            elif meth == "Page.reload":
                assert m.get("sessionId") == "S1", m
                with open(reloads, "a") as f:
                    f.write("x")
            os.write(w, json.dumps({"id": m["id"], "result": out}).encode() + b"\\0")
    """
)


def load(state: Path):
    os.environ["NOO_KIOSK_STATE"] = str(state)
    spec = spec_from_loader("noo_kiosk_cdp", SourceFileLoader("noo_kiosk_cdp", str(HELPER)))
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def cli(state: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, NOO_KIOSK_STATE=str(state))
    return subprocess.run([sys.executable, str(HELPER), *args], capture_output=True, text=True, env=env, timeout=30)


def test_the_broker_drives_a_browser_on_fds_3_and_4(tmp_path: Path) -> None:
    # A FRESH interpreter, so os.pipe() hands out fds 3 and 4: exactly the
    # case where dup2(3, 3) keeps close-on-exec and the browser starts
    # without its pipe.
    fake = tmp_path / "fake_browser.py"
    fake.write_text(FAKE_BROWSER)
    reloads = tmp_path / "reloads"
    harness = textwrap.dedent(
        f"""
        import json, os, sys
        from importlib.machinery import SourceFileLoader
        from importlib.util import module_from_spec, spec_from_loader
        os.environ["NOO_KIOSK_STATE"] = {str(tmp_path)!r}
        spec = spec_from_loader("cdp", SourceFileLoader("cdp", {str(HELPER)!r}))
        m = module_from_spec(spec); spec.loader.exec_module(m)
        proc, pipe = m.spawn([sys.executable, {str(fake)!r}, {str(reloads)!r}])
        m.publish_once(pipe)
        pipe.on_page("Page.reload", {{"ignoreCache": True}})
        os.close(pipe.w)
        print("rc", proc.wait(10))
        """
    )
    r = subprocess.run([sys.executable, "-c", harness], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "rc 0" in r.stdout, r.stdout + r.stderr
    page = json.loads((tmp_path / "page.json").read_text())
    assert page["heartbeat"] == 1793405596688
    assert page["build"] == "stack-v0.6.16"
    assert page["frame"] == {"ms": 12, "quality": "high"}
    assert stat.S_IMODE((tmp_path / "page.json").stat().st_mode) == 0o644, "status reads page.json without privilege"
    assert reloads.read_text() == "x"


def test_page_json_is_read_by_the_old_verbs(tmp_path: Path) -> None:
    (tmp_path / "page.json").write_text(json.dumps(
        {"heartbeat": 1793405596688, "build": "stack-v0.6.16", "frame": {"ms": 40, "quality": "low"}, "updated_at": int(time.time())}))
    assert cli(tmp_path, "probe").stdout.strip() == "ok"
    assert cli(tmp_path, "heartbeat").stdout.strip() == "1793405596688"
    assert cli(tmp_path, "build").stdout.strip() == "stack-v0.6.16"
    assert json.loads(cli(tmp_path, "frame").stdout) == {"ms": 40, "quality": "low"}


def test_a_stale_page_json_is_a_browser_not_answering(tmp_path: Path) -> None:
    (tmp_path / "page.json").write_text(json.dumps({"heartbeat": 1, "build": "x", "updated_at": int(time.time()) - 600}))
    for verb in ("probe", "heartbeat", "build"):
        r = cli(tmp_path, verb)
        assert r.returncode == 5, (verb, r.stdout, r.stderr)
        assert "stale" in r.stderr
    r = cli(tmp_path / "nowhere", "probe")
    assert r.returncode == 5 and "no page.json" in r.stderr


class _Pipe:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def on_page(self, method, params=None):
        self.calls.append(method)
        return {}

    def evaluate(self, expr):
        raise RuntimeError("Runtime.evaluate: no reply in 15s")


def test_a_page_that_cannot_be_asked_writes_nothing(tmp_path: Path) -> None:
    m = load(tmp_path)
    with pytest.raises(RuntimeError):
        m.publish_once(_Pipe())
    assert not (tmp_path / "page.json").exists(), "a page.json written without asking hides a dead browser"


def _ask(m, allowed: set[int], verb: bytes) -> tuple[str, _Pipe]:
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    pipe = _Pipe()
    with a, b:
        b.sendall(verb)
        m.answer(a, pipe, allowed)
        return b.recv(512).decode(), pipe


def test_the_socket_checks_the_caller_before_anything_else(tmp_path: Path) -> None:
    m = load(tmp_path)
    me = os.getuid()
    reply, pipe = _ask(m, {me}, b"reload\n")
    assert reply == "ok\n" and pipe.calls == ["Page.reload"]

    reply, pipe = _ask(m, {me + 1}, b"reload\n")
    assert reply.startswith(f"refused: uid {me} "), reply
    assert pipe.calls == [], "a refused caller reached the browser"


def test_the_socket_knows_one_verb(tmp_path: Path) -> None:
    m = load(tmp_path)
    for verb in (b"navigate http://100.64.0.1/\n", b'{"method":"Runtime.evaluate"}\n', b"\n"):
        reply, pipe = _ask(m, {os.getuid()}, verb)
        assert reply.startswith("refused: unknown verb"), reply
        assert pipe.calls == []


def test_the_socket_is_connectable_and_the_peer_check_is_the_gate(tmp_path: Path) -> None:
    m = load(tmp_path)
    m.SOCK = str(tmp_path / "cdp.sock")
    srv = m.listen()
    try:
        # connect() needs write on the socket file, and the seat user is not
        # the display user: the mode cannot be the gate, so it is 0666.
        assert stat.S_IMODE(os.stat(m.SOCK).st_mode) == 0o666
    finally:
        srv.close()
    assert m.allowed_uids() >= {0, os.getuid()}
