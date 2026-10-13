# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The eval harness's identity probes, against a fake gateway.

Two things a live run cannot prove: that the engine reports LEAK when the
gateway leaks (a fake that isolates correctly is planted with a leak and
the row must flip), and that an operator's key yields n/a rows rather than
false leaks. Plus the rename: ``python -m noo_eval demo`` must run.
"""
from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import sys
from pathlib import Path

import httpx

EVAL = Path(__file__).resolve().parents[1] / "eval"
sys.path.insert(0, str(EVAL))

from noo_eval import identity  # noqa: E402
from noo_eval.scenario import Scenario  # noqa: E402


def _jwt(sub: str, role: str) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"sub": sub, "role": role}).encode()).decode().rstrip("=")
    return f"h.{payload}.s"


class FakeGateway:
    """Enough of the agent-mail surface to answer the probes. ``leak`` makes
    every reader see every message — the planted failure."""

    def __init__(self, role: str = "user", leak: bool = False):
        self.role, self.leak = role, leak
        self.messages: dict[str, dict] = {}
        self.reads: set[tuple[str, str]] = set()
        self.n = 0

    def _who(self, request: httpx.Request) -> str:
        tok = request.headers.get("Authorization", "").split(" ")[-1]
        seg = tok.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg))["sub"]

    @staticmethod
    def _account(name: str) -> str:
        return name.split("/")[0]

    def _may_read(self, who: str, m: dict) -> bool:
        if self.leak or self.role in ("admin", "operator"):
            return True
        owns = lambda n: n == who or (("/" not in who) and n.startswith(who + "/"))  # noqa: E731
        if owns(m["from"]) or owns(m["to"]):
            return True
        return m["to"] == self._account(who) and who != m["to"]

    def handle(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        if path == "/api/identity/token":
            body = json.loads(request.content)
            sub = body["subject_token"]
            return httpx.Response(200, json={"access_token": _jwt(sub, self.role), "subject": sub,
                                             "account": self._account(sub)})
        who = self._who(request)
        if path == "/api/agents/messages" and method == "POST":
            body = json.loads(request.content)
            if self._account(body["to"]) != self._account(who):
                return httpx.Response(403, json={"error": "not trusted"})
            self.n += 1
            mid = f"m{self.n}"
            self.messages[mid] = {"id": mid, "from": who, "to": body["to"], "text": body.get("text", "")}
            return httpx.Response(200, json={"sent": True, "message": self.messages[mid]})
        if path == "/api/agents/messages" and method == "GET":
            unread = request.url.params.get("unread") == "true"
            rows = [m for m in self.messages.values() if self._may_read(who, m)
                    and not (unread and (m["id"], who) in self.reads)]
            return httpx.Response(200, json={"messages": rows})
        if path.startswith("/api/agents/messages/") and path.endswith("/ack"):
            mid = path.split("/")[-2]
            m = self.messages.get(mid)
            if not m:
                return httpx.Response(404, json={"error": "message not found"})
            owns_to = m["to"] == who or (("/" not in who) and m["to"].startswith(who + "/"))
            if not (owns_to or self.leak or self.role in ("admin", "operator")):
                return httpx.Response(403, json={"error": "only the recipient can ack"})
            self.reads.add((mid, who))
            return httpx.Response(200, json={"acked": True, "id": mid})
        if path.startswith("/api/agents/messages/"):
            m = self.messages.get(path.split("/")[-1])
            if not m:
                return httpx.Response(404, json={"error": "message not found"})
            if not self._may_read(who, m):
                return httpx.Response(403, json={"error": "not a party to this message"})
            return httpx.Response(200, json=m)
        return httpx.Response(404, json={"error": f"no route {path}"})


def _run(gw: FakeGateway, foreign="other"):
    async def go():
        async with httpx.AsyncClient(base_url="http://fake", transport=httpx.MockTransport(gw.handle)) as c:
            return await identity.run_identity(c, "key", "owner", ["a", "b", "c"], foreign)
    return asyncio.run(go())


def test_an_isolating_gateway_reports_no_leak_and_every_row_is_present():
    rep = _run(FakeGateway())
    assert rep.tests, "no rows: the engine ran nothing"
    leaks = [t for t in rep.tests if t.leaked]
    assert not leaks, [f"{t.probe}: {t.detail}" for t in leaks]
    probes = {t.probe for t in rep.tests}
    for want in ("send to a sibling window", "sibling lists / fetches another window's mail",
                 "sibling acks another window's mail", "account-addressed mail reaches every window",
                 "one window's ack reads it for a sibling", "foreign account reads the owner's mail",
                 "foreign account addresses the window without trust"):
        assert want in probes, f"missing probe row: {want}"
    assert not any("n/a" in t.detail for t in rep.tests), "ordinary account must not produce n/a rows"


def test_a_leaking_gateway_is_reported_as_leaking():
    # The planted failure: a fake that lets every reader see every message.
    rep = _run(FakeGateway(leak=True))
    leaked = {t.probe for t in rep.tests if t.leaked}
    assert "sibling lists / fetches another window's mail" in leaked, rep.tests
    assert "sibling acks another window's mail" in leaked, rep.tests
    assert "foreign account reads the owner's mail" in leaked, rep.tests


def test_an_operator_key_yields_na_rows_not_false_leaks():
    rep = _run(FakeGateway(role="admin"))
    assert not any(t.leaked for t in rep.tests), [t for t in rep.tests if t.leaked]
    na = [t for t in rep.tests if t.detail.startswith("n/a")]
    assert len(na) >= 2, "sibling probes under an operator must be n/a, not silently passing"
    assert any("see everything by right" in n for n in rep.notes)


def test_an_unmintable_window_is_a_note_not_an_isolated_row():
    gw = FakeGateway()
    real = gw.handle

    def refuse(request):
        if request.url.path == "/api/identity/token":
            return httpx.Response(403, json={"error": "not yours"})
        return real(request)

    async def go():
        async with httpx.AsyncClient(base_url="http://fake", transport=httpx.MockTransport(refuse)) as c:
            return await identity.run_identity(c, "key", "owner", ["a", "b", "c"], None)
    rep = asyncio.run(go())
    assert not rep.tests
    assert any("could not mint" in n for n in rep.notes)


def test_scenarios_load_and_identity_carries_no_credential():
    for f in (EVAL / "scenarios").glob("*.yaml"):
        Scenario.load(f)
    s = Scenario.load(EVAL / "scenarios" / "identity.yaml")
    assert s.identity and len(s.identity.windows) >= 3 and not s.workloads
    text = (EVAL / "scenarios" / "identity.yaml").read_text()
    assert "noo-sk-" not in text and "Bearer" not in text


def test_the_package_is_named_noo_eval_and_the_demo_runs(tmp_path):
    out = tmp_path / "demo.html"
    r = subprocess.run([sys.executable, "-m", "noo_eval", "demo", "--out", str(out)],
                       cwd=EVAL, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    assert out.exists() and out.stat().st_size > 1000
    # A retired package is gone when its SOURCE is gone. A bare directory
    # outlives a rename as a __pycache__ leftover, which fails this guard on a
    # dev box while CI's fresh clone stays green — so ask for source files.
    retired = sorted(str(f.relative_to(EVAL)) for f in (EVAL / "pai_eval").rglob("*.py"))
    assert not retired, f"the retired package name is back: {retired}"
