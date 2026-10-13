# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Identity-plane probes: windows under one account, and accounts against
each other.

Every probe is one :class:`IsolationTest` row: *user_a* holds something,
*user_b* tries to reach it, and ``leaked`` says whether it could. The rows
render in the report's isolation matrix next to the memory probes, because
they are the same control (H-D1, tenant isolation) asked of a different
surface — agent mail — where the answer is exact rather than statistical.

Credentials never live in a scenario file. The probe engine takes one
``identity``-scoped service key (``NOO_EVAL_IDENTITY_KEY``) and mints every
identity it needs through ``POST /api/identity/token``:

* a **window** is a connection subject ``<owner>/<label>`` — the same name
  the MCP doors mint per session, without needing an MCP client here;
* a **foreign** party is an account subject the key may mint but does not
  own, so it stands outside the owner's boundary.

A window inherits its account's ROLE. An operator's windows read and ack
everything by right, so the sibling probes under an operator key would
report LEAK for the wrong reason. The engine reads the minted token's role
and marks those probes ``n/a`` with the reason instead — an eval that
cannot tell "privileged" from "leaking" is not measuring isolation.
"""
from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass, field

import httpx

from .schema import IsolationTest

TOKEN_PATH = "/api/identity/token"
CONNECTION_TYPE = "urn:noomesh:params:oauth:token-type:connection"
PRIVILEGED_ROLES = {"admin", "operator"}


def _claims(jwt: str) -> dict:
    """The payload of a JWT, unverified — we only read our own freshly
    minted token's ``role`` to decide which probes mean anything."""
    try:
        seg = jwt.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg))
    except Exception:
        return {}


@dataclass
class Identity:
    name: str
    token: str
    account: str
    role: str = ""

    @property
    def privileged(self) -> bool:
        return self.role in PRIVILEGED_ROLES


@dataclass
class ProbeReport:
    tests: list[IsolationTest] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def row(self, a: str, b: str, probe: str, leaked: bool, detail: str = "") -> None:
        self.tests.append(IsolationTest(user_a=a, user_b=b, probe=probe, leaked=leaked, detail=detail))


class IdentityProbes:
    """Drive the probes over an ``httpx.AsyncClient`` already pointed at the
    gateway. The client is injected so a test can stand in a fake gateway
    with ``httpx.MockTransport`` and PLANT a leak — a probe engine that has
    never been seen to report LEAK has not been tested."""

    def __init__(self, client: httpx.AsyncClient, key: str):
        self.client = client
        self.key = key
        self.report = ProbeReport()

    # ── minting ──────────────────────────────────────────────────────────
    async def _mint(self, subject: str, connection: bool) -> Identity | None:
        body = {"subject_token": subject}
        if connection:
            body["subject_token_type"] = CONNECTION_TYPE
        r = await self.client.post(TOKEN_PATH, json=body,
                                   headers={"Authorization": f"Bearer {self.key}"})
        if r.status_code != 200:
            self.report.notes.append(f"could not mint '{subject}': HTTP {r.status_code} {r.text[:120]}")
            return None
        data = r.json()
        tok = data.get("access_token", "")
        return Identity(name=data.get("subject") or subject, token=tok,
                        account=data.get("account") or subject.split("/")[0],
                        role=str(_claims(tok).get("role", "")))

    async def window(self, owner: str, label: str) -> Identity | None:
        return await self._mint(f"{owner}/{label}", connection=True)

    async def account(self, name: str) -> Identity | None:
        return await self._mint(name, connection=False)

    # ── primitives ───────────────────────────────────────────────────────
    def _auth(self, who: Identity) -> dict:
        return {"Authorization": f"Bearer {who.token}"}

    async def send(self, frm: Identity, to: str, text: str) -> tuple[int, str]:
        r = await self.client.post("/api/agents/messages", json={"to": to, "text": text},
                                   headers=self._auth(frm))
        mid = ""
        if r.status_code == 200:
            try:
                mid = r.json().get("message", {}).get("id", "")
            except Exception:
                mid = ""
        return r.status_code, mid

    async def sees(self, who: Identity, mid: str, unread_only: bool = False) -> bool:
        """Does ``who``'s own listing contain message ``mid``?"""
        params = {"limit": 200}
        if unread_only:
            params["unread"] = "true"
        r = await self.client.get("/api/agents/messages", params=params, headers=self._auth(who))
        if r.status_code != 200:
            return False
        try:
            return any(m.get("id") == mid for m in r.json().get("messages", []))
        except Exception:
            return False

    async def fetch(self, who: Identity, mid: str, secret: str) -> tuple[int, bool]:
        """Direct fetch of one message: (status, body contained the secret)."""
        r = await self.client.get(f"/api/agents/messages/{mid}", headers=self._auth(who))
        return r.status_code, (secret in r.text)

    async def ack(self, who: Identity, mid: str) -> int:
        r = await self.client.post(f"/api/agents/messages/{mid}/ack", json={}, headers=self._auth(who))
        return r.status_code

    # ── the window scenario ──────────────────────────────────────────────
    async def windows_under_one_account(self, owner: str, labels: list[str]) -> None:
        """Three (or more) windows of one person: mail to a window is that
        window's alone; mail to the account reaches every window; one
        window's ack does not read it for another."""
        if len(labels) < 3:
            self.report.notes.append("identity.windows needs at least three labels (sender, recipient, bystander)")
            return
        wins = [await self.window(owner, lb) for lb in labels]
        if any(w is None for w in wins):
            return
        a, b, c = wins[0], wins[1], wins[2]
        stamp = f"eval-{uuid.uuid4().hex[:10]}"
        secret = f"{stamp}-window-secret"
        sibling_ok = not a.privileged
        if not sibling_ok:
            self.report.notes.append(
                f"{owner} is {a.role}: its windows see everything by right, so the "
                "sibling-isolation probes are marked n/a; bind the key to an ordinary account to measure them")

        # (1) window → window
        status, mid = await self.send(a, b.name, f"{secret} direct")
        if status != 200 or not mid:
            self.report.row(a.name, b.name, "send to a sibling window", leaked=False,
                            detail=f"send failed: HTTP {status} — nothing below can run")
            return
        self.report.row(a.name, b.name, "send to a sibling window", leaked=False, detail="delivered")
        self.report.row(b.name, b.name, "recipient sees its own mail, unread",
                        leaked=not await self.sees(b, mid, unread_only=True),
                        detail="present in the recipient's unread listing" if await self.sees(b, mid, True)
                        else "MISSING from the recipient's own listing")
        if sibling_ok:
            listed = await self.sees(c, mid)
            st, has_secret = await self.fetch(c, mid, secret)
            leaked = listed or (200 <= st < 300)
            self.report.row(b.name, c.name, "sibling lists / fetches another window's mail", leaked=leaked,
                            detail=f"listing={'yes' if listed else 'no'} fetch=HTTP {st}"
                                   + (" (body carried the secret)" if has_secret else ""))
            st = await self.ack(c, mid)
            self.report.row(b.name, c.name, "sibling acks another window's mail",
                            leaked=(200 <= st < 300), detail=f"ack → HTTP {st} (403 expected)")
        else:
            self.report.row(b.name, c.name, "sibling lists / fetches another window's mail",
                            leaked=False, detail=f"n/a — {owner} is {a.role}")
            self.report.row(b.name, c.name, "sibling acks another window's mail",
                            leaked=False, detail=f"n/a — {owner} is {a.role}")
        st = await self.ack(b, mid)
        self.report.row(b.name, b.name, "recipient acks its own mail", leaked=False,
                        detail=f"ack → HTTP {st}" + ("" if st == 200 else " (200 expected)"))

        # (2) window → the bare account: fan-out, read state per window
        status, fid = await self.send(a, owner, f"{stamp} fanout")
        if status != 200 or not fid:
            self.report.row(a.name, owner, "send to the bare account", leaked=False,
                            detail=f"send failed: HTTP {status}")
            return
        seen_b = await self.sees(b, fid, True)
        seen_c = await self.sees(c, fid, True)
        self.report.row(owner, f"{b.name}, {c.name}", "account-addressed mail reaches every window",
                        leaked=False,
                        detail=("both windows see it unread" if seen_b and seen_c
                                else f"NOT fanned out: b={'yes' if seen_b else 'no'} c={'yes' if seen_c else 'no'}"))
        st = await self.ack(b, fid)
        still_b = await self.sees(b, fid, True)
        still_c = await self.sees(c, fid, True)
        # The row that matters: B's ack must clear B and must NOT clear C.
        self.report.row(b.name, c.name, "one window's ack reads it for a sibling",
                        leaked=(not still_c), detail=(
                            f"after {b.name} acked (HTTP {st}): unread for b={'yes' if still_b else 'no'}, "
                            f"c={'yes' if still_c else 'no'}"))

    # ── the cross-account probe ──────────────────────────────────────────
    async def foreign_account(self, owner: str, label: str, foreign: str) -> None:
        """Somebody else's account against the owner's window: it may not
        address the window without a trust entry, and may not read the
        owner's mail."""
        w = await self.window(owner, label)
        f = await self.account(foreign)
        if w is None or f is None:
            return
        secret = f"eval-{uuid.uuid4().hex[:10]}-owner-secret"
        status, mid = await self.send(w, w.name, secret)      # a note to self, in the owner's box
        if status != 200 or not mid:
            self.report.row(w.name, f.name, "owner plants a note in its own box", leaked=False,
                            detail=f"send failed: HTTP {status}")
            return
        if f.privileged:
            self.report.notes.append(f"foreign party {foreign} is {f.role}; cross-account probes are n/a")
            self.report.row(w.name, f.name, "foreign account reads the owner's mail", leaked=False,
                            detail=f"n/a — {foreign} is {f.role}")
            return
        listed = await self.sees(f, mid)
        st, has_secret = await self.fetch(f, mid, secret)
        self.report.row(w.name, f.name, "foreign account reads the owner's mail",
                        leaked=listed or (200 <= st < 300),
                        detail=f"listing={'yes' if listed else 'no'} fetch=HTTP {st}"
                               + (" (body carried the secret)" if has_secret else ""))
        st, _ = await self.send(f, w.name, "hello from outside")
        self.report.row(w.name, f.name, "foreign account addresses the window without trust",
                        leaked=(200 <= st < 300), detail=f"send → HTTP {st} (403 expected)")

    async def accounts_against_each_other(self, personas: list[str]) -> None:
        """The H-D1 shape over agent mail: each persona plants a note in its
        own box; every other persona tries to read it. Personas must be
        accounts the key may mint; the ones it cannot are noted, never
        counted as isolated."""
        ids = {}
        for p in personas:
            who = await self.account(p)
            if who:
                ids[p] = who
        if len(ids) < 2:
            self.report.notes.append("cross-account probes need at least two mintable personas")
            return
        planted = {}
        for p, who in ids.items():
            secret = f"eval-{uuid.uuid4().hex[:10]}-{p}"
            st, mid = await self.send(who, who.name, secret)
            if st == 200 and mid:
                planted[p] = (mid, secret)
        for a, (mid, secret) in planted.items():
            for b, who_b in ids.items():
                if a == b:
                    continue
                if who_b.privileged:
                    self.report.row(a, b, "reads the other's mail", leaked=False, detail=f"n/a — {b} is {who_b.role}")
                    continue
                listed = await self.sees(who_b, mid)
                st, has_secret = await self.fetch(who_b, mid, secret)
                self.report.row(a, b, "reads the other's mail", leaked=listed or (200 <= st < 300),
                                detail=f"listing={'yes' if listed else 'no'} fetch=HTTP {st}"
                                       + (" (body carried the secret)" if has_secret else ""))


async def run_identity(client: httpx.AsyncClient, key: str, owner: str, windows: list[str],
                       foreign: str | None) -> ProbeReport:
    eng = IdentityProbes(client, key)
    t0 = time.monotonic()
    await eng.windows_under_one_account(owner, windows)
    if foreign:
        await eng.foreign_account(owner, windows[0], foreign)
    eng.report.notes.append(f"identity probes: {len(eng.report.tests)} row(s) in {time.monotonic() - t0:.1f}s")
    return eng.report


async def run_cross_account(client: httpx.AsyncClient, key: str, personas: list[str]) -> ProbeReport:
    eng = IdentityProbes(client, key)
    await eng.accounts_against_each_other(personas)
    return eng.report
