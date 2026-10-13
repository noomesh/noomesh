# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The worker refuses a `worker.*` message it cannot attribute.

an earlier changef R31/R32. The bus grant (#100) confined `worker.>` publish to
the gateway; it could not say anything about a particular message, and every
handler took `user_id` / `_requester` out of the body it was handed.

These tests drive :mod:`noomesh.gateway.bus_principal` directly and through
``worker_pool._handle_request``, with a fake NATS message. Every one of them
FAILS on the pre-change code — before this, `_handle_request` decoded and
dispatched, so "unsigned is refused" had nothing to refuse it.

No bus, no gateway, no Rust toolchain: the signer is 15 lines of hmac, so the
cross-language contract is pinned by reproducing it here (`_sign`) rather
than by standing up a gateway. If the Rust side changes the wire format,
``test_bus_principal_parity.py`` is what notices.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from noomesh.gateway import bus_principal as bp

# One key per audience. This process is the `worker`.
KEYS = {"worker": "worker-bus-key", "trellion": "trellion-bus-key", "trellion-intel": "intel-bus-key"}
CONTROLLER_SECRET = "test-controller-secret"


# ── The signer, as the Rust gateway does it ───────────────────────────


def _sign(
    *,
    sub: str = "alice",
    kind: str = "user",
    role: str = "user",
    scopes: "list[str] | None" = None,
    subj: str = "worker.rag.query",
    iat: "float | None" = None,
    ttl: int = 60,
    nonce: str = "",
    keys: "dict[str, str] | None" = None,
    legacy_secret: "str | None" = None,
) -> str:
    iat = time.time() if iat is None else iat
    claims = {
        "sub": sub,
        "kind": kind,
        "role": role,
        "scopes": scopes if scopes is not None else ["read"],
        "subj": subj,
        "iat": int(iat),
        "exp": int(iat) + ttl,
        "nonce": nonce or f"n{time.time_ns()}",
    }
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    if legacy_secret is not None:
        # The pre-702 format: one bare MAC under the shared controller secret.
        return f"{body}.{hmac.new(legacy_secret.encode(), body.encode(), hashlib.sha256).hexdigest()}"
    macs = [
        f"{aud}={hmac.new(key.encode(), f'{aud}.{body}'.encode(), hashlib.sha256).hexdigest()}"
        for aud, key in (KEYS if keys is None else keys).items()
    ]
    return f"{body}.{','.join(macs)}"


def _own(token: str) -> "tuple[str, str]":
    """(body, the worker's MAC)."""
    body, _, sigs = token.partition(".")
    return body, dict(e.split("=", 1) for e in sigs.split(","))["worker"]


class FakeMsg:
    """The bits of a nats.aio Msg the worker pool touches."""

    def __init__(self, subject: str, data: dict, headers: "dict | None" = None):
        self.subject = subject
        self.data = json.dumps(data).encode()
        self.headers = headers
        self.reply = "_INBOX.test"
        self.responses: "list[dict]" = []

    async def respond(self, payload: bytes) -> None:
        self.responses.append(json.loads(payload.decode()))


@pytest.fixture(autouse=True)
def _worker_env(monkeypatch):
    monkeypatch.setenv("NOO_BUS_KEY", KEYS["worker"])
    monkeypatch.setenv("NOO_BUS_AUDIENCE", "worker")
    # Present on purpose: the verifier must not read it.
    monkeypatch.setenv("NOO_CONTROLLER_SECRET", CONTROLLER_SECRET)
    bp.reset_nonce_cache()
    yield
    bp.reset_nonce_cache()


# ── The four refusals ─────────────────────────────────────────────────


def test_unsigned_is_refused():
    """No header at all. There is no mode to fall back on."""
    with pytest.raises(bp.PrincipalError) as exc:
        bp.verify_message(None, "worker.tool.generic")
    assert exc.value.reason == "missing"


def test_a_bad_signature_is_refused():
    body, sig = _own(_sign())
    forged = f"{body}.worker={'0' * len(sig)}"
    with pytest.raises(bp.PrincipalError) as exc:
        bp.verify_token(forged, "worker.rag.query")
    assert exc.value.reason == "bad_signature"


def test_a_token_signed_with_another_key_is_refused():
    token = _sign(keys={"worker": "not-the-worker-key"})
    with pytest.raises(bp.PrincipalError) as exc:
        bp.verify_token(token, "worker.rag.query")
    assert exc.value.reason == "bad_signature"


def test_an_expired_token_is_refused():
    token = _sign(iat=time.time() - 600)
    with pytest.raises(bp.PrincipalError) as exc:
        bp.verify_token(token, "worker.rag.query")
    assert exc.value.reason == "expired"


def test_a_token_from_the_future_is_refused():
    token = _sign(iat=time.time() + 600)
    with pytest.raises(bp.PrincipalError) as exc:
        bp.verify_token(token, "worker.rag.query")
    assert exc.value.reason == "not_yet_valid"


def test_a_replayed_token_is_refused():
    token = _sign(nonce="replay-me")
    assert bp.verify_token(token, "worker.rag.query").sub == "alice"
    with pytest.raises(bp.PrincipalError) as exc:
        bp.verify_token(token, "worker.rag.query")
    assert exc.value.reason == "replay"


def test_a_principal_cannot_be_lifted_onto_another_subject():
    """The cheap-subject-to-expensive-subject move, inside the window."""
    token = _sign(subj="worker.memory.search")
    with pytest.raises(bp.PrincipalError) as exc:
        bp.verify_token(token, "worker.tool.generic")
    assert exc.value.reason == "wrong_subject"


def test_a_worker_with_no_key_refuses_rather_than_accepts(monkeypatch):
    monkeypatch.delenv("NOO_BUS_KEY", raising=False)
    with pytest.raises(bp.PrincipalError) as exc:
        bp.verify_token(_sign(), "worker.rag.query")
    assert exc.value.reason == "no_key"


def test_a_worker_with_no_audience_refuses_rather_than_accepts(monkeypatch):
    monkeypatch.delenv("NOO_BUS_AUDIENCE", raising=False)
    with pytest.raises(bp.PrincipalError) as exc:
        bp.verify_token(_sign(), "worker.rag.query")
    assert exc.value.reason == "no_key"


# ── the shared controller secret is refused ──────────


def test_the_controller_secret_format_is_refused_even_with_the_secret_at_hand():
    """THE retirement. A principal signed the pre-702 way — one bare MAC
    under NOO_CONTROLLER_SECRET, which this process even has in its env — is
    refused. Before an earlier change this exact token verified."""
    token = _sign(legacy_secret=CONTROLLER_SECRET)
    with pytest.raises(bp.PrincipalError) as exc:
        bp.verify_token(token, "worker.rag.query")
    assert exc.value.reason == "legacy_signature"


def test_the_controller_secret_under_the_new_format_is_refused():
    """Nor does the controller secret work as the worker's key."""
    token = _sign(keys={"worker": CONTROLLER_SECRET})
    with pytest.raises(bp.PrincipalError) as exc:
        bp.verify_token(token, "worker.rag.query")
    assert exc.value.reason == "bad_signature"


def test_a_leaked_add_on_key_forges_nothing_for_the_worker():
    """Trellion's key exposes trellion only: a MAC for its own audience is
    not one the worker reads, and its key under the worker's label fails."""
    only_trellion = _sign(keys={"trellion": KEYS["trellion"]})
    with pytest.raises(bp.PrincipalError) as exc:
        bp.verify_token(only_trellion, "worker.rag.query")
    assert exc.value.reason == "no_audience"
    relabelled = _sign(keys={"worker": KEYS["trellion"]})
    with pytest.raises(bp.PrincipalError) as exc:
        bp.verify_token(relabelled, "worker.rag.query")
    assert exc.value.reason == "bad_signature"


def test_each_audience_verifies_its_own_mac(monkeypatch):
    """The same header serves every verifier, each with its own key."""
    token = _sign(nonce="shared-header")
    for aud, key in KEYS.items():
        bp.reset_nonce_cache()
        monkeypatch.setenv("NOO_BUS_KEY", key)
        monkeypatch.setenv("NOO_BUS_AUDIENCE", aud)
        assert bp.verify_token(token, "worker.rag.query").sub == "alice", aud


def test_the_verifier_reads_no_controller_secret():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(bp))
    consts = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)]
    assert "NOO_CONTROLLER_SECRET" not in consts


def test_a_truncated_signature_is_refused():
    """The cluster token's 32-char legacy width is not inherited here."""
    body, sig = _own(_sign())
    with pytest.raises(bp.PrincipalError) as exc:
        bp.verify_token(f"{body}.worker={sig[:32]}", "worker.rag.query")
    assert exc.value.reason == "bad_signature"


# ── The payload stops being authoritative ─────────────────────────────


def test_a_payload_user_id_that_disagrees_is_refused():
    """R32: the tenant was the publisher's to choose."""
    principal = bp.verify_token(_sign(sub="alice"), "worker.rag.query")
    with pytest.raises(bp.PrincipalError) as exc:
        bp.apply_to_request({"user_id": "bob", "query": "x"}, principal)
    assert exc.value.reason == "user_id_mismatch"


def test_a_payload_user_id_inside_params_is_refused_too():
    principal = bp.verify_token(_sign(sub="alice"), "worker.rag.query")
    with pytest.raises(bp.PrincipalError):
        bp.apply_to_request({"params": {"user_id": "bob"}}, principal)


def test_the_header_replaces_the_payload_identity():
    principal = bp.verify_token(_sign(sub="alice", scopes=["read"]), "worker.rag.query")
    out = bp.apply_to_request(
        {"params": {"_requester": {"sub": "root", "scopes": ["admin"]}}}, principal
    )
    assert out["params"]["_requester"] == {
        "sub": "alice",
        "scopes": ["read"],
        "role": "user",
    }
    assert out["user_id"] == "alice"
    assert bp.tenant_of(out) == "alice"


def test_an_internal_principal_may_still_name_the_user_it_acts_for():
    """The heartbeat runs a task owned by somebody. That has to keep working."""
    principal = bp.verify_token(
        _sign(
            sub="internal:heartbeat",
            kind="internal",
            scopes=["read", "write"],
            subj="worker.api.heartbeat.run",
        ),
        "worker.api.heartbeat.run",
    )
    out = bp.apply_to_request({"user_id": "alice"}, principal)
    assert bp.tenant_of(out) == "alice"
    # …but it does not get to be an admin because the body said so.
    assert out["_requester"]["scopes"] == ["read", "write"]


def test_an_internal_principal_is_not_admin_even_if_the_body_claims_it():
    principal = bp.verify_token(
        _sign(
            sub="internal:autonomy",
            kind="internal",
            scopes=["read"],
            subj="worker.autonomy.check_rag",
        ),
        "worker.autonomy.check_rag",
    )
    out = bp.apply_to_request(
        {"_requester": {"sub": "x", "scopes": ["admin"]}}, principal
    )
    assert not bp.of(out).is_admin
    assert not bp.of(out).kb_unrestricted


def test_kb_unrestricted_is_a_scope_not_an_absence():
    unrestricted = bp.verify_token(
        _sign(sub="internal:heartbeat", kind="internal", scopes=["read", "kb:unrestricted"]),
        "worker.rag.query",
    )
    plain = bp.verify_token(
        _sign(sub="internal:hooks", kind="internal", scopes=["read"], nonce="x2"),
        "worker.rag.query",
    )
    assert unrestricted.kb_unrestricted
    assert not plain.kb_unrestricted


# ── kb.py: absent principal is a refusal, not the whole corpus ────────


def test_kb_roles_refuse_a_request_with_no_principal():
    from noomesh.workers.kb import _resolve_kb_roles

    with pytest.raises(PermissionError):
        _resolve_kb_roles({})


def test_kb_roles_are_unrestricted_only_for_a_verified_admin():
    from noomesh.workers.kb import _resolve_kb_roles

    admin = bp.verify_token(_sign(sub="root", scopes=["admin"]), "worker.rag.query")
    assert _resolve_kb_roles(bp.apply_to_request({}, admin)) is None

    reader = bp.verify_token(
        _sign(sub="alice", scopes=["read"], nonce="r2"), "worker.rag.query"
    )
    roles = _resolve_kb_roles(bp.apply_to_request({}, reader))
    assert roles is not None, "a read-scope user must not get the whole corpus"
    assert "user:alice" in roles


def test_kb_roles_ignore_an_admin_claim_in_the_body():
    """The exact R32 line: `"admin" in scopes` read out of the payload."""
    from noomesh.workers.kb import _resolve_kb_roles

    reader = bp.verify_token(
        _sign(sub="alice", scopes=["read"]), "worker.rag.query"
    )
    request = bp.apply_to_request(
        {"_requester": {"sub": "alice", "scopes": ["admin"]}}, reader
    )
    # The body was overwritten, so even a handler that still reads
    # `_requester` cannot be fooled.
    assert request["_requester"]["scopes"] == ["read"]
    assert _resolve_kb_roles(request) is not None


# ── The worker pool gate ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_worker_pool_refuses_an_unsigned_message():
    from noomesh.gateway import worker_pool

    msg = FakeMsg("worker.tool.generic", {"name": "noo_config_set", "arguments": {}})
    await worker_pool._handle_request(msg)

    assert msg.responses, "a refused message must still get a reply"
    reply = msg.responses[0]
    assert reply["success"] is False
    assert "principal" in reply["error"]


@pytest.mark.asyncio
async def test_the_worker_pool_refuses_a_forged_message():
    from noomesh.gateway import worker_pool

    token = _sign(subj="worker.tool.generic")
    body, _, sig = token.partition(".")
    msg = FakeMsg(
        "worker.tool.generic",
        {"name": "noo_config_set"},
        headers={bp.HEADER: f"{body}.{'f' * 64}"},
    )
    await worker_pool._handle_request(msg)
    assert msg.responses[0]["success"] is False


@pytest.mark.asyncio
async def test_the_worker_pool_serves_a_signed_message():
    """The rail must not be a wall: a properly signed message still runs."""
    from noomesh.gateway import worker_pool
    from noomesh.workers.registry import _REGISTRY

    seen: dict = {}

    async def _handler(request):
        seen.update(request)
        return {"ok": True}

    subject = "worker.test.principal"
    _REGISTRY[subject] = _handler
    try:
        msg = FakeMsg(
            subject,
            {"query": "x"},
            headers={bp.HEADER: _sign(sub="alice", subj=subject)},
        )
        await worker_pool._handle_request(msg)
    finally:
        _REGISTRY.pop(subject, None)

    assert msg.responses[0]["success"] is True
    assert seen["_requester"]["sub"] == "alice"


@pytest.mark.asyncio
async def test_the_retired_optional_mode_does_not_let_an_unsigned_message_through(monkeypatch):
    """`NOO_BUS_PRINCIPAL=optional` was a one-release bridge and is retired.

    A worker that still has it in its environment must refuse exactly as if
    it were absent (the gateway refuses to BOOT with it open; the worker
    simply has no code that reads it).
    """
    from noomesh.gateway import worker_pool
    from noomesh.workers.registry import _REGISTRY

    monkeypatch.setenv("NOO_BUS_PRINCIPAL", "optional")
    subject = "worker.test.principal"
    ran = []

    async def _handler(request):
        ran.append(request)
        return {"ok": True}

    _REGISTRY[subject] = _handler
    try:
        msg = FakeMsg(subject, {"query": "x"})
        await worker_pool._handle_request(msg)
    finally:
        _REGISTRY.pop(subject, None)
    assert msg.responses, "the worker must answer the refusal, not drop it"
    assert msg.responses[0]["success"] is False
    assert ran == [], "an unsigned message reached the handler"
    assert not hasattr(bp, "mode"), "the retired mode switch is back"


def test_the_header_is_found_whatever_case_it_arrives_in():
    """Getting this wrong refuses EVERY message, which reads as an outage."""
    token = _sign(subj="worker.rag.query")
    for name in (bp.HEADER, bp.HEADER.lower(), bp.HEADER.upper()):
        bp.reset_nonce_cache()
        assert bp.verify_message({name: token}, "worker.rag.query").sub == "alice"


def test_the_nonce_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(bp, "NONCE_MAX", 16)
    now = time.time()
    for i in range(200):
        assert bp._remember_nonce(f"n{i}", now)
    assert len(bp._NONCES) <= 16


# ── The approval row binds to the turn the envelope names (§3f R41) ───
#
# The producer half of R41 is in `tools.rs`; this is the worker end. Without
# it, deleting the ImportError guard could leave the binding not happening
# and nothing would say so — an approval row written all-NULL looks exactly
# like an unattended turn, which is a legitimate state.


@pytest.mark.asyncio
async def test_a_tool_call_binds_the_approval_row_to_its_turn(monkeypatch):
    from noomesh.gateway import exec_approval
    from noomesh.workers import tools as wtools

    seen = {}

    async def _fake_call_tool(name, args):
        # Read it where an approval would be raised: inside the dispatch.
        seen["principal"] = exec_approval.turn_principal()
        return "ok"

    monkeypatch.setattr(
        "noomesh.mcp.tool_models.get_tool_class", lambda name: object
    )
    monkeypatch.setattr("noomesh.mcp.tool_models.call_tool", _fake_call_tool)

    principal = bp.verify_token(
        _sign(sub="alice", subj="worker.tool.generic"), "worker.tool.generic"
    )
    request = bp.apply_to_request(
        {
            "name": "python_exec",
            "arguments": {
                # The model's attempt to bind the row to someone else's chat.
                "conversation_id": "victims-conversation",
                "channel": "telegram",
            },
            # Gateway-authored, beside `arguments` (tools.rs::tool_envelope).
            "conversation_id": "conv-1",
            "channel": "google_chat",
            # The gateway attaches one for every user dispatch (followup
            # 1266); without it the handler refuses before binding anything.
            "delegated_token": "gateway-minted-token",
        },
        principal,
    )
    await wtools._tool_generic(request)

    got = seen["principal"]
    assert got.requester == "alice", "the verified principal did not reach the row"
    assert got.conversation_id == "conv-1"
    assert got.channel == "google_chat"
    assert got.bound


@pytest.mark.asyncio
async def test_the_binding_does_not_leak_past_the_dispatch(monkeypatch):
    """A ContextVar left set would bind the NEXT tool call to this turn."""
    from noomesh.gateway import exec_approval
    from noomesh.workers import tools as wtools

    async def _boom(name, args):
        raise RuntimeError("tool blew up")

    monkeypatch.setattr(
        "noomesh.mcp.tool_models.get_tool_class", lambda name: object
    )
    monkeypatch.setattr("noomesh.mcp.tool_models.call_tool", _boom)

    principal = bp.verify_token(
        _sign(sub="alice", subj="worker.tool.generic"), "worker.tool.generic"
    )
    request = bp.apply_to_request(
        {"name": "python_exec", "arguments": {}, "conversation_id": "conv-1",
         "delegated_token": "gateway-minted-token"},
        principal,
    )
    # The dispatch ladder swallows tool errors, so this returns rather than raises.
    await wtools._tool_generic(request)
    assert not exec_approval.turn_principal().bound, (
        "the turn principal survived the dispatch — the next tool call in this "
        "worker would raise an approval bound to somebody else's conversation"
    )


# ── Review L5 / L7 ────────────────────────────────────────────────────


#: The known-answer vector, shared with gateway-rust/src/bus_principal.rs
#: (`the_mac_matches_the_known_answer_vector`). Both runtimes must produce
#: exactly this for mac("trellion", key, body).
KAT_KEY, KAT_AUD, KAT_BODY = "kat-key-0123456789abcdef", "trellion", "eyJzdWIiOiJrYXQifQ"
KAT_MAC = "3327620662d8835fbe27e8595ef9f10050d3477175dbb98a1644d0604140af2f"


def test_the_mac_matches_the_known_answer_vector(monkeypatch):
    got = hmac.new(KAT_KEY.encode(), f"{KAT_AUD}.{KAT_BODY}".encode(), hashlib.sha256).hexdigest()
    assert got == KAT_MAC
    # And the verifier itself computes it: a token carrying exactly this MAC
    # gets past the signature check (it then fails on the claims, which are
    # not a real principal — the point is the reason is not bad_signature).
    monkeypatch.setenv("NOO_BUS_KEY", KAT_KEY)
    monkeypatch.setenv("NOO_BUS_AUDIENCE", KAT_AUD)
    with pytest.raises(bp.PrincipalError) as exc:
        bp.verify_token(f"{KAT_BODY}.{KAT_AUD}={KAT_MAC}", "worker.rag.query")
    assert exc.value.reason != "bad_signature", exc.value.reason


def test_a_non_ascii_mac_is_a_refusal_not_an_exception():
    body, sig = _own(_sign())
    forged = f"{body}.worker={'é' * 64}"
    with pytest.raises(bp.PrincipalError) as exc:
        bp.verify_token(forged, "worker.rag.query")
    assert exc.value.reason == "bad_signature"
