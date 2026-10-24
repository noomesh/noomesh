# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Agent-to-agent messaging client for Python agents inside the stack
. Lives in ``noomesh`` — the core package every
Python image carries — so the worker, trellion and anything else can use
it with one import and no dependency on trellion.

Two paths, chosen per call:

- **Through the gateway** (``send``, ``inbox``, ``thread``, ``ack``): the
  cluster credential the container already holds; the gateway seals and
  opens on the agent's behalf. Works with no key at all.
- **On the bus** (``listen``): subscribe to this agent's inbox subject with
  the NATS connection the worker already has, and open sealed bodies
  with this agent's OWN key — the end-to-end path. The key pair is
  generated once and persisted under the data root; its public half is
  registered with the gateway (``register``) so senders wrap to it.

Sealing format mirrors ``gateway-rust/src/agent_crypto.rs`` exactly
(X25519 + ChaCha20-Poly1305, domain-labelled SHA-256 KDFs); the fixture
in ``gateway-rust/src/fixtures/agent_seal_vector.json`` is opened by
both sides in their test suites, which is what keeps them agreeing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

ALG = "x25519-chacha20poly1305-v1"
ALG_V2 = "x25519-chacha20poly1305-v2"
ENVELOPE_VERSION = 2
REVIEW_WRAP = "review"
SUBJECT_ROOT = "agent.msg"
KINDS = ("message", "task", "result", "ack", "note")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


MAX_ID_LEN = 128


def is_valid_id(s: str) -> bool:
    """Mirror of the gateway's ``is_valid_id``: ``[A-Za-z0-9_-]`` segments
    joined by single ``/``, at most 128 chars."""
    return (
        0 < len(s) <= MAX_ID_LEN
        and not s.startswith("/")
        and not s.endswith("/")
        and "//" not in s
        and all(c.isascii() and (c.isalnum() or c in "-_/") for c in s)
    )


def subject_token(agent: str) -> str:
    """Mirror of the gateway's ``subject_token``: ``/`` → ``.`` for a valid
    id (injective — two agents can never share a subject), the old
    squash-to-underscore for anything else (which the gateway rejects)."""
    if is_valid_id(agent):
        return agent.replace("/", ".")
    return "".join(c if (c.isalnum() or c in "-_") else "_" for c in agent)


# ── keys ────────────────────────────────────────────────────────────────────


class AgentKeys:
    """This agent's key pair (X25519 for sealing, Ed25519 for signing)."""

    def __init__(self, seal: X25519PrivateKey, sign: Ed25519PrivateKey):
        self.seal = seal
        self.sign = sign

    @classmethod
    def generate(cls) -> "AgentKeys":
        return cls(X25519PrivateKey.generate(), Ed25519PrivateKey.generate())

    @classmethod
    def from_secret(cls, secret: str) -> "AgentKeys":
        """Deterministic derivation — the same rule as the gateway's
        ``KeySet::from_secret`` (so a test can share a secret with Rust)."""
        s = secret.strip().encode()
        seal = hashlib.sha256(b"noomesh-agent-msg/x25519/v1:" + s).digest()
        sign = hashlib.sha256(b"noomesh-agent-msg/ed25519/v1:" + s).digest()
        return cls(X25519PrivateKey.from_private_bytes(seal), Ed25519PrivateKey.from_private_bytes(sign))

    @classmethod
    def load_or_create(cls, path: Path) -> "AgentKeys":
        if path.exists():
            d = json.loads(path.read_text())
            return cls(
                X25519PrivateKey.from_private_bytes(_b64d(d["x25519_private"])),
                Ed25519PrivateKey.from_private_bytes(_b64d(d["ed25519_private"])),
            )
        k = cls.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        data = json.dumps({
            "x25519_private": _b64(k.seal.private_bytes(*raw)),
            "ed25519_private": _b64(k.sign.private_bytes(*raw)),
        })
        # Created 0600 from the first byte — never world-readable, even for
        # the instant between write and chmod.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(data)
        return k

    def public_record(self) -> dict[str, str]:
        pub = serialization.Encoding.Raw, serialization.PublicFormat.Raw
        return {
            "x25519": _b64(self.seal.public_key().public_bytes(*pub)),
            "ed25519": _b64(self.sign.public_key().public_bytes(*pub)),
            "alg": ALG,
        }

    def signed_record(self, agent: str, prev: Optional["AgentKeys"] = None) -> dict[str, str]:
        """The registry record the gateway accepts: self-signed proof that
        this agent holds the Ed25519 key (``sig``), plus ``prev_sig`` under
        the key being replaced when rotating. Mirrors ``KeySet::signed_record``."""
        rec = self.public_record()
        inp = key_record_input(agent, rec["x25519"], rec["ed25519"])
        rec["sig"] = _b64(self.sign.sign(inp))
        if prev is not None:
            rec["prev_sig"] = _b64(prev.sign.sign(inp))
        return rec


def key_record_input(agent: str, x25519_b64: str, ed25519_b64: str) -> bytes:
    out = b"noomesh-agent-msg/keyreg/v1:"
    for part in (agent, x25519_b64, ed25519_b64):
        out += part.encode() + b"\x00"
    return out


def verify_key_record(agent: str, record: dict) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(_b64d(record["ed25519"]))
        pub.verify(_b64d(record["sig"]), key_record_input(agent, record["x25519"], record["ed25519"]))
        return True
    except Exception:
        return False


def _wrap_key(epk_secret: X25519PrivateKey, recipient: X25519PublicKey, label: str) -> bytes:
    """v1 wrap KDF — kept to open bodies sealed before wave B."""
    shared = epk_secret.exchange(recipient)
    return hashlib.sha256(b"noomesh-agent-msg/wrap/v1:" + shared + label.encode()).digest()


def _raw(k) -> bytes:
    return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _wrap_key_v2(
    own_secret: X25519PrivateKey,
    dh_peer: X25519PublicKey,
    epk: X25519PublicKey,
    recipient: X25519PublicKey,
    label: str,
) -> bytes:
    """v2 wrap KDF: binds the ephemeral and recipient public keys as well as
    the shared secret. Mirrors ``wrap_key_v2`` in agent_crypto.rs. A shared
    secret of all zeroes means a low-order point — refuse it."""
    shared = own_secret.exchange(dh_peer)
    if shared == b"\x00" * 32:
        raise ValueError("non-contributory key exchange (low-order point)")
    return hashlib.sha256(
        b"noomesh-agent-msg/wrap/v2:" + shared + _raw(epk) + _raw(recipient) + label.encode()
    ).digest()


def envelope_aad(env: dict) -> bytes:
    """The associated data a v2 body is sealed under. Mirrors
    ``agent_messages.rs::envelope_aad`` — ``ts`` is deliberately absent."""
    out = b"noomesh-agent-msg/aad/v2:"
    for field in ("id", "thread_id", "from", "to", "kind"):
        out += str(env.get(field, "")).encode() + b"\x00"
    return out


def signing_input_v2(env: dict) -> bytes:
    """The bytes a v2 signature covers: the whole envelope minus ``sig``, in
    canonical JSON. Mirrors ``agent_crypto.rs::signing_input_v2`` (serde_json
    orders object keys, so ``sort_keys=True`` here)."""
    body = {k: v for k, v in env.items() if k != "sig"}
    return b"noomesh-agent-msg/env/v2:" + json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def seal(body: Any, recipients: dict[str, X25519PublicKey], aad: bytes) -> tuple[dict, dict]:
    """Seal ``body`` to every recipient (v2). ``aad`` binds the ciphertext to
    its envelope — see :func:`envelope_aad`. Returns ``({"ct": …}, enc_meta)``."""
    if not recipients:
        raise ValueError("no recipients")
    msg_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
    ct = ChaCha20Poly1305(msg_key).encrypt(nonce, plaintext, aad)
    epk_secret = X25519PrivateKey.generate()
    epk_pub = epk_secret.public_key()
    wraps = {}
    for label, key in recipients.items():
        wk = _wrap_key_v2(epk_secret, key, epk_pub, key, label)
        wraps[label] = _b64(ChaCha20Poly1305(wk).encrypt(b"\x00" * 12, msg_key, label.encode()))
    return {"ct": _b64(ct)}, {"alg": ALG_V2, "epk": _b64(_raw(epk_pub)), "nonce": _b64(nonce), "wraps": wraps}


def open_sealed(body: dict, enc_meta: dict, label: str, secret: X25519PrivateKey, aad: bytes = b"") -> Any:
    """Open a sealed body as ``label``. ``aad`` is the envelope binding for v2
    bodies; v1 bodies (sealed before wave B) authenticate against the
    algorithm string and ignore it."""
    alg = enc_meta.get("alg")
    if alg not in (ALG, ALG_V2):
        raise ValueError(f"unknown sealing algorithm {alg!r}")
    v2 = alg == ALG_V2
    epk = X25519PublicKey.from_public_bytes(_b64d(enc_meta["epk"]))
    wrapped = _b64d(enc_meta["wraps"][label])
    if v2:
        wk = _wrap_key_v2(secret, epk, epk, secret.public_key(), label)
    else:
        wk = _wrap_key(secret, epk, label)
    msg_key = ChaCha20Poly1305(wk).decrypt(b"\x00" * 12, wrapped, label.encode())
    body_aad = aad if v2 else ALG.encode()
    plaintext = ChaCha20Poly1305(msg_key).decrypt(_b64d(enc_meta["nonce"]), _b64d(body["ct"]), body_aad)
    return json.loads(plaintext)


def signing_input(env: dict) -> bytes:
    out = b""
    for part in (env["id"], env["thread_id"], env["from"], env["to"], env["kind"], env["ts"]):
        out += part.encode() + b"\x00"
    out += json.dumps(env["body"], separators=(",", ":"), ensure_ascii=False).encode()
    return out


def verify_signature(env: dict, signer: Ed25519PublicKey) -> bool:
    """v2 envelopes are signed over the whole canonical envelope; v1 over the
    six identifying fields plus the body."""
    try:
        inp = signing_input_v2(env) if int(env.get("v", 1)) >= 2 else signing_input(env)
        signer.verify(_b64d(env["sig"]), inp)
        return True
    except Exception:
        return False


# ── client ──────────────────────────────────────────────────────────────────


class AgentMessenger:
    """One agent identity inside the stack.

    ``agent`` is the short id senders address (e.g. ``worker/ingest``);
    ``harness`` names the software. Keys live at
    ``$NOO_DATA_DIR/agent-keys/<agent>.json`` (the in-container ``noo-data``
    mount, ``/data`` by default) unless ``key_path`` is given. The HOST data
    root (``NOO_DATA_ROOT``) is never used: it is not mounted in the stack's
    containers, so keys written there would sit on the container's
    ephemeral layer and be regenerated on every recreate.
    """

    def __init__(self, agent: str, harness: str = "noomesh-worker", key_path: Optional[Path] = None):
        if not is_valid_id(agent):
            raise ValueError(f"agent id {agent!r} is not valid: letters, digits, '-', '_' and single '/' separators")
        self.agent = agent
        self.harness = harness
        if key_path is None:
            data_dir = Path(os.getenv("NOO_DATA_DIR", "/data"))
            if not data_dir.is_dir():
                # Visible, not a silent fallback to an ephemeral path: a key
                # that is lost on restart breaks the registered identity.
                raise RuntimeError(
                    f"agent key directory root {data_dir} is not mounted; set NOO_DATA_DIR to the "
                    "noo-data mount or pass key_path"
                )
            key_path = data_dir / "agent-keys" / f"{subject_token(agent)}.json"
        self.keys = AgentKeys.load_or_create(key_path)
        self._review_sign: Optional[Ed25519PublicKey] = None

    # -- gateway path --
    @staticmethod
    def _headers() -> dict[str, str]:
        """The one door — this is a call to the GATEWAY.

        It used to mint its own token, reasoning that the node-agent token
        must not come first because the gateway does not accept it inbound.
        That reasoning was about `_node_agent_headers`, not about this door,
        which never offers the node-agent token: it prefers this container's
        own NOO_GATEWAY_KEY and presents nothing else (the shared-HMAC fallback
        is retired).
        Reading NOO_CLUSTER_SECRET alone also meant no header at all on a
        controller that carries only NOO_CONTROLLER_SECRET.
        """
        from ..cluster.cluster_auth import internal_gateway_headers  # noqa: PLC0415

        return internal_gateway_headers("gateway")

    def _client(self):
        from ..gateway.helpers import _local_gateway_url  # noqa: PLC0415
        from ..tls_ca import require_ca  # noqa: PLC0415
        import httpx  # noqa: PLC0415

        # A CA is REQUIRED (NOO_TLS_CA, else the install's standard path):
        # no CA raises TlsCaMissing naming the setting; verification is never switched off
        # and no silent system-store fallback.
        return httpx.Client(base_url=_local_gateway_url(), headers=self._headers(), verify=require_ca(), timeout=15)

    def register(self, prev: Optional[AgentKeys] = None) -> dict:
        """Register this agent's public keys (self-signed). Pass ``prev`` —
        the keys being replaced — when rotating; without it the gateway
        refuses to overwrite a different registered key."""
        with self._client() as c:
            r = c.put(f"/api/agents/keys/{self.agent}", json=self.keys.signed_record(self.agent, prev))
            r.raise_for_status()
            return r.json()

    def review_signing_key(self) -> Optional[Ed25519PublicKey]:
        """The controller's signing key, fetched once — what every
        gateway-published envelope is signed with. ``None`` when the
        controller has no review key (plaintext mode)."""
        if self._review_sign is None:
            with self._client() as c:
                r = c.get("/api/agents/keys/review")
                if r.status_code == 404:
                    return None
                r.raise_for_status()
                self._review_sign = Ed25519PublicKey.from_public_bytes(_b64d(r.json()["ed25519"]))
        return self._review_sign

    def send(self, to: str, text: Optional[str] = None, body: Optional[dict] = None, kind: str = "message",
             thread_id: Optional[str] = None, refs: Optional[list[str]] = None) -> dict:
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        payload: dict[str, Any] = {"from": self.agent, "to": to, "kind": kind, "refs": refs or [],
                                   "agent": self.agent, "harness": self.harness}
        if body is not None:
            payload["body"] = body
        elif text is not None:
            payload["text"] = text
        else:
            raise ValueError("text or body is required")
        if thread_id:
            payload["thread_id"] = thread_id
        with self._client() as c:
            r = c.post("/api/agents/messages", json=payload)
            r.raise_for_status()
            return r.json()

    def inbox(self, unread: bool = False, limit: int = 50, thread: Optional[str] = None) -> list[dict]:
        params: dict[str, Any] = {"to": self.agent, "limit": limit}
        if unread:
            params["unread"] = "true"
        if thread:
            params["thread"] = thread
        with self._client() as c:
            r = c.get("/api/agents/messages", params=params)
            r.raise_for_status()
            return r.json().get("messages", [])

    def thread(self, thread_id: str) -> list[dict]:
        rows = self.inbox(limit=500, thread=thread_id)
        return list(reversed(rows))

    def ack(self, message_id: str) -> None:
        with self._client() as c:
            c.post(f"/api/agents/messages/{message_id}/ack").raise_for_status()

    # -- bus path (end-to-end) --
    def inbox_subject(self) -> str:
        return f"{SUBJECT_ROOT}.direct.{subject_token(self.agent)}"

    def open(self, env: dict) -> dict:
        """Open a sealed envelope addressed to this agent, in place. Only
        envelopes actually addressed to this agent are opened — a wrap
        under our key on a message addressed elsewhere is a forward we did
        not ask for."""
        enc = env.get("enc", "none")
        if enc == "none" or env.get("to") != self.agent:
            return env
        meta = env.get("enc_meta") or {}
        if self.agent in meta.get("wraps", {}):
            env["body"] = open_sealed(env["body"], meta, self.agent, self.keys.seal, envelope_aad(env))
            env["opened_by"] = self.agent
        return env

    def accept(self, env: Any, signer: Optional[Ed25519PublicKey]) -> bool:
        """Is this bus message one the gateway published? With a signer
        (the controller's key) every envelope must be sealed and carry a
        signature that verifies — anything else was written straight onto
        the bus by something holding the NATS credential and is dropped.
        Without a signer (plaintext mode) shape is all that can be checked."""
        if not isinstance(env, dict) or env.get("to") != self.agent:
            return False
        if signer is None:
            return True
        return env.get("enc", "none") != "none" and bool(env.get("sig")) and verify_signature(env, signer)

    async def listen(self, messaging, handler: Callable[[dict], Awaitable[None]]) -> None:
        """Subscribe on the bus (``messaging`` = the worker's ``ClusterMessaging``,
        already connected) and hand every verified envelope addressed to this
        agent to ``handler``, opened when it was wrapped to this agent's key."""
        signer = self.review_signing_key()

        async def on_msg(msg):
            try:
                env = json.loads(msg.data)
            except Exception:
                return
            if not self.accept(env, signer):
                return
            await handler(self.open(env))

        await messaging.nc.subscribe(self.inbox_subject(), cb=on_msg)
