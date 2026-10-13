#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Regenerate the cross-language agent-messaging seal vectors.

Rebuilds ``gateway-rust/src/fixtures/agent_seal_vector.json`` (v1) and
``gateway-rust/src/fixtures/agent_seal_vector_v2.json`` (v2) from the
Python implementation in ``noomesh.agents.messaging`` — the same module
whose ``seal``/``signing_input``/``signing_input_v2`` the Rust side
(``gateway-rust/src/agent_crypto.rs``) mirrors byte-for-byte.

Both files are deterministic EXCEPT for the ephemeral X25519 key (``epk``)
and the ChaCha20-Poly1305 ``nonce`` inside ``enc_meta`` — those are fresh
random values on every run (that is the whole point of an ephemeral key),
so the ``ct`` and ``wraps`` ciphertexts also change from run to run. The
secrets, plaintext, envelope shape, recipient id and signature all stay
fixed, since they are derived deterministically from the secrets and the
envelope bytes.

The recipient id used is ``node-a/claude-code-1`` — a placeholder, never a
real fleet hostname, because the OSS sync rewrites fleet hostnames in the
published tree and this id sits under both the AEAD wrap label and the
envelope signature.

Run: ``python3 scripts/gen-agent-seal-vectors.py``
"""

from __future__ import annotations

import base64
import json
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from noomesh.agents.messaging import (  # noqa: E402
    ALG,
    REVIEW_WRAP,
    AgentKeys,
    _raw,
    _wrap_key,
    envelope_aad,
    seal,
    signing_input,
    signing_input_v2,
)

RECIPIENT = "node-a/claude-code-1"

CONTROLLER_SECRET = "controller-review-secret-with-enough-entropy-0123"
AGENT_SECRET = "agent-secret-with-enough-entropy-abcdefghijklmn"
SIGNING_SECRET = "controller-signing-secret-with-enough-entropy-9876"

FIXTURES = REPO / "gateway-rust/src/fixtures"


def gen_v1() -> dict:
    """v1 vector: insertion-order keys, 1-space indent, no trailing newline
    — the format the existing ``agent_seal_vector.json`` is in."""
    ctrl = AgentKeys.from_secret(CONTROLLER_SECRET)
    agent = AgentKeys.from_secret(AGENT_SECRET)
    plaintext = {"text": "cross-language vector", "n": 7}
    recipients = {REVIEW_WRAP: ctrl.seal.public_key(), RECIPIENT: agent.seal.public_key()}

    # v1 sealing (pre wave-B): the wrap KDF is `_wrap_key` (no epk/recipient
    # binding) and the body ciphertext's AAD is the algorithm string itself,
    # not an envelope binding — this is what `open_sealed`'s v1 branch (and
    # the Rust `open`'s non-v2 branch) expects. `seal()` in messaging.py only
    # implements v2, so this vector is built by hand from the same KDFs.
    msg_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    plaintext_bytes = json.dumps(plaintext, separators=(",", ":"), ensure_ascii=False).encode()
    ct_bytes = ChaCha20Poly1305(msg_key).encrypt(nonce, plaintext_bytes, ALG.encode())
    epk_secret = X25519PrivateKey.generate()
    epk_pub = epk_secret.public_key()
    wraps = {}
    for label, key in recipients.items():
        wk = _wrap_key(epk_secret, key, label)
        wraps[label] = base64.b64encode(ChaCha20Poly1305(wk).encrypt(b"\x00" * 12, msg_key, label.encode())).decode()
    ct = {"ct": base64.b64encode(ct_bytes).decode()}
    meta = {
        "alg": ALG,
        "epk": base64.b64encode(_raw(epk_pub)).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "wraps": wraps,
    }

    envelope = {
        "id": "msg_vector",
        "thread_id": "thr_vector",
        "from": "node-c/coordinator",
        "to": RECIPIENT,
        "kind": "message",
        "ts": "2026-09-03T00:00:00Z",
        "body": ct,
    }
    inp = signing_input(envelope)
    sig = ctrl.sign.sign(inp)

    data = {
        "controller_secret": CONTROLLER_SECRET,
        "agent_secret": AGENT_SECRET,
        "plaintext": plaintext,
        "envelope": envelope,
        "enc_meta": meta,
        "sig": base64.b64encode(sig).decode(),
    }
    path = FIXTURES / "agent_seal_vector.json"
    path.write_text(json.dumps(data, indent=1))
    return data


def gen_v2() -> dict:
    """v2 vector: alphabetically-sorted keys, 2-space indent, trailing
    newline — the format the existing ``agent_seal_vector_v2.json`` is in."""
    ctrl = AgentKeys.from_secret(CONTROLLER_SECRET)
    agent = AgentKeys.from_secret(AGENT_SECRET)
    signer = AgentKeys.from_secret(SIGNING_SECRET)
    plaintext = {"n": 3, "text": "meet at the graph"}

    envelope = {
        "v": 2,
        "id": "msg_v2fixture0000000",
        "thread_id": "thr_v2fixture000",
        "from": "node-c/coordinator",
        "to": RECIPIENT,
        "kind": "message",
        "ts": "2026-09-04T00:00:00+00:00",
        "refs": [],
        "ttl_s": 0,
        "enc": "e2e",
    }
    aad = envelope_aad(envelope)
    recipients = {REVIEW_WRAP: ctrl.seal.public_key(), RECIPIENT: agent.seal.public_key()}
    ct, meta = seal(plaintext, recipients, aad)
    envelope["body"] = ct
    envelope["enc_meta"] = meta

    inp = signing_input_v2(envelope)
    sig = signer.sign.sign(inp)

    data = {
        "_comment": (
            "Generated by scripts/gen-agent-seal-vectors.py; Rust opens and verifies it "
            "(and vice versa) — the cross-language contract for envelope protocol v2 "
            "."
        ),
        "agent_secret": AGENT_SECRET,
        "alg": "x25519-chacha20poly1305-v2",
        "controller_secret": CONTROLLER_SECRET,
        "envelope": envelope,
        "plaintext": plaintext,
        "sig": base64.b64encode(sig).decode(),
        "signing_secret": SIGNING_SECRET,
    }
    path = FIXTURES / "agent_seal_vector_v2.json"
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return data


def main() -> None:
    gen_v1()
    gen_v2()
    print(f"wrote {FIXTURES / 'agent_seal_vector.json'}")
    print(f"wrote {FIXTURES / 'agent_seal_vector_v2.json'}")
    print("note: epk/nonce/ct/wraps ciphertexts are fresh each run (ephemeral key) — everything else is fixed.")


if __name__ == "__main__":
    main()
