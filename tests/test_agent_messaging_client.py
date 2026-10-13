# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""noomesh.agents.messaging — sealing/signing parity with the gateway."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from noomesh.agents.messaging import (ALG_V2, REVIEW_WRAP, AgentKeys, AgentMessenger, envelope_aad, is_valid_id,
                                      open_sealed, seal, signing_input, signing_input_v2, subject_token,
                                      verify_key_record, verify_signature)

REPO = Path(__file__).resolve().parents[1]
VECTOR = REPO / "gateway-rust/src/fixtures/agent_seal_vector.json"


def test_seal_open_round_trip_and_wrong_key_fails():
    ctrl = AgentKeys.from_secret("controller-review-secret-with-enough-entropy-0123")
    agent = AgentKeys.generate()
    body = {"text": "hi", "n": [1, 2]}
    aad = b"envelope-binding"
    ct, meta = seal(body, {REVIEW_WRAP: ctrl.seal.public_key(), "a": agent.seal.public_key()}, aad)
    assert meta["alg"] == ALG_V2
    assert open_sealed(ct, meta, REVIEW_WRAP, ctrl.seal, aad) == body
    assert open_sealed(ct, meta, "a", agent.seal, aad) == body
    try:
        open_sealed(ct, meta, REVIEW_WRAP, X25519PrivateKey.generate(), aad)
        assert False, "wrong key opened the wrap"
    except Exception:
        pass
    # v2: the same ciphertext under a different envelope does not open.
    try:
        open_sealed(ct, meta, REVIEW_WRAP, ctrl.seal, b"another-envelope")
        assert False, "ciphertext opened under a foreign envelope binding"
    except Exception:
        pass


def test_v2_fixture_round_trips_against_the_rust_side():
    """The fixture Rust also opens and verifies — the cross-language contract."""
    v = json.loads((REPO / "gateway-rust/src/fixtures/agent_seal_vector_v2.json").read_text())
    ctrl = AgentKeys.from_secret(v["controller_secret"])
    agent = AgentKeys.from_secret(v["agent_secret"])
    signer = AgentKeys.from_secret(v["signing_secret"])
    env = v["envelope"]
    aad = envelope_aad(env)
    assert open_sealed(env["body"], env["enc_meta"], REVIEW_WRAP, ctrl.seal, aad) == v["plaintext"]
    assert open_sealed(env["body"], env["enc_meta"], env["to"], agent.seal, aad) == v["plaintext"]
    assert verify_signature({**env, "sig": v["sig"]}, signer.sign.public_key())
    # The review key is not the signing key: reading history no longer implies
    # being able to forge it.
    assert not verify_signature({**env, "sig": v["sig"]}, ctrl.sign.public_key())
    # Every field is inside the signature now, not just the six identifying ones.
    for field, value in (("enc", "none"), ("refs", ["x"]), ("ttl_s", 99), ("v", 3)):
        assert not verify_signature({**env, field: value, "sig": v["sig"]}, signer.sign.public_key()), field
    stripped = json.loads(json.dumps(env))
    stripped["enc_meta"]["wraps"].pop(env["to"])
    assert not verify_signature({**stripped, "sig": v["sig"]}, signer.sign.public_key()), "wrap strip"
    # Canonical form is byte-stable.
    assert signing_input_v2({**env, "sig": v["sig"]}) == signing_input_v2(env)


def test_fixture_matches_the_rust_side():
    v = json.loads(VECTOR.read_text())
    ctrl = AgentKeys.from_secret(v["controller_secret"])
    agent = AgentKeys.from_secret(v["agent_secret"])
    env = v["envelope"]
    assert open_sealed(env["body"], v["enc_meta"], REVIEW_WRAP, ctrl.seal) == v["plaintext"]
    assert open_sealed(env["body"], v["enc_meta"], "node-a/claude-code-1", agent.seal) == v["plaintext"]
    assert verify_signature({**env, "sig": v["sig"]}, ctrl.sign.public_key())


def test_subject_token_matches_rust_rule():
    # Injective for valid ids: `/` → `.`, nothing else changes.
    assert subject_token("node-a/claude-code-1") == "node-a.claude-code-1"
    assert subject_token("node-a/claude-code-1") != subject_token("node-a_claude-code-1")
    assert is_valid_id("worker/ingest") and not is_valid_id("a.b") and not is_valid_id("a//b") and not is_valid_id("/x")
    # Invalid ids keep the old squash (the gateway rejects them anyway).
    assert subject_token("a.b*c") == "a_b_c"


def test_key_records_are_self_signed_and_bound_to_the_agent(tmp_path):
    k = AgentKeys.generate()
    rec = k.signed_record("worker/ingest")
    assert verify_key_record("worker/ingest", rec)
    assert not verify_key_record("worker/other", rec), "a record must not replay under another agent id"
    rotated = AgentKeys.generate().signed_record("worker/ingest", prev=k)
    assert verify_key_record("worker/ingest", rotated) and "prev_sig" in rotated
    # The key file is 0600 from creation.
    p = tmp_path / "k.json"
    AgentKeys.load_or_create(p)
    assert (p.stat().st_mode & 0o777) == 0o600


def test_listener_accepts_only_signed_sealed_envelopes_addressed_to_it(tmp_path):
    ctrl = AgentKeys.from_secret("controller-review-secret-with-enough-entropy-0123")
    m = AgentMessenger("worker/ingest", key_path=tmp_path / "k.json")
    env = {"v": 2, "id": "msg_1", "thread_id": "thr_1", "from": "node-c/coordinator", "to": "worker/ingest",
           "kind": "message", "ts": "2026-09-03T00:00:00Z", "refs": [], "ttl_s": 0, "enc": "e2e"}
    body, meta = seal({"text": "hi"}, {REVIEW_WRAP: ctrl.seal.public_key(), "worker/ingest": m.keys.seal.public_key()},
                      envelope_aad(env))
    env["body"], env["enc_meta"] = body, meta
    env["sig"] = base64.b64encode(ctrl.sign.sign(signing_input_v2(env))).decode()
    signer = ctrl.sign.public_key()
    assert m.accept(env, signer)
    assert m.open(dict(env))["body"] == {"text": "hi"}
    assert not m.accept({**env, "enc": "none", "sig": None}, signer), "plaintext on a sealed bus is dropped"
    assert not m.accept({**env, "to": "worker/other"}, signer), "not addressed to us"
    forged = {**env, "from": "node-a/claude-code-1"}
    assert not m.accept(forged, signer), "re-addressed copy fails the signature"
    # Plaintext mode (no controller key): shape only.
    assert m.accept({**env, "enc": "none", "sig": None}, None)
