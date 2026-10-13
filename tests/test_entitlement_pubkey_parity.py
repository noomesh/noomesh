# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The entitlement public key is baked into TWO binaries — the gateway
(verifies at runtime) and the CLI (verifies before install, and refuses to
issue with a mismatched signing key). They must be the same 32 bytes, or a
token the CLI accepts is one the gateway rejects. The noo-cli CI job builds
crate-only, so this cross-crate pin lives in the Python job."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _pubkey(path: str) -> str:
    text = (REPO / path).read_text()
    m = re.search(r'pub const PUBKEY_HEX: &str = "([0-9a-f]{64})";', text)
    assert m, f"{path}: PUBKEY_HEX must be a 64-hex ed25519 public key"
    return m.group(1)


def test_gateway_and_cli_bake_the_same_entitlement_key():
    assert _pubkey("gateway-rust/src/entitlement.rs") == _pubkey("noo-cli/src/entitlement.rs")


def test_key_is_not_a_placeholder():
    k = _pubkey("gateway-rust/src/entitlement.rs")
    assert len(set(k)) > 4, "PUBKEY_HEX looks like a placeholder, not a real key"
