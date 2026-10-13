# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Tests for cluster/cluster_auth.py — HMAC token create/verify.

Spec: HMAC-MD5 token format is ``node_id:timestamp:signature``.
- Tokens are valid for 300 seconds (5 minutes).
- Clock skew tolerance is 30 seconds.
- Wrong secret, expired, tampered, or malformed tokens MUST reject.
"""

from unittest.mock import patch

import pytest

from noomesh.cluster.cluster_auth import (
    create_cluster_token,
    generate_cluster_secret,
    verify_cluster_token,
)

SECRET = "test-secret-abc123"


class TestGenerateSecret:
    def test_length_and_uniqueness(self):
        s1 = generate_cluster_secret()
        s2 = generate_cluster_secret()
        assert len(s1) >= 32
        assert s1 != s2


# ── I/O Spec: token verification ──────────────────────────────────
# Each row defines: (create_secret, create_time, verify_secret, verify_time, expected_valid)
#
# Rules:
#   1. Same secret + within 300s window  → valid
#   2. Wrong secret                      → reject
#   3. Age > 300s                        → reject (expired)
#   4. Future token within 30s skew      → valid
#   5. Future token beyond 30s skew      → reject

_VERIFY_SPEC = [
    # id                    create_secret  create_time   verify_secret  verify_time    expected
    ("same_secret_fresh",   SECRET,        1_000_000.0,  SECRET,        1_000_000.0,   True),
    ("same_secret_at_299s", SECRET,        1_000_000.0,  SECRET,        1_000_299.0,   True),
    ("expired_at_301s",     SECRET,        1_000_000.0,  SECRET,        1_000_301.0,   False),
    ("wrong_secret",        SECRET,        1_000_000.0,  "wrong",       1_000_000.0,   False),
    ("future_within_skew",  SECRET,        1_000_020.0,  SECRET,        1_000_000.0,   True),
    ("future_beyond_skew",  SECRET,        1_000_060.0,  SECRET,        1_000_000.0,   False),
]


class TestVerifySpec:
    @pytest.mark.parametrize(
        "create_secret,create_time,verify_secret,verify_time,expected_valid",
        [row[1:] for row in _VERIFY_SPEC],
        ids=[row[0] for row in _VERIFY_SPEC],
    )
    def test_verify_token(
        self, create_secret, create_time, verify_secret, verify_time, expected_valid
    ):
        with patch("noomesh.cluster.cluster_auth.time") as mt:
            mt.time.return_value = create_time
            token = create_cluster_token("node-1", secret=create_secret)

        with patch("noomesh.cluster.cluster_auth.time") as mt:
            mt.time.return_value = verify_time
            valid, _ = verify_cluster_token(token, secret=verify_secret)
            assert valid is expected_valid


# ── I/O Spec: malformed tokens ────────────────────────────────────
# Every entry here MUST be rejected with valid=False.

_REJECT_SPEC = [
    ("empty_string",        ""),
    ("no_colons",           "garbage"),
    ("one_colon",           "node:123"),
    ("tampered_sig",        None),   # built dynamically below
]


class TestRejectSpec:
    @pytest.mark.parametrize(
        "token",
        ["", "garbage", "node:123"],
        ids=["empty", "no_colons", "one_colon"],
    )
    def test_malformed_rejected(self, token):
        valid, _ = verify_cluster_token(token, secret=SECRET)
        assert valid is False

    def test_tampered_signature_rejected(self):
        token = create_cluster_token("node-1", secret=SECRET)
        parts = token.split(":")
        parts[2] = "0" * 64
        valid, _ = verify_cluster_token(":".join(parts), secret=SECRET)
        assert valid is False


class TestTokenFormat:
    def test_format_is_three_colon_separated_parts(self):
        token = create_cluster_token("node-42", secret=SECRET)
        parts = token.split(":")
        assert len(parts) == 3
        assert parts[0] == "node-42"
        assert parts[1].isdigit()
        # Full HMAC-SHA256 hex — the one width anything accepts (P13).
        assert len(parts[2]) == 64

    def test_truncated_32_char_prefix_is_refused(self):
        # The P13 one-release window for the 32-hex legacy width is closed:
        # the CORRECT prefix is refused, like any other truncation.
        token = create_cluster_token("node-42", secret=SECRET)
        node, ts, sig = token.split(":")
        assert verify_cluster_token(token, secret=SECRET)[0] is True
        for n in (16, 32, 48):
            valid, _ = verify_cluster_token(f"{node}:{ts}:{sig[:n]}", secret=SECRET)
            assert valid is False, f"prefix len {n} must be refused"
