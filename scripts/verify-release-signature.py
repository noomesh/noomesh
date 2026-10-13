#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Verify a `noo-sig1.` release signature without trusting a noo binary first.

WHY THIS EXISTS. The release rail signs `sha256sums.txt` and `stack-<tag>.lock`
with the Ed25519 release key, and everything downstream verifies
those signatures with `noo security release-verify`. That works everywhere
except in the one place it matters most: the job that HOLDS the signing seed.
Previously the `lock` job in `.github/workflows/images-release.yml`
resolved "the newest noo-cli release", downloaded a binary from it, and ran
that binary with `NOO_RELEASE_SIGNING_SEED` in its environment — a binary it
had not checked in any way. Anyone who could attach an asset to a release, or
create a release at all, could have had the signing key read out and posted
somewhere on the next stack tag, and every node in every fleet trusts that key
by construction. Asking the unverified binary to verify itself is no answer, so
the check has to come from something already in the repository: this script.

It implements Ed25519 verification (RFC 8032 §5.1.7) on the Python standard
library alone — no `cryptography`, no OpenSSL, nothing to install on a runner —
and reads the trusted public keys straight out of `noo-cli/src/release_sig.rs`,
so the workflow and the CLI can never drift onto different key lists.

    verify-release-signature.py [--keys-from <release_sig.rs>] [--key <hex>]
                                <signed-file> [<signed-file>.sig]

Exit 0 when a pinned key verifies the signature, 1 otherwise. Silent success is
deliberate: this runs inside `set -eu` workflow steps.
"""

import argparse
import base64
import hashlib
import re
import sys

SIG_PREFIX = "noo-sig1."

# Ed25519 over Curve25519, RFC 8032. Extended (X, Y, Z, T) coordinates.
P = 2**255 - 19
D = -121665 * pow(121666, P - 2, P) % P
L = 2**252 + 27742317777372353535851937790883648493


def recover_x(y: int, sign: int):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * pow(2, (P - 1) // 4, P) % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def point_add(p1, p2):
    a = (p1[1] - p1[0]) * (p2[1] - p2[0]) % P
    b = (p1[1] + p1[0]) * (p2[1] + p2[0]) % P
    c = 2 * p1[3] * p2[3] * D % P
    e = 2 * p1[2] * p2[2] % P
    return ((b - a) * (e - c) % P, (e + c) * (b + a) % P,
            (e - c) * (e + c) % P, (b - a) * (b + a) % P)


def point_mul(scalar, point):
    acc = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            acc = point_add(acc, point)
        point = point_add(point, point)
        scalar >>= 1
    return acc


_GY = 4 * pow(5, P - 2, P) % P
_GX = recover_x(_GY, 0)
G = (_GX, _GY, 1, _GX * _GY % P)


def decompress(raw: bytes):
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


def ed25519_verify(pubkey: bytes, signature: bytes, message: bytes) -> bool:
    a = decompress(pubkey)
    if a is None or len(signature) != 64:
        return False
    r = decompress(signature[:32])
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    h = int.from_bytes(
        hashlib.sha512(signature[:32] + pubkey + message).digest(), "little") % L
    lhs = point_mul(s, G)
    rhs = point_add(r, point_mul(h, a))
    return ((lhs[0] * rhs[2] - rhs[0] * lhs[2]) % P == 0
            and (lhs[1] * rhs[2] - rhs[1] * lhs[2]) % P == 0)


def keys_from_source(path: str):
    """Pull RELEASE_PUBKEYS_HEX out of noo-cli/src/release_sig.rs.

    Reading the Rust constant rather than repeating it here means a key
    rotation lands in exactly one place; a workflow pinning its own copy would
    eventually keep verifying against a key the CLI had already retired.
    """
    src = open(path, encoding="utf-8").read()
    m = re.search(r"RELEASE_PUBKEYS_HEX\s*:\s*&\[&str\]\s*=\s*&\[(.*?)\]", src, re.S)
    if not m:
        raise SystemExit(f"could not find RELEASE_PUBKEYS_HEX in {path}")
    return re.findall(r'"([0-9a-fA-F]{64})"', m.group(1))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keys-from", help="path to noo-cli/src/release_sig.rs")
    ap.add_argument("--key", action="append", default=[],
                    help="an additional trusted public key, 64 hex chars")
    ap.add_argument("file")
    ap.add_argument("sig", nargs="?")
    args = ap.parse_args()

    keys = list(args.key)
    if args.keys_from:
        keys += keys_from_source(args.keys_from)
    if not keys:
        print("no trusted release keys given (--keys-from or --key)", file=sys.stderr)
        return 1

    message = open(args.file, "rb").read()
    sig_path = args.sig or args.file + ".sig"
    text = open(sig_path, encoding="utf-8").read().strip()
    if not text.startswith(SIG_PREFIX):
        print(f"{sig_path}: not a release signature (expected the "
              f"{SIG_PREFIX} prefix)", file=sys.stderr)
        return 1
    body = text[len(SIG_PREFIX):]
    try:
        signature = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except Exception as exc:
        print(f"{sig_path}: bad base64url in signature: {exc}", file=sys.stderr)
        return 1

    for hex_key in keys:
        try:
            pubkey = bytes.fromhex(hex_key)
        except ValueError:
            continue
        if len(pubkey) == 32 and ed25519_verify(pubkey, signature, message):
            return 0

    print(f"{args.file}: signature does not verify against any of the "
          f"{len(keys)} pinned release key(s)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
