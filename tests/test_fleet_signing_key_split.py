# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Node bundles are signed with a FLEET SIGNING KEY, not the cluster CA key
(§3f R26).

One key used to do two unrelated jobs: issue every mTLS identity in the
cluster, and sign the bundles that deliver ROOT CODE to every box (the
node-agent binary, pai-hostd, `noo-apply` itself, fleet secrets). Compromise
of either job's key compromised the other, and the code-signing half could
not be rotated without re-issuing every certificate in the fleet.

The verifier lives in three places that must agree, in three languages:

  scripts/noo-apply.sh                 the Linux applier (root)
  noo-cli/src/commands/node_fetch.rs   the macOS poller
  scripts/sign-bundle.sh               the hand-build signer

This file pins the CONTRACT between them by source text, for the same reason
`test_bundle_kind_allowlists.py` does: a disagreement is silent in the field
— the controller prints "delivered", the node refuses, and the two never
meet. The behavioural halves (what actually verifies against what) are in
the Rust unit tests in `node_fetch.rs`.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
APPLY = (REPO / "scripts/noo-apply.sh").read_text()
SIGN = (REPO / "scripts/sign-bundle.sh").read_text()
FETCH = (REPO / "noo-cli/src/commands/node_fetch.rs").read_text()
LOCAL = (REPO / "noo-cli/src/commands/security_local.rs").read_text()
PKI = (REPO / "noo-cli/src/pki.rs").read_text()


def test_signing_pub_is_a_bundle_kind_everywhere():
    """A kind known to the signer but not an applier is a refused bundle (76)."""
    m = re.search(r'^KNOWN_KINDS="([^"]*)"$', APPLY, re.M)
    assert m, "noo-apply.sh: no KNOWN_KINDS assignment"
    assert "signing-pub" in m.group(1).split()

    m = re.search(r'^KNOWN="([^"]*)"$', SIGN, re.M)
    assert m, "sign-bundle.sh: no KNOWN assignment"
    assert "signing-pub" in m.group(1).split()

    m = re.search(r"const KNOWN_KINDS: &\[&str\] = &\[(.*?)\];", FETCH, re.S)
    assert m, "node_fetch.rs: no KNOWN_KINDS array"
    assert "signing-pub" in re.findall(r'"([^"]+)"', m.group(1))


def test_the_controller_no_longer_signs_bundles_with_the_ca_key():
    """`build_signed_bundle` must route through the per-node key chooser.

    A direct `ca.ca_key_path()` in a bundle builder is the regression: it
    puts the CA key back on the code-delivery path for every node, which is
    R26 verbatim.
    """
    # The two builders and their signing arguments.
    for fn in ("build_signed_cert_bundle", "build_signed_bundle_with_key"):
        assert f"fn {fn}(" in LOCAL, f"{fn} disappeared — re-point this guard"

    body = LOCAL[LOCAL.index("fn build_signed_cert_bundle("):]
    body = body[: body.index("pub(crate) fn build_signed_bundle(")]
    assert "let key = ca.bundle_signing_key(node);" in body and "sign_and_tar(ca, work, &key)" in body, (
        "build_signed_cert_bundle no longer signs with the fleet signing key"
    )
    assert ".arg(ca.ca_key_path())" not in body, (
        "build_signed_cert_bundle signs cert bundles with the CA key again (R26)"
    )

    # The ONE place the CA key may still sign is the rollover, and it must
    # say so at the call site.
    rollovers = [
        ln for ln in LOCAL.splitlines()
        if "ca.ca_key_path()" in ln and not ln.lstrip().startswith("//")
    ]
    assert len(rollovers) == 1, (
        f"the CA key signs at {len(rollovers)} call sites; exactly one (the "
        f"signing-key rollover) is allowed: {rollovers}"
    )
    assert "build_signed_bundle_with_key" in rollovers[0], (
        f"the CA key is used outside the rollover path: {rollovers[0]}"
    )


def test_the_signing_key_is_separate_material_with_the_ca_key_permissions():
    assert 'self.dir.join("signing.key")' in PKI
    assert 'self.dir.join("signing.pub")' in PKI
    # 0600, like ca.key. A world-readable signing key is a fleet takeover.
    # Written through the private-key writer, which is 0600 from the first
    # byte (the design: never created at the umask and chmod-ed after).
    m = re.search(
        r"write_key_file\(&self\.signing_key_path\(\), key\.serialize_pem\(\)\.as_bytes\(\)\)",
        PKI,
    )
    assert m, "the fleet signing key is not written through write_key_file (0600)"
    writer = PKI[PKI.index("fn write_key_file(") :]
    writer = writer[: writer.index("\n}\n")]
    assert ".mode(0o600)" in writer and "set_mode(path, 0o600)" in writer, "write_key_file no longer creates 0600"
    assert "self.ensure_signing_key()?" in PKI, "generate_ca does not mint a signing key"


def test_both_verifiers_prefer_the_signing_key_and_keep_only_the_rollover_arm():
    """Two arms, same order, in both languages (an earlier change A1/A2).

    1. signing.pub — the normal path
    2. the CA, only for a bundle carrying signing-pub — the rollover — and,
       on a node that already holds a signing key, only countersigned by it

    The third arm (the CA unconditionally, NOO_APPLY_ACCEPT_CA_SIGNED) is
    retired; the behaviour is pinned in test_apply_signature_lanes_retired.py
    and node_fetch.rs's R26 tests.
    """
    # Shell
    assert 'SIGNPUB="$_pki/signing.pub"' in APPLY
    assert 'if [ -f "$SIGNPUB" ] && _sig_ok "$SIGNPUB"; then' in APPLY
    assert 'if [ "$_kinds" = "signing-pub " ] && _sig_ok "$_keys/ca.pub"; then' in APPLY
    assert 'manifest.xsig*' in APPLY
    assert 'NOO_APPLY_ACCEPT_CA_SIGNED:-1' not in APPLY
    # Rust
    assert "has_signing && verify(signing_pub, &sig)" in FETCH
    assert "rollover && ca_ok" in FETCH
    assert "countersignatures(stage)" in FETCH
    assert "accept_ca_signed" not in FETCH


def test_the_compatibility_window_is_gone_and_says_so():
    """A retired lane must be refused loudly, and its switch named as ignored."""
    for src in (APPLY, FETCH):
        assert "CA-signed apply lane is retired" in src
        assert "NOO_APPLY_ACCEPT_CA_SIGNED is retired" in src
    assert "removed in the next release" not in APPLY
    assert "removed in the next release" not in FETCH


def test_the_ca_signs_nothing_but_a_countersigned_key():
    """The controller half of A1/A2 after review: a CA-signed bundle carries
    signing-pub and nothing else, is countersigned with every retained key,
    and no builder will sign anything else for a node that has not adopted."""
    body = LOCAL[LOCAL.index("fn sign_and_tar("):]
    body = body[: body.index("\n}\n")]
    assert "ca.retained_signing_keys()" in body
    assert "manifest.xsig.{n}" in body
    w = LOCAL[LOCAL.index("pub(crate) fn build_signed_bundle_with_key("):]
    w = w[: w.index("\n}\n")]
    assert 'files.len() == 1 && files[0].0 == "signing-pub"' in w
    assert "return Err(not_adopted(node));" in LOCAL
    assert "NOTHING else" in SIGN


def test_the_rotation_verb_exists_and_is_reachable():
    main = (REPO / "noo-cli/src/main.rs").read_text()
    usage = (REPO / "noo-cli/src/usage.rs").read_text()
    assert '&["security", "pki", "rotate-signing-key"]' in main, "verb not dispatched"
    assert '&["security", "pki", "rotate-signing-key"]' in usage, (
        "verb has no usage line — `noo --help` is pinned by a test and native help "
        "is the CLI's contract"
    )
    assert "pub fn pki_rotate_signing_key(" in LOCAL
