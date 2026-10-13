# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The bus-principal wire format must not drift between the two runtimes.

`gateway-rust/src/bus_principal.rs` signs, `noomesh/gateway/bus_principal.py`
verifies, and nothing in either process can observe a disagreement: a claim
the Rust side renames simply reads as absent on the Python side, and absent
claims are how "unrestricted" used to happen. So the contract is pinned here,
statically, the same way `test_posture_key_parity` pins the posture keys —
no bus, no gateway, no cargo (there is none on the controller).

What is pinned: the header name, the claim names, the signature primitive and
its width, and the freshness window. Each is a thing that, if it drifted,
would either refuse every message (visible, recoverable) or accept one it
should not (invisible) — and the second is why this file exists.
"""
from __future__ import annotations

import re
from pathlib import Path

from noomesh.gateway import bus_principal as bp

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "gateway-rust/src/bus_principal.rs"


def _rust_source() -> str:
    src = RUST.read_text()
    assert len(src) > 2000, "bus_principal.rs is suspiciously small — wrong path?"
    return src


def _rust_const(name: str) -> str:
    """A `pub const NAME: &str = "value";` from the Rust module."""
    m = re.search(rf'pub const {name}:\s*&str\s*=\s*"([^"]+)"', _rust_source())
    assert m, f"{name} not found in bus_principal.rs — did the shape change?"
    return m.group(1)


def _rust_claim_fields() -> list[str]:
    """Field names of the `struct Claims`, comments stripped first."""
    src = re.sub(r"//[^\n]*", "", _rust_source())
    block = re.search(r"struct Claims<'a>\s*\{(.*?)\n\}", src, re.S)
    assert block, "struct Claims not found — did the shape change?"
    return re.findall(r"^\s*(\w+):", block.group(1), re.M)


def test_the_header_name_matches() -> None:
    assert _rust_const("HEADER") == bp.HEADER


def test_the_claim_names_match() -> None:
    """Every claim the verifier reads must be one the signer emits.

    The asymmetry is deliberate: the Rust side may not emit a claim Python
    never looks at (dead weight on every message), and Python must not read
    one Rust never sends (which silently reads as absent).
    """
    rust = set(_rust_claim_fields())
    assert rust, "parsed no claim fields"
    verified = {"sub", "kind", "role", "scopes", "subj", "iat", "exp", "nonce"}
    assert rust == verified, (
        "the signed claim set drifted from what the verifier reads.\n"
        f"  only in bus_principal.rs: {sorted(rust - verified) or 'none'}\n"
        f"  only in the verifier:     {sorted(verified - rust) or 'none'}"
    )


def test_the_verifier_actually_reads_every_claim() -> None:
    """Guard against the guard: the set above is hand-written.

    If it drifted from the code it describes, the test above would keep
    passing while checking nothing real.
    """
    src = (ROOT / "src/noomesh/gateway/bus_principal.py").read_text()
    for claim in _rust_claim_fields():
        assert f'"{claim}"' in src, (
            f"the signer emits {claim!r} but the verifier never mentions it"
        )


def test_the_freshness_window_matches_the_signed_ttl() -> None:
    m = re.search(r"pub const TTL_SECS:\s*u64\s*=\s*(\d+)", _rust_source())
    assert m, "TTL_SECS not found in bus_principal.rs"
    assert int(m.group(1)) == bp.CLOCK_SKEW_SECS, (
        "the Rust signer's TTL and the Python verifier's skew allowance "
        "disagree — tokens would be refused (or accepted) at the edges for "
        "reasons neither side can explain"
    )


def test_the_nonce_cache_outlives_the_window_a_replay_could_use() -> None:
    """A nonce forgotten while its token is still fresh is a replay hole."""
    assert bp.NONCE_TTL_SECS >= bp.CLOCK_SKEW_SECS * 2


def test_neither_side_uses_the_controller_secret() -> None:
    """an earlier change: the bus is signed per audience, never with the
    shared controller secret, on either side (comments aside)."""
    rust = re.sub(r"//[^\n]*", "", _rust_source().split("#[cfg(test)]")[0])
    assert "NOO_CONTROLLER_SECRET" not in rust and "controller_secret" not in rust
    import ast

    py_tree = ast.parse((ROOT / "src/noomesh/gateway/bus_principal.py").read_text())
    consts = {n.value for n in ast.walk(py_tree) if isinstance(n, ast.Constant)}
    assert "NOO_CONTROLLER_SECRET" not in consts


def test_the_audiences_match() -> None:
    """The gateway signs for exactly the audiences a verifier may be."""
    block = re.search(r"pub const AUDIENCES:[^=]*=\s*&\[(.*?)\];", _rust_source(), re.S)
    assert block, "AUDIENCES not found in bus_principal.rs"
    rust = re.findall(r'\("([^"]+)",\s*"(NOO_BUS_KEY_[A-Z_]+)"\)', block.group(1))
    assert [a for a, _ in rust] == list(bp.AUDIENCES)
    for aud, var in rust:
        assert var == "NOO_BUS_KEY_" + aud.upper().replace("-", "_"), (aud, var)


def test_the_mac_input_matches() -> None:
    """mac(aud) = HMAC(key, "<aud>.<body>") on both sides."""
    src = _rust_source()
    assert "mac.update(audience.as_bytes());" in src and 'mac.update(b".");' in src
    py = (ROOT / "src/noomesh/gateway/bus_principal.py").read_text()
    assert 'f"{audience}.{body}"' in py


def test_the_signature_is_full_width_hmac_sha256() -> None:
    """64 hex, never the cluster token's 32-char legacy prefix (P13)."""
    src = _rust_source()
    assert "Hmac<Sha256>" in src
    assert "hex::encode" in src
    py = (ROOT / "src/noomesh/gateway/bus_principal.py").read_text()
    assert "len(mac) != 64" in py, (
        "the verifier no longer pins the signature width — a truncated "
        "signature has a 2^-128 forgery margin instead of 2^-256"
    )


def test_the_unrestricted_scope_name_matches() -> None:
    assert _rust_const("SCOPE_KB_UNRESTRICTED") == "kb:unrestricted"
    # And the verifier agrees, behaviourally rather than by string match.
    p = bp.Principal(sub="internal:x", kind="internal", role="user",
                     scopes=[_rust_const("SCOPE_KB_UNRESTRICTED")])
    assert p.kb_unrestricted


# ── The retired mode switch ───────────────────────────────────────────
#
# `NOO_BUS_PRINCIPAL=optional` served unsigned `worker.*` messages for one
# release. It is retired: the Python verifier has no mode, and the Rust
# gateway declares the key in `RETIRED_BRIDGES` so a row or env value still
# holding it open refuses the boot instead of being silently ignored.

POSTURE_RS = ROOT / "gateway-rust/src/posture.rs"


def test_the_verifier_has_no_mode_switch() -> None:
    for name in ("mode", "MODE_VAR", "MODE_OPTIONAL", "MODE_REQUIRED"):
        assert not hasattr(bp, name), f"bus_principal.{name} is back — the bridge is retired"


def test_the_key_is_retired_not_catalogued() -> None:
    from noomesh.posture import POSTURE_KEYS

    assert "NOO_BUS_PRINCIPAL" not in POSTURE_KEYS
    src = re.sub(r"//[^\n]*", "", POSTURE_RS.read_text())
    retired = re.search(r"RETIRED_BRIDGES:.*?=\s*&\[(.*?)\n\];", src, re.S)
    assert retired, "RETIRED_BRIDGES not found in posture.rs — did the shape change?"
    m = re.search(r'key:\s*"NOO_BUS_PRINCIPAL",\s*closed:\s*"([^"]*)"', retired.group(1))
    assert m, "NOO_BUS_PRINCIPAL must be declared retired (a stale row must refuse boot)"
    assert m.group(1) == "required", "its closed value is 'required', not a boolean"
    catalog = re.search(r"POSTURE_CATALOG:.*?=\s*&\[(.*?)\n\];", src, re.S)
    assert catalog and '"NOO_BUS_PRINCIPAL"' not in catalog.group(1)
