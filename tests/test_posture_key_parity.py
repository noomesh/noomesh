# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The two POSTURE_KEYS allow-lists must not drift.

`gateway-rust/src/posture.rs` and `src/noomesh/posture.py` each hold a copy,
kept in step only by a comment saying so. They are applied by *different
processes* in the same container — the Rust binary at its startup, the Python
worker_pool at its own — so drift does not fail anywhere. It half-applies a
security gate: the DB says a gate is on, one runtime honours it, the other
carries on with the `.env` value, and nothing logs a disagreement.

`NOO_EXEC_APPROVAL_MODE` is the sharpest example: Rust-side `approval`,
Python-side `auto` means the HTTP door queues a tool call for a human while
the workers behind it run whatever they are handed. (`NOO_MULTI_USER` was the
old example here; it is gone — tenant isolation no longer waits on a flag.)

Static parse on purpose: no gateway, no DB, no Rust toolchain (there is no
cargo on the controller), so this runs everywhere pytest does.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUST = ROOT / "gateway-rust/src/posture.rs"
PY = ROOT / "src/noomesh/posture.py"


# Comments are stripped BEFORE the block is located, not after. The prose in
# both files contains the very delimiters the block regex looks for — the
# Python list carries "(config-graduation phase 1)", whose `)` ends a
# non-greedy match early and silently yields ONE key. That produced a test
# that failed against two correct files, which is worse than no test.
def _rust_catalog() -> list[tuple[str, str]]:
    """`(key, kind)` for every entry in `POSTURE_CATALOG`, kind ∈ gate|bridge.

    The Rust side is one classified table (R43), not a flat list: a `Gate` is a
    property of the environment and a vetted profile sets it; a `Bridge` is a
    rollout state the operator holds open and a profile must never name it.
    """
    src = re.sub(r"//[^\n]*", "", RUST.read_text())
    block = re.search(
        # Non-greedy, and anchored on the table's own closing `];` at column
        # 0. A greedy `(.*)\];` ran to the LAST `];` in the file and swallowed
        # the helper functions below, whose `&'static PostureKey>` then parsed
        # as a catalog entry with no key.
        r"pub const POSTURE_CATALOG:\s*&\[PostureKey\]\s*=\s*&\[(.*?)\n\];", src, re.S
    )
    assert block, "POSTURE_CATALOG not found in posture.rs — did the shape change?"
    # Split on the struct literal rather than matching each one with a
    # lookahead: the last entry is followed by a comment, not by another
    # `PostureKey`, and a `(?=PostureKey|$)` lookahead silently dropped it —
    # the parse then reported one fewer key than the file has, which is a test
    # lying in the safe-looking direction.
    chunks = block.group(1).split("PostureKey")[1:]
    out: list[tuple[str, str]] = []
    for entry in chunks:
        key = re.search(r'key:\s*"([^"]+)"', entry)
        assert key, f"catalog entry with no key: {entry[:80]}"
        kind = "bridge" if "PostureKind::Bridge" in entry else "gate"
        out.append((key.group(1), kind))
    assert out, "parsed no entries from POSTURE_CATALOG"
    # The parse must see the whole table, not a prefix of it.
    assert len(out) == block.group(1).count("key:"), (
        f"parsed {len(out)} catalog entries but the table has "
        f"{block.group(1).count('key:')} — the parser is dropping some"
    )
    return out


def _rust_keys() -> list[str]:
    return [k for k, _ in _rust_catalog()]


def _rust_gate_keys() -> list[str]:
    return [k for k, kind in _rust_catalog() if kind == "gate"]


def _rust_bridge_keys() -> list[str]:
    return [k for k, kind in _rust_catalog() if kind == "bridge"]


def _python_keys() -> list[str]:
    src = re.sub(r"#[^\n]*", "", PY.read_text())
    block = re.search(r"POSTURE_KEYS\s*=\s*\((.*?)\)", src, re.S)
    assert block, "POSTURE_KEYS not found in posture.py — did the shape change?"
    return re.findall(r'"([^"]+)"', block.group(1))


def test_posture_allow_lists_match() -> None:
    rust, py = _rust_keys(), _python_keys()
    assert rust, "parsed no keys from posture.rs"
    assert py, "parsed no keys from posture.py"

    only_rust = sorted(set(rust) - set(py))
    only_py = sorted(set(py) - set(rust))
    assert not only_rust and not only_py, (
        "POSTURE_KEYS drifted — a DB posture row would be honoured by one "
        "runtime and ignored by the other, half-applying a security gate.\n"
        f"  only in posture.rs: {only_rust or 'none'}\n"
        f"  only in posture.py: {only_py or 'none'}"
    )


def test_no_duplicate_keys() -> None:
    for name, keys in (("posture.rs", _rust_keys()), ("posture.py", _python_keys())):
        dupes = {k for k in keys if keys.count(k) > 1}
        assert not dupes, f"{name} lists {dupes} more than once"


def test_bootstrap_tier_gates_are_not_posture_managed() -> None:
    """TLS/secret gates are needed BEFORE the DB is reachable.

    Posture is read from Postgres at startup, so a gate the process needs in
    order to *reach* Postgres cannot live here — it would be applied after the
    decision that depended on it. Also covers the two that were deliberately
    removed as invariants (auth is always on, fail-closed): re-adding either
    would turn an invariant back into a knob.
    """
    forbidden = {
        "NOO_TLS_CERT", "NOO_TLS_KEY", "NOO_TLS_CA", "DATABASE_URL",
        "NOO_JWT_SECRET", "POSTGRES_PASSWORD",
        "NOO_AUTH_ENABLED", "NOO_CLUSTER_AUTH_STRICT",
    }
    for name, keys in (("posture.rs", _rust_keys()), ("posture.py", _python_keys())):
        leaked = forbidden & set(keys)
        assert not leaked, f"{name} exposes bootstrap-tier/invariant gates: {sorted(leaked)}"


def _profile_keys() -> dict[str, list[str]]:
    """Keys each vetted posture bundle sets, parsed from `posture_profile()`."""
    src = re.sub(r"//[^\n]*", "", (ROOT / "gateway-rust/src/routes/users.rs").read_text())
    block = re.search(
        r"fn posture_profile\(.*?\n\}", src, re.S
    )
    assert block, "posture_profile() not found — did the shape change?"
    out: dict[str, list[str]] = {}
    for name, body in re.findall(r'"(\w+)"\s*=>\s*Some\(&\[(.*?)\]\)', block.group(0), re.S):
        out[name] = re.findall(r'\(\s*"([A-Z_]+)"\s*,', body)
    return out


def test_profile_keys_are_all_allow_listed() -> None:
    """A profile may only set keys posture will actually accept.

    `posture_apply_profile` upserts each pair and the allow-list is checked on
    read (`apply_security_posture` skips unknown keys). So a typo'd or retired
    key in a bundle does not error — it writes a row that is then silently
    ignored, and the operator sees "applied N gates" for a gate that never
    takes effect.
    """
    allowed = set(_rust_keys())
    for profile, keys in _profile_keys().items():
        unknown = sorted(set(keys) - allowed)
        assert not unknown, (
            f"profile '{profile}' sets {unknown}, which is not in POSTURE_KEYS — "
            "those rows would be written and then ignored at startup"
        )


def test_every_gate_key_appears_in_every_profile() -> None:
    """A bundle that skips a GATE leaves it at whatever env says.

    For a customer distribution that is the difference between "hardened means
    hardened" and "hardened means hardened except the bits nobody added to the
    list". If a gate genuinely has no sensible bundle default, that is a design
    decision worth making explicit — by classifying it, not by omitting it.
    """
    gates = set(_rust_gate_keys())
    assert gates, "parsed no gate keys"
    profiles = _profile_keys()
    assert profiles, "parsed no profiles"
    for profile, keys in profiles.items():
        missing = sorted(gates - set(keys))
        assert not missing, (
            f"profile '{profile}' does not set {missing} — applying it leaves "
            "those gates at the env default rather than the bundle's intent"
        )


def test_no_profile_names_a_bridge_key() -> None:
    """R43, the live one: a profile must not close a rollout bridge.

    `noo security posture apply-profile hardened` (runbook step C1) set
    `NOO_NATS_LEGACY_SHARED_CREDS` (since retired) back to 0,
    undoing step A3 two parts earlier, and a Mac node that had not been re-provisioned fell off the bus
    until the bridge was put back by hand. The old version of this file was
    part of the cause: it REQUIRED every profile to name every key, bridges
    included, so the bug was pinned in place by a test.

    A bridge is closed by `--include-bridges`, which reads the safe value from
    the catalog — never by a profile.
    """
    bridges = set(_rust_bridge_keys())
    assert bridges, "parsed no bridge keys — the classification is not doing anything"
    profiles = _profile_keys()
    assert profiles, "parsed no profiles"
    for profile, keys in profiles.items():
        named = sorted(bridges & set(keys))
        assert not named, (
            f"profile '{profile}' names bridge key(s) {named}. Applying a "
            "profile would move a compatibility bridge the operator is holding "
            "open on purpose — which is exactly R43. Remove it from the "
            "profile; `--include-bridges` closes bridges deliberately."
        )


def test_the_known_bridges_are_classified_as_bridges() -> None:
    """Pinned by name, because these are the ones with a live incident behind
    them. Reclassifying one as a Gate silently re-arms R43."""
    bridges = set(_rust_bridge_keys())
    for key in ("NOO_CLUSTER_TOKEN_V1",):
        assert key in bridges, (
            f"{key} is a compatibility bridge, not a gate — a profile that "
            "sets it breaks a half-migrated fleet"
        )
    # ...and the gates must stay gates, or `hardened` hardens nothing.
    gates = set(_rust_gate_keys())
    for key in ("NOO_EXEC_APPROVAL_MODE", "NOO_MCP_EXTERNAL_ENABLED"):
        assert key in gates, f"{key} must be a gate so every profile sets it"


def test_retired_bridges_are_in_neither_runtime() -> None:
    """A retired bridge has no arm left to read it. Listing it in either
    allow-list would write a DB row into the env as though it meant something;
    the Rust gateway instead refuses to boot while a row holds one open
    (posture.rs RETIRED_BRIDGES)."""
    retired = ("NOO_CLUSTER_LEGACY_FULL_ACCESS", "NOO_BOOTSTRAP_ACCEPT_UNSIGNED_FETCH",
               "NOO_BUS_PRINCIPAL", "NOO_APPROVAL_BREAK_GLASS")
    rust, py = set(_rust_keys()), set(_python_keys())
    assert rust and py, "parsed nothing"
    for key in retired:
        assert key not in rust, f"{key} is retired but back in POSTURE_CATALOG"
        assert key not in py, f"{key} is retired but back in posture.py POSTURE_KEYS"
        assert f'key: "{key}"' in RUST.read_text(), f"{key} must stay declared in RETIRED_BRIDGES"


# ── The exec-approval default must be the same, fail-closed, in both runtimes ──
#
# The same half-applied-gate hazard as the allow-lists, one level down: the Rust
# gate guards the HTTP door and the Python worker guards what runs behind it. If
# their no-configuration defaults disagree, a fresh install is gated in one
# process and open in the other, and nothing logs the disagreement.

MIDDLEWARE = ROOT / "gateway-rust/src/middleware.rs"
EXEC_APPROVAL_PY = ROOT / "src/noomesh/gateway/exec_approval.py"
# `auto` runs a HIGH-risk call; `disabled` is its alias. Both are open.
OPEN_MODES = {"auto", "disabled"}


def _rust_default_mode() -> str:
    src = MIDDLEWARE.read_text()
    m = re.search(
        r'pub const DEFAULT_EXEC_APPROVAL_MODE:\s*&str\s*=\s*"([a-z]+)"', src
    )
    assert m, "DEFAULT_EXEC_APPROVAL_MODE not found in middleware.rs"
    return m.group(1)


def _python_default_mode() -> str:
    src = EXEC_APPROVAL_PY.read_text()
    m = re.search(r'^\s*DEFAULT_MODE\s*=\s*"([a-z]+)"', src, re.M)
    assert m, "ExecApprovalManager.DEFAULT_MODE not found in exec_approval.py"
    return m.group(1)


def test_exec_approval_default_is_fail_closed() -> None:
    rust = _rust_default_mode()
    assert rust not in OPEN_MODES, (
        f"the no-configuration exec-approval default is '{rust}' — a fresh "
        "install with no posture row and no env runs HIGH-risk tools (and every "
        "tool name the classifier does not recognise) with no human in the loop"
    )


def test_exec_approval_default_matches_across_runtimes() -> None:
    rust, py = _rust_default_mode(), _python_default_mode()
    assert rust == py, (
        "exec-approval default drifted: gateway-rust says "
        f"'{rust}', the Python worker says '{py}'. One process would gate a "
        "call the other runs."
    )


def test_exec_approval_mode_has_no_yaml_tier() -> None:
    """The gate must not be readable from `noomesh.yaml` in either runtime.

    `noomesh.yaml` is writable over `PUT /api/config/security`, which the
    agent's own `noo_config_set` tool reaches — a gate stored there can be
    flipped by the thing it constrains (the reason `NOO_MCP_EXTERNAL_ENABLED`
    was moved to posture in #420).
    """
    rust = MIDDLEWARE.read_text()
    start = rust.index("pub fn exec_approval_mode() -> String {")
    body = rust[start : rust.index("\n}", start)]
    assert "config_yaml" not in body, f"the Rust gate reads YAML again:\n{body}"

    py_src = (ROOT / "src/noomesh/config.py").read_text()
    assert "exec_approval_mode: Literal" not in py_src, (
        "SecurityConfig models exec_approval_mode again — the YAML key is "
        "retired and must raise, not default"
    )


def test_retired_yaml_gates_are_absent_from_the_shipped_example() -> None:
    """`noomesh.yaml.example` must not ship a key that refuses boot.

    It shipped `security.exec_approval_mode: auto` — which is how a fresh
    install ended up with the gate switched off by the distribution's own
    template. With the key now a startup refusal, shipping it would brick
    every new install instead.
    """
    import yaml  # noqa: PLC0415 — test-local

    doc = yaml.safe_load((ROOT / "noomesh.yaml.example").read_text()) or {}
    assert "exec_approval_mode" not in (doc.get("security") or {}), (
        "noomesh.yaml.example still sets security.exec_approval_mode — the "
        "gateway refuses to start on it"
    )


def test_security_config_refuses_the_retired_key() -> None:
    """Behavioural, not static: loading a config that sets it must RAISE.

    A silent ignore is the failure mode this whole change is about — an
    operator who writes `exec_approval_mode: strict` and gets `auto` has a
    control that exists only in their head.
    """
    import pytest  # noqa: PLC0415 — test-local

    from noomesh.config import SecurityConfig

    # The legitimate rest of the section still loads.
    SecurityConfig(exec_approval_timeout=300, high_risk_tools=["shell"])

    for value in ("auto", "approval", "strict"):
        with pytest.raises(ValueError, match="posture"):
            SecurityConfig(exec_approval_mode=value)


def test_the_retired_approval_gate_is_in_no_profile() -> None:
    """`NOO_APPROVAL_BREAK_GLASS` is retired (posture.rs RETIRED_BRIDGES).
    A profile naming it would write a row that boot then deletes — or, at
    any value but `0`, a row the gateway refuses to start on."""
    profiles = _profile_keys()
    assert profiles, "parsed no profiles"
    for profile, keys in profiles.items():
        assert "NOO_APPROVAL_BREAK_GLASS" not in keys, (
            f"profile '{profile}' still sets the retired NOO_APPROVAL_BREAK_GLASS"
        )
