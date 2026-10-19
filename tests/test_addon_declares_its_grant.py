# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""An add-on's overlay declares the grant its gateway key asks for.

an earlier change. Each add-on overlay that hands a container its own
gateway key (`NOO_GATEWAY_KEY: ${NOO_SVC_KEY_<X>:-}`) carries a top-level
`x-noo-addon` block naming the add-on, the `noo_service_keys` consumer, the
store key, every container that holds it, and the scopes it asks for.
noo-cli's build script derives the secret-registry rows and the default grant
from these blocks, so the block IS the registry for add-on keys — and a block
that disagrees with the compose it sits above would make `rotate` recreate the
wrong containers (an earlier change's silence) or `provision` ask for a word the
gateway refuses (PR 343's first live run).

The blocks are read per file (tests/_addon_decls.py). What each container
actually receives is read from the composed projection, so an overlay
that `extends` another inherits across files.
"""

from __future__ import annotations

import re

import pytest

from tests._addon_decls import BLOCK, block_of, decls
from tests._compose_projection import (
    ADDON_OVERLAYS,
    ROOT,
    env_of,
    full_projection,
    load_raw,
    untag,
)
from tests._scope_vocabulary import NOT_ASKABLE, issuable

KEY_VAR = "NOO_GATEWAY_KEY"
ADDONS_RS = ROOT / "noo-cli/src/commands/addons.rs"
PREFIX = "noo-"


def _container(service: str) -> str:
    # Base-style services get the prefix from container_name; evolve names its
    # service `noo-evolve` outright.
    return service if service.startswith(PREFIX) else PREFIX + service


def _kebab(s: str) -> str:
    return s.lower().replace("_", "-")


def _addon_rows() -> set[str]:
    m = re.search(r"pub const ADDON_ROWS: &\[AddonRow\] = &\[(.*?)\n\];", ADDONS_RS.read_text(), re.S)
    assert m, "ADDON_ROWS not found in addons.rs — the parse broke"
    keys = set(re.findall(r'key:\s*"([a-z_]+)"', m.group(1)))
    assert {"trellion", "evolve"} <= keys, f"parsed {keys!r} — the parse broke"
    return keys


def _interpolates(value: str, key: str) -> bool:
    # Boundary-matched: `${NOO_SVC_KEY_TRELLION_INTEL:-}` contains
    # `${NOO_SVC_KEY_TRELLION`, and a prefix match would call trellion-intel a
    # holder of trellion's key.
    return bool(re.search(r"\$\{" + re.escape(key) + r"[:}\-]", str(value)))


def _secret_sources() -> dict[str, str]:
    """Top-level secret name → source variable, across every overlay."""
    return {k: v.get("x-noo-source") for k, v in (full_projection().get("secrets") or {}).items()}


def _delivered_key(svc: dict) -> str | None:
    """How the container receives its gateway key, normalised to the
    interpolation it stands for: a plain `NOO_GATEWAY_KEY: ${X:-}` → that
    text; a file — `NOO_GATEWAY_KEY_FILE:
    ${X:+/run/secrets/<t>}` plus a secret targeting `<t>` sourced from X —
    → `${X:-}` too, but only when the pointer's variable and the FILE's
    source agree (intel inherits trellion's secrets list; a pointer naming
    intel's variable over trellion's file must not read as intel's key)."""
    env = env_of(svc)
    if (env.get(KEY_VAR) or "").strip():
        return env[KEY_VAR]
    ptr = env.get(KEY_VAR + "_FILE") or ""
    m = re.fullmatch(r"\$\{([A-Z0-9_]+):\+/run/secrets/([a-z0-9_]+)\}", ptr)
    if not m:
        return None
    entries = [
        e for e in (svc.get("secrets") or []) if isinstance(e, dict) and e.get("target") == m.group(2)
    ]
    if len(entries) != 1 or _secret_sources().get(entries[0]["source"]) != m.group(1):
        return f"<file {m.group(2)} not sourced from {m.group(1)}>"
    return "${" + m.group(1) + ":-}"


def _holds(svc: dict, key: str) -> bool:
    """Does the container receive `key` — interpolated into its env, or as a
    compose secret sourced from it?"""
    if any(_interpolates(v, key) for v in env_of(svc).values()):
        return True
    sources = _secret_sources()
    return any(
        sources.get(e["source"] if isinstance(e, dict) else e) == key for e in (svc.get("secrets") or [])
    )


@pytest.fixture(scope="module")
def services() -> dict:
    svcs = full_projection()["services"]
    assert svcs, "the projection has zero services — the assertions would be vacuous"
    return svcs


def test_an_overlay_that_delivers_a_gateway_key_declares_it_and_one_that_does_not_delivers_none(
    services: dict,
) -> None:
    checked = 0
    for overlay in ADDON_OVERLAYS:
        own = (untag(load_raw(ROOT / overlay)).get("services") or {}).keys()
        assert own, f"{overlay} declares no services — the read broke"
        delivering = sorted(s for s in own if _delivered_key(services[s]))
        has_block = block_of(overlay) is not None
        if delivering:
            assert has_block, (
                f"{overlay} hands {KEY_VAR} to {delivering} but has no {BLOCK} block — the key "
                "has no registry row, so `rotate` never recreates its holder and `provision` "
                "cannot name it"
            )
        else:
            assert not has_block, (
                f"{overlay} declares {BLOCK} but no service in it receives {KEY_VAR}"
            )
        checked += 1
    assert checked == len(ADDON_OVERLAYS)


def test_voice_holds_no_gateway_credential(services: dict) -> None:
    """Voice (whisper + piper) never calls the gateway. That is a checked
    statement, not an omission: a key appearing there would need a block."""
    own = untag(load_raw(ROOT / "docker-compose.voice.yml")).get("services") or {}
    assert own, "docker-compose.voice.yml parsed to zero services"
    for name in own:
        assert KEY_VAR not in env_of(services[name]), f"voice's {name} receives {KEY_VAR}"
    assert block_of("docker-compose.voice.yml") is None


def test_each_block_names_itself_consistently() -> None:
    rows = _addon_rows()
    for d in decls():
        assert re.fullmatch(r"NOO_SVC_KEY_[A-Z0-9_]+", d.key), f"{d.overlay}: key {d.key!r}"
        suffix = d.key.removeprefix("NOO_SVC_KEY_")
        assert d.consumer == "svc:" + _kebab(suffix), (
            f"{d.overlay}: consumer {d.consumer!r} is not svc:{_kebab(suffix)} — the store key "
            "and the noo_service_keys row would name two different consumers"
        )
        assert d.addon in rows, f"{d.overlay}: addon {d.addon!r} is not an ADDON_ROWS key"
        assert d.overlay == f"docker-compose.{_kebab(d.addon)}.yml", (
            f"{d.overlay} declares addon {d.addon!r}; lib-addons.sh maps that add-on to "
            f"docker-compose.{_kebab(d.addon)}.yml"
        )
        assert d.containers, f"{d.overlay}: containers is empty"
        for c in d.containers:
            assert c.startswith(PREFIX), f"{d.overlay}: container {c!r} is not noo-*"


def test_the_declared_containers_are_exactly_the_keys_holders(services: dict) -> None:
    """Both directions. A holder missing from `containers` is not recreated on
    a rotate and keeps the old value; a container named that does not hold
    the key is a recreate that proves nothing."""
    for d in decls():
        holders = {_container(s) for s, svc in services.items() if _holds(svc, d.key)}
        assert holders == set(d.containers), (
            f"{d.overlay} declares {d.key} held by {sorted(d.containers)}; compose interpolates "
            f"it into {sorted(holders)}"
        )
        for c in d.containers:
            svc = next(s for s in services if _container(s) == c)
            value = _delivered_key(services[svc]) or ""
            assert value == "${" + d.key + ":-}", (
                f"{c}'s {KEY_VAR} is {value!r}; the declaration says it is ${{{d.key}:-}}"
            )


def test_every_asked_scope_is_one_the_gateway_issues() -> None:
    for d in decls():
        assert d.scopes, f"{d.overlay}: scopes is empty — a key that opens nothing"
        for s in d.scopes:
            assert s not in NOT_ASKABLE, (
                f"{d.overlay} asks for {s!r}; an add-on may not ask for {sorted(NOT_ASKABLE)} "
                "(`addon` is always added by the CLI)"
            )
            assert issuable(s), (
                f"{d.overlay} asks for {s!r}, which the gateway would refuse at issue — "
                "`provision` would fail on its first live run"
            )
        assert len(set(d.scopes)) == len(d.scopes), f"{d.overlay}: a scope is listed twice"


def test_no_two_declarations_share_a_key_a_consumer_or_an_addon() -> None:
    ds = decls()
    for field in ("key", "consumer", "addon"):
        values = [getattr(d, field) for d in ds]
        assert len(set(values)) == len(values), (
            f"two {BLOCK} blocks share a {field}: {values} — one secret with two holders is "
            "the shared-secret problem wearing a per-consumer name"
        )


# test_evolves_dev_overlay_agrees_with_the_dist_declaration: moved with the overlay to the add-on repo (N6)
