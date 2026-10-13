# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A per-consumer gateway key must reach exactly one consumer.

noomesh an earlier change. `NOO_GATEWAY_KEY` is trellion-intel's OWN credential — a
named row in `noo_service_keys`, scoped, quota-capped, revocable, with a
`last_used_at`. Its whole value over `NOO_CONTROLLER_SECRET` is that ONE
container holds it, so it can be rotated, revoked and observed on its own.

Declaring it in the shared `*trellion-env` anchor would hand it to every
service that merges the anchor, and rebuild the shared-secret problem with
extra steps — the problem being that a rotation is then all-or-nothing and
only as good as the recreate, which on 2026-09-14 missed the profile-gated
noo-trellion-intel for four days.

The assertions read the compose projection, not the YAML text: the anchor is
a merge key, so a value added to it appears in every merging service's
`environment` without the string ever appearing near their definitions.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

COMPOSE = Path(__file__).resolve().parents[1] / "docker-compose.cluster.yml"
KEY = "NOO_GATEWAY_KEY"

# service -> the registry secret that service's key MUST come from.
# The CORE rows are written here; every add-on's row comes from its overlay's
# `x-noo-addon` block, so a new add-on declares its key
# in one place and this guard still insists it has a source of its OWN.
CORE_OWNERS = {
    "worker": "NOO_SVC_KEY_WORKER",
    # A REPLICA of noo-worker (the design, `deploy.replicas: ${NOO_WORKER_EXTRA}`),
    # not a second consumer: same image, same role, scaled horizontally. One key
    # per SERVICE is the unit that matters — giving each replica its own would
    # make `last_used_at` say "some replica called", which answers nothing, and
    # a revocation would have to chase a count that changes with load.
    "worker-extra": "NOO_SVC_KEY_WORKER",
}


def _service_of(container: str) -> str:
    # `noo-trellion` is service `trellion`; evolve names its service
    # `noo-evolve` outright. Resolved against the services as written, not
    # guessed from the spelling.
    from tests._compose_projection import raw_services_union
    names = raw_services_union()
    hits = [s for s in names if s == container or "noo-" + s == container]
    assert len(hits) == 1, f"container {container!r} resolves to services {hits}"
    return hits[0]


def _owners() -> dict[str, str]:
    from tests._addon_decls import decls
    out = dict(CORE_OWNERS)
    for d in decls():
        for c in d.containers:
            out[_service_of(c)] = d.key
    return out


OWNERS = _owners()

# Services that deliberately share another's source because they ARE that
# service. Sharing is otherwise forbidden, so each entry is a decision.
REPLICAS = {"worker-extra": "worker"}
# Services whose environment is a LIST rather than a mapping still merge the
# same anchor; `_env` normalises both. Only the services that inherit the
# shared block — trellion merges the anchor, trellion-intel EXTENDS trellion
# — are checked for inheritance.
ANCHOR_MERGERS = ("trellion", "trellion-intel")


@pytest.fixture(scope="module")
def services() -> dict:
    # The COMPOSED projection, not the base text: trellion-intel is an overlay
    # that `extends` trellion, and what it holds is only
    # visible after compose resolves the inheritance.
    from tests._compose_projection import full_projection
    svcs = full_projection()["services"]
    assert svcs, "the projection has zero services — the assertions below would be vacuous"
    return svcs


def _env(service: dict) -> dict:
    """A service's environment as a mapping, whichever form it uses.

    `NOO_GATEWAY_KEY_FILE` counts as the key: noo-worker's key arrives as a
    FILE since 2026-09-29 (compose `secrets:`), pointed at by
    `NOO_GATEWAY_KEY_FILE=${NOO_SVC_KEY_WORKER:+/run/secrets/noo_gateway_key}`
    — the same one source, the same one holder."""
    env = service.get("environment") or {}
    if isinstance(env, list):
        out = {}
        for item in env:
            k, _, v = str(item).partition("=")
            out[k] = v
    else:
        out = dict(env)
    if KEY + "_FILE" in out and KEY not in out:
        out[KEY] = out.pop(KEY + "_FILE")
    return out


def test_only_declared_owners_receive_the_key(services: dict) -> None:
    holders = sorted(name for name, svc in services.items() if KEY in _env(svc))
    assert holders == sorted(OWNERS), (
        f"{KEY} reaches {holders}; the declared owners are {sorted(OWNERS)}. If this grew "
        "without a row in OWNERS, the likely cause is the key being added to a shared "
        "anchor — which hands it to every merging service and makes it a shared secret "
        "again."
    )


def test_no_two_owners_share_a_source(services: dict) -> None:
    """Two consumers reading the same registry secret is the shared-secret
    problem wearing a per-consumer name: one rotation would move both, and
    `last_used_at` could no longer say which of them is still calling."""
    sources = {svc: _env(services[svc])[KEY] for svc in OWNERS if svc not in REPLICAS}
    seen: dict[str, str] = {}
    for svc, value in sources.items():
        for other, other_value in seen.items():
            assert value != other_value, (
                f"{svc} and {other} both interpolate {value!r} — that is one secret with "
                "two holders, not two per-consumer keys"
            )
        seen[svc] = value


def test_a_replica_carries_exactly_its_originals_key(services: dict) -> None:
    """A replica must read the SAME source as the service it replicates. A
    replica pointed at a different (or missing) var authenticates as somebody
    else, or falls back to the shared secret while its original does not —
    and the difference only shows under load, when replicas exist at all."""
    for replica, original in REPLICAS.items():
        assert _env(services[replica])[KEY] == _env(services[original])[KEY], (
            f"{replica} replicates {original} but interpolates a different value for {KEY}"
        )


def test_the_shared_anchor_never_carries_the_key(services: dict) -> None:
    """The anchor is what these services SHARE. A per-consumer key in it is
    inherited by every merger — the exact shape this file exists to forbid,
    and the reason the anchor was hoisted out of the trellion service (it used
    to BE trellion's environment block, so trellion could own nothing)."""
    # The anchor lives in the trellion overlay the earlier change.
    from tests._compose_projection import load_raw, untag
    doc = untag(load_raw(COMPOSE.parent / "docker-compose.trellion.yml"))
    shared = doc.get("x-trellion-env") or {}
    assert shared, "x-trellion-env is missing — the assertions below would be vacuous"
    assert KEY not in shared, (
        f"{KEY} is declared in the shared x-trellion-env anchor, so every merging service "
        "inherits it"
    )


def test_every_owner_still_inherits_the_shared_environment(services: dict) -> None:
    """The override must ADD to the merged anchor, not replace it. A local
    `environment:` block that dropped `<<: *trellion-env` would silently strip
    the database URLs and every other inherited value."""
    for svc in ANCHOR_MERGERS:
        env = _env(services[svc])
        assert "NOO_TRELLION_DATABASE_URL" in env, (
            f"{svc} no longer inherits *trellion-env — the local environment block "
            "replaced the merge instead of extending it"
        )


def test_each_key_is_wired_to_its_own_registry_secret(services: dict) -> None:
    """It must interpolate the per-consumer secret, not a shared one. Pointing
    it at NOO_CONTROLLER_SECRET would satisfy every other test here while
    delivering exactly the shared value this exists to stop using."""
    for svc, source in OWNERS.items():
        value = _env(services[svc])[KEY]
        assert source in value, (
            f"{svc}'s {KEY} interpolates {value!r}; it must come from {source}"
        )
        for shared in ("NOO_CONTROLLER_SECRET", "NOO_CLUSTER_SECRET", "NOO_JWT_SECRET"):
            assert shared not in value, f"{svc}'s {KEY} must not be fed from the shared {shared}"


def test_each_defaults_to_empty_so_every_install_keeps_working(services: dict) -> None:
    """Absent is the default and must stay safe: trellion's gateway_auth.py
    falls through to the shared HMAC on an unset OR blank value, so the
    interpolation needs the `:-` form rather than failing the launch. A
    file-delivered key uses `:+` instead — unset store value, unset pointer,
    the same fall-through — and the launcher exports the source empty so
    compose creates the service (lib-secrets.sh derive_file_secrets)."""
    for svc in OWNERS:
        value = _env(services[svc])[KEY]
        assert ":-" in value or re.fullmatch(r"\$\{[A-Z0-9_]+:\+/run/secrets/[a-z0-9_]+\}", value), (
            f"{svc}'s {KEY} interpolates {value!r} with no default — an install that has "
            "minted no key would fail to launch instead of falling back to the HMAC"
        )
