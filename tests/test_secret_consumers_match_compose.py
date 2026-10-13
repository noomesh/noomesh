# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A secret's declared consumers must include every container compose gives it to.

`SecretSpec.consumers` is not documentation. `noo security secrets rotate`
recreates exactly those containers, and #258's verdict — the one that refuses
to call a rotation successful — judges exactly those containers. A holder
missing from the list is therefore invisible twice: it is not recreated, and
its absence is not noticed. It keeps the OLD value, and a refused credential
logs nothing.

That is an earlier change one layer up. There the launcher skipped a
profile-gated container; here the registry never names it. The shape is the
same and so is the silence.

Found 2026-09-20: thirteen secrets had undeclared holders, and the missing
services were the same three every time — `trellion-intel`, `worker`,
`worker-extra`. Each arrived after the lists were written, and each merges an env anchor, so it picked up secrets without
anyone editing a consumer list.

The rule is ONE-DIRECTIONAL: every compose holder must be declared. Extra
declared names are fine and expected — `noo-node-agent` and
`noo-node-agent-sensors` run on nodes, from a different file.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.cluster.yml"
SECRETS_RS = ROOT / "noo-cli" / "src" / "commands" / "secrets.rs"
# Compose service `gateway` is container `noo-gateway`; the prefix is
# NOO_CONTAINER_PREFIX, whose default is the only value the registry names.
PREFIX = "noo-"


def _env(service: dict) -> dict:
    env = service.get("environment") or {}
    if isinstance(env, list):
        out = {}
        for item in env:
            k, _, v = str(item).partition("=")
            out[k] = v
        return out
    return env


@pytest.fixture(scope="module")
def compose_holders() -> dict[str, set[str]]:
    # The composed projection (base + every add-on overlay): trellion-intel
    # `extends` trellion across files the earlier change, and its
    # inherited holdings are not in any one file's text.
    from tests._compose_projection import full_projection
    doc = full_projection()
    services = doc.get("services") or {}
    assert services, f"{COMPOSE} parsed to zero services — the assertions would be vacuous"
    holders: dict[str, set[str]] = {}
    for name, svc in services.items():
        # The evolve overlay names its service `noo-evolve` outright; every
        # base service gets the prefix from container_name.
        container = name if name.startswith(PREFIX) else PREFIX + name
        for key, val in _env(svc).items():
            # A `NAME_FILE` pointer (compose `secrets:` delivery) holds NAME
            # just as a plain `NAME` does: a rotation must recreate it too.
            # the earlier change no container carries NOO_JWT_SECRET
            # plainly, so without this the check below would see nothing.
            held = key.removesuffix("_FILE")
            # …unless the pointer is gated on a DIFFERENT store key
            # (`NOO_CLUSTER_SECRET_FILE: ${NOO_BROWSER_KEY:+/run/secrets/…}`,
            # the browser's one-release bridge): then the file
            # is that key's, and that is what the container holds.
            m = re.match(r"\$\{([A-Z0-9_]+):\+/run/secrets/", str(val))
            if key.endswith("_FILE") and m and m.group(1) != held and held == "NOO_CLUSTER_SECRET":
                held = m.group(1)
            holders.setdefault(held, set()).add(container)
    assert "NOO_JWT_SECRET" in holders, "parsed no JWT secret holder — the parse is wrong"
    return holders


@pytest.fixture(scope="module")
def declared() -> dict[str, set[str]]:
    src = SECRETS_RS.read_text()
    specs = re.findall(r'key:\s*"([A-Z0-9_]+)".*?consumers:\s*&\[(.*?)\]', src, re.S)
    assert len(specs) > 10, f"parsed only {len(specs)} SecretSpecs — the regex missed the table"
    out = {key: set(re.findall(r'"([^"]+)"', cons)) for key, cons in specs}
    # Add-on keys are not hand-written rows since the
    # build script derives them from each overlay's `x-noo-addon`, so the
    # registry the CLI runs is the core rows plus these.
    from tests._addon_decls import decls
    for d in decls():
        assert d.key not in out, (
            f"{d.key} is both a hand-written row in secrets.rs and declared by {d.overlay} — "
            "two answers to who holds it"
        )
        out[d.key] = set(d.containers)
    return out


def test_every_container_compose_hands_a_secret_to_is_declared(
    compose_holders: dict[str, set[str]], declared: dict[str, set[str]]
) -> None:
    drift: list[str] = []
    for key, live in sorted(compose_holders.items()):
        if key not in declared:
            continue  # not a registry-managed secret; nothing to rotate
        missing = live - declared[key]
        if missing:
            drift.append(f"  {key}: compose also gives it to {sorted(missing)}")
    assert not drift, (
        "these containers hold a secret the registry does not name:\n"
        + "\n".join(drift)
        + "\n\n`secrets rotate` recreates the DECLARED consumers and #258's verdict judges "
        "the DECLARED consumers, so an undeclared holder is skipped AND unnoticed — it keeps "
        "the old value, and a refused credential logs nothing."
    )


def test_a_secret_reached_by_INTERPOLATION_is_declared_too(
    declared: dict[str, set[str]]
) -> None:
    """A registry key can reach a container under a DIFFERENT env var name.

    `NOO_GATEWAY_KEY=${NOO_SVC_KEY_WORKER:-}` makes noo-worker a holder of
    NOO_SVC_KEY_WORKER, but the name compose uses is NOO_GATEWAY_KEY, so the
    name-matching assertion above cannot see it. That gap was real: the worker
    key named `noo-worker` and not `noo-worker-extra`, which receives it
    through the same interpolation — a rotation would have recreated one and
    stranded every replica.
    """
    from tests._compose_projection import full_projection
    doc = full_projection()
    drift: list[str] = []
    for key, names in sorted(declared.items()):
        holders = {
            (svc if svc.startswith(PREFIX) else PREFIX + svc)
            for svc, s in (doc.get("services") or {}).items()
            # Boundary-matched, not a prefix: `${NOO_SVC_KEY_TRELLION_INTEL:-}`
            # CONTAINS `${NOO_SVC_KEY_TRELLION`, and a prefix match reported
            # trellion-intel as a holder of trellion's key — a false positive
            # that would have been "fixed" by declaring something untrue.
            if any(
                re.search(r"\$\{" + re.escape(key) + r"[:}\-]", str(v))
                for v in _env(s).values()
            )
        }
        missing = holders - names
        if missing:
            drift.append(f"  {key}: interpolated into {sorted(missing)}")
    assert not drift, (
        "these containers receive a registry secret through interpolation under another "
        "env var name, and are not declared:\n" + "\n".join(drift)
        + "\n\nThe name-matching test cannot see these: compose says "
        "`NOO_GATEWAY_KEY=${NOO_SVC_KEY_X:-}`, so the holder is only visible by following "
        "the interpolation. `rotate` recreates the declared consumers, so an undeclared "
        "one keeps the old value."
    )


def test_a_replica_is_declared_wherever_its_original_is(
    compose_holders: dict[str, set[str]], declared: dict[str, set[str]]
) -> None:
    """`worker-extra` is `worker` scaled. It merges the same
    environment, so it holds the same secrets — and a rotation that recreates
    `worker` alone leaves every replica on the old value."""
    for key, names in declared.items():
        if f"{PREFIX}worker" in names and f"{PREFIX}worker-extra" in compose_holders.get(key, set()):
            assert f"{PREFIX}worker-extra" in names, (
                f"{key} names noo-worker but not its replica noo-worker-extra; a rotation would "
                "recreate one and strand the others"
            )


def test_a_secret_reached_through_a_DERIVED_pgpass_is_declared_too(
    declared: dict[str, set[str]]
) -> None:
    """Since 2026-09-29 no DSN interpolates a role password: the launcher
    DERIVES a pgpass body from it (`NOO_PGPASS_ROLES_*` in lib-secrets.sh)
    and compose delivers that body as a file. So `POSTGRES_PASSWORD` reaches
    noo-gateway, and `NOO_APP_DB_PASSWORD` the worker and its replicas,
    without the key's name appearing anywhere in their environment — the
    two assertions above cannot see it, and a rotation that skipped them
    would leave a stale password in a pgpass file."""
    from tests._compose_projection import full_projection
    from tests.test_compose_secret_files import _shell_roles, top_level_secrets

    sources = top_level_secrets()
    roles = _shell_roles()
    doc = full_projection()
    checked = 0
    drift: list[str] = []
    for svc, s in (doc.get("services") or {}).items():
        container = svc if svc.startswith(PREFIX) else PREFIX + svc
        for sec in s.get("secrets") or []:
            var = sources.get(sec["source"] if isinstance(sec, dict) else sec)
            if var not in roles:
                continue
            for _role, key in roles[var][1]:
                checked += 1
                if container not in declared.get(key, set()):
                    drift.append(f"  {key}: reaches {container} through {var}")
    assert checked >= 4, f"only {checked} derived (container, key) pairs — the parse is wrong"
    assert not drift, "a derived pgpass carries a secret to a container its registry row does not name:\n" + "\n".join(drift)
