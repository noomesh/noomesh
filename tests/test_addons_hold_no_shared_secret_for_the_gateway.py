# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The add-ons authenticate to the gateway with their own key only.

Until an earlier change retired them, the trellion and evolve add-ons' gateway clients
fell back to a cluster HMAC signed with ``NOO_CONTROLLER_SECRET`` /
``NOO_CLUSTER_SECRET`` when their exchanged service-key token was unavailable.
Both fallbacks are gone (``security/no-hmac-fallback`` in each sibling) and the
gateway refuses an add-on's HMAC (``gateway-rust/src/addon_hmac_refusal.rs``).
So the delivery follows the readers:

- **noo-evolve** runs the evolve add-on alone; nothing in it reads either secret, so
  compose hands it neither (pointer or file).
- **noo-trellion / noo-trellion-intel** run noomesh's ``worker_pool`` as their
  process. Since an earlier change it no longer reads the controller secret (bus
  principals verify with each container's OWN ``NOO_BUS_KEY``), so neither is
  handed it; the fleet secret stays for the worker plane's browser-container
  door and env check (the operator's track). Each kept delivery is listed here with
  its reader, and the reader must still exist — the day it goes, so must the
  delivery.

The reader guard (``test_secret_env_has_a_reader``) catches a delivery with no
reader at all; this file says WHY each remaining add-on delivery exists.
"""

from __future__ import annotations


from tests._compose_projection import ROOT, env_of, full_projection

SHARED = ("NOO_CONTROLLER_SECRET", "NOO_CLUSTER_SECRET")

# (service, secret) → (file, the line that reads it). Each is noomesh code
# that runs IN that container — never the add-on's own.
# Empty since neither shared secret reaches an add-on. The
# fleet secret's last use there, the browser door, has its own key now.
KEPT: dict[tuple[str, str], tuple[str, str]] = {}

ADD_ONS = ("trellion", "trellion-intel", "noo-evolve")


def _delivered(svc: dict) -> set[str]:
    """Shared secrets the service is handed: a plain name, a `_FILE` pointer,
    or a `secrets:` entry whose target names it."""
    env = env_of(svc)
    out = {n for n in SHARED if n in env or f"{n}_FILE" in env}
    for s in svc.get("secrets") or []:
        target = (s.get("target") if isinstance(s, dict) else s) or ""
        for n in SHARED:
            if target == n.lower():
                out.add(n)
    return out


def test_evolve_is_handed_neither_shared_secret() -> None:
    p = full_projection()["services"]
    assert "noo-evolve" in p, "the evolve overlay is not in the projection — this test would be vacuous"
    got = _delivered(p["noo-evolve"])
    assert not got, f"noo-evolve is handed {sorted(got)}; nothing in the add-on reads it since an earlier change"
    assert "NOO_GATEWAY_KEY_FILE" in env_of(p["noo-evolve"]), "evolve's own key is its only credential and must be delivered"


def test_every_shared_secret_an_add_on_still_gets_is_a_named_noomesh_reader() -> None:
    p = full_projection()["services"]
    seen = 0
    for svc in ADD_ONS:
        assert svc in p, svc
        for name in sorted(_delivered(p[svc])):
            seen += 1
            assert (svc, name) in KEPT, (
                f"{svc} is handed {name} with no named reason. The add-on itself stopped reading it "
                "; either name the noomesh reader that runs in this container, or stop delivering it"
            )
    assert seen == len(KEPT), f"expected the {len(KEPT)} kept deliveries, saw {seen}"


def test_each_kept_delivery_still_has_its_reader() -> None:
    for (svc, name), (path, needle) in KEPT.items():
        src = (ROOT / path).read_text(encoding="utf-8")
        assert needle in src, f"{svc}/{name}: {path} no longer reads it ({needle!r}) — stop delivering it"


def test_the_delivery_sniffer_sees_a_delivery() -> None:
    """Sanity: `_delivered` must find the trellion pair's kept pointers, or an
    empty evolve result above means a sniffer that matches nothing."""
    p = full_projection()["services"]
    assert _delivered(p["trellion"]) == set(), "an earlier change: no shared secret reaches trellion"
    assert _delivered({"environment": {"NOO_CLUSTER_SECRET_FILE": "/run/secrets/x"}}) == {"NOO_CLUSTER_SECRET"}
    assert _delivered({"secrets": [{"source": "s", "target": "noo_controller_secret"}]}) == {"NOO_CONTROLLER_SECRET"}


def test_the_add_on_sides_of_the_gateway_refusal_agree() -> None:
    """The gateway refuses exactly the actors the retired fallbacks signed as
    (`trellion`, `pai-evolve`), and nothing in this tree signs a self-call as
    one of them — the worker's channel client used `trellion` until an earlier change retired the add-on HMAC."""
    refusal = (ROOT / "gateway-rust/src/addon_hmac_refusal.rs").read_text(encoding="utf-8")
    for actor in ('("trellion", "trellion")', '("pai-evolve", "evolve")'):
        assert actor in refusal, actor
    offenders = []
    for path in sorted((ROOT / "src/noomesh").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for actor in ("trellion", "trellion-intel", "pai-evolve", "evolve"):
            for call in ("internal_gateway_headers", "create_cluster_token"):
                if f'{call}("{actor}"' in text:
                    offenders.append(f"{path.relative_to(ROOT)}: {call}({actor!r})")
    assert not offenders, offenders


def test_no_worker_plane_container_is_handed_the_controller_secret() -> None:
    """an earlier change: the controller secret reaches the gateway and nothing
    else — not the worker, its replica, or the trellion pair."""
    p = full_projection()["services"]
    holders = [svc for svc, spec in p.items() if "NOO_CONTROLLER_SECRET" in _delivered(spec)]
    assert holders == ["gateway"], holders


def test_each_bus_verifier_holds_its_own_key_and_no_other() -> None:
    """an earlier change: worker, trellion and trellion-intel each verify bus
    principals with a key of their own, sourced from their own variable."""
    p = full_projection()["services"]
    want = {"worker": "worker", "worker-extra": "worker", "trellion": "trellion", "trellion-intel": "trellion-intel"}
    for svc, aud in want.items():
        if svc not in p:
            continue
        env = env_of(p[svc])
        assert env.get("NOO_BUS_AUDIENCE") == aud, (svc, env.get("NOO_BUS_AUDIENCE"))
        assert env.get("NOO_BUS_KEY_FILE") == "/run/secrets/noo_bus_key" or "NOO_BUS_KEY_FILE" in env, svc
        sources = {s["source"] for s in p[svc].get("secrets") or [] if isinstance(s, dict) and s.get("target") == "noo_bus_key"}
        assert sources == {"noo_bus_key_" + aud.replace("-", "_")}, (svc, sources)
        others = {s.get("source") for s in p[svc].get("secrets") or [] if isinstance(s, dict)} & {
            "noo_bus_key_worker", "noo_bus_key_trellion", "noo_bus_key_trellion_intel"}
        assert others == sources, f"{svc} holds another audience's bus key: {others - sources}"
    gw = {s.get("target") for s in p["gateway"].get("secrets") or [] if isinstance(s, dict)}
    assert {"noo_bus_key_worker", "noo_bus_key_trellion", "noo_bus_key_trellion_intel"} <= gw, gw


def test_the_verify_rows_bus_verifier_list_is_the_projection() -> None:
    """Review L4: the `shared secrets` row's BUS_VERIFIERS (noo-cli
    secrets_delivery.rs) is exactly the set of composed services that verify
    bus principals — read from the projection, both ways, with the audience
    compose sets."""
    import re

    src = (ROOT / "noo-cli/src/commands/secrets_delivery.rs").read_text(encoding="utf-8")
    block = re.search(r"pub\(crate\) const BUS_VERIFIERS: &\[\(&str, &str\)\] = &\[(.*?)\];", src, re.S)
    assert block, "BUS_VERIFIERS not found"
    declared = dict(re.findall(r'\("([^"]+)",\s*"([^"]+)"\)', block.group(1)))
    p = full_projection()["services"]
    composed = {
        svc: str(env_of(spec).get("NOO_BUS_AUDIENCE"))
        for svc, spec in p.items()
        if "NOO_BUS_KEY_FILE" in env_of(spec)
    }
    assert composed, "no service in the projection verifies bus principals — the projection is empty"
    for svc, aud in composed.items():
        assert declared.get(svc) == aud, f"{svc} verifies as {aud!r} in compose but the row says {declared.get(svc)!r}"
    for svc, aud in declared.items():
        if svc in p:
            assert composed.get(svc) == aud, f"the row expects {svc} as {aud!r}; compose says {composed.get(svc)!r}"


def test_no_worker_plane_container_is_handed_the_fleet_secret() -> None:
    """an earlier change (review H1): the fleet secret is a
    node's credential. Among the controller's own services only the gateway
    (it verifies node tokens) and the containerised node agents hold it — not
    the worker, its replica, the trellion pair, evolve or the browser."""
    p = full_projection()["services"]

    def holds_fleet(svc: str, spec: dict) -> bool:
        if "NOO_CLUSTER_SECRET" not in _delivered(spec):
            return False
        # The browser's one-release bridge: the OLD pointer name aimed at its
        # OWN key's file. Judged by where it points, and by its secrets list.
        env = env_of(spec)
        targets = {s.get("source") for s in spec.get("secrets") or [] if isinstance(s, dict)}
        if svc == "browser":
            return "noo_cluster_secret" in targets or "noo_cluster_secret" in str(env.get("NOO_CLUSTER_SECRET_FILE", ""))
        return True

    holders = sorted(svc for svc, spec in p.items() if holds_fleet(svc, spec))
    assert set(holders) <= {"gateway", "node-agent", "node-agent-sensors"}, holders
    assert "gateway" in holders
    for svc in ("worker", "trellion", "trellion-intel", "noo-evolve"):
        assert svc in p, svc


def test_the_browser_key_reaches_its_holders_only() -> None:
    p = full_projection()["services"]

    def has(spec) -> bool:
        env = env_of(spec)
        return "NOO_BROWSER_KEY_FILE" in env or any(
            isinstance(s, dict) and s.get("target") == "noo_browser_key" for s in spec.get("secrets") or [])

    holders = {svc for svc, spec in p.items() if has(spec)}
    assert holders <= {"gateway", "worker", "worker-extra", "browser"}, holders
    assert {"gateway", "worker"} <= holders, holders


def test_the_browsers_old_pointer_name_carries_the_browser_key() -> None:
    """The one-release bridge: `NOO_CLUSTER_SECRET_FILE` on the
    browser points at the browser key's file, and the browser is handed no
    fleet secret at all."""
    p = full_projection()["services"]
    if "browser" not in p:
        return
    env = env_of(p["browser"])
    assert "/run/secrets/noo_browser_key" in str(env.get("NOO_CLUSTER_SECRET_FILE", "")), env.get("NOO_CLUSTER_SECRET_FILE")
    sources = {s.get("source") for s in p["browser"].get("secrets") or [] if isinstance(s, dict)}
    assert "noo_cluster_secret" not in sources, sources
