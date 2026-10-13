# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""`noo stack start` and `noo stack rebuild` must agree about trellion.

an earlier change made the noo-trellion container mandatory: the in-process worker
pool is gone, and with it the gateway image's trellion dependency tree. Three
knobs encode that, and BOTH launchers have to set them or the two commands
produce containers with different environments.

They drifted. start.sh was updated to always-on; rebuild.sh kept branching on
the now-obsolete NOO_TRELLION_ENABLED with a default of OFF. The failure is
silent at rebuild time and fatal at the next gateway start: without
NOO_MIGRATIONS_ENVS=mesh the entrypoint resolves "all", hands the mesh env
to the Rust runner, and is left holding the MEMORY env — which needs
`import trellion.db`, a package the gateway image does not have.

These assertions are deliberately about the SHAPE (unconditional export), not
just the presence of the string: the broken version contained every one of
these lines, nested inside a `case` that did not fire.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
LAUNCHERS = ("noomesh-start.sh", "noomesh-rebuild.sh")

# Each knob and the value both launchers must settle on.
# NOO_MCP_GATEWAY_HOST_PORT left this table 2026-08-10: the park
# port became instance-relative (3199 + NOO_PORT_OFFSET), so the export
# lives in scripts/lib-instance.sh, which BOTH launchers source
# unconditionally — pinned by the dedicated tests at the bottom.
REQUIRED_EXPORTS = {
    "NOO_WORKER_SUPERVISOR": "external",
    "NOO_MIGRATIONS_ENVS": "mesh",
}


def _body(name: str) -> str:
    path = SCRIPTS / name
    assert path.exists(), f"{path} is missing"
    return path.read_text()


def _indentation_of_export(body: str, var: str) -> list[str]:
    """Leading whitespace of every `export VAR=` line."""
    return re.findall(rf"^([ \t]*)export {var}=", body, re.MULTILINE)


@pytest.mark.parametrize("launcher", LAUNCHERS)
@pytest.mark.parametrize("var,value", sorted(REQUIRED_EXPORTS.items()))
def test_launcher_exports_trellion_knob(launcher: str, var: str, value: str) -> None:
    body = _body(launcher)
    assert f"export {var}=" in body, (
        f"{launcher} never exports {var}. Both launchers must set it — see "
        "the 'Trellion worker pool (always on)' block."
    )
    assert value in body, f"{launcher} exports {var} but not with the value {value!r}"


@pytest.mark.parametrize("launcher", LAUNCHERS)
@pytest.mark.parametrize("var", sorted(REQUIRED_EXPORTS))
def test_trellion_knob_is_not_nested_in_a_conditional(launcher: str, var: str) -> None:
    """Top-level, so it fires regardless of NOO_TRELLION_ENABLED.

    An indented export is the exact shape of the bug: present in the file,
    inside a `case` arm that a default .env never reaches.
    """
    indents = _indentation_of_export(_body(launcher), var)
    assert indents, f"{launcher} does not export {var}"
    assert any(i == "" for i in indents), (
        f"{launcher} only exports {var} from an indented (conditional) block. "
        "The trellion container is mandatory since an earlier change — export it "
        "unconditionally at the top level."
    )


@pytest.mark.parametrize("launcher", LAUNCHERS)
def test_trellion_switch_contract(launcher: str) -> None:
    """The switch is real, and it is now the `addons:` map in noomesh.yaml.

    Both launchers must (a) resolve it through the SHARED helper — the env
    flag they each used to parse by hand is what drifted, and a shared
    function is the only version of "must mirror exactly" a test can enforce
    — with trellion's opt-out polarity (default 1), (b) never select it by
    profile (its overlay is the switch, an earlier change; noo-worker rides
    the controller profile since the phase-5 flip, so opting out is 'don't
    compose trellion', never zero Python workers), and (c) stop a leftover
    container when it is off."""
    body = _body(launcher)
    assert "lib-addons.sh" in body, (
        f"{launcher}: must source scripts/lib-addons.sh rather than parse the "
        "add-on decision itself — hand-mirrored copies are what drifted"
    )
    assert "addon_on trellion 1" in body, (
        f"{launcher}: resolve trellion through addon_on with its opt-out "
        "default (1) — an absent declaration is today's trellion-enabled shape"
    )
    # the earlier change trellion is an OVERLAY composed by
    # lib-compose.sh from the same `addon_on trellion 1`; no launcher may
    # carry a profile for it — that is the second switch the proposal forbids.
    assert "TRELLION_PROFILE" not in body and "--profile trellion" not in body, (
        f"{launcher}: selects trellion by profile; it is an overlay (docker-compose.trellion.yml)"
    )
    assert "addons_trellion_overlay" in body, (
        f"{launcher}: the OFF branch must name the overlay to reach the service it stops — "
        "the overlay is not composed when the add-on is off"
    )
    assert "TRELLION_STOP_ON_OFF" in body and "stop trellion" in body, (
        f"{launcher}: the OFF branch must STOP a leftover trellion container "
        "— `up` ignores unselected profiles, so a container from a previous "
        "enabled run keeps running (rehearsal round 2, 2026-08-13)"
    )


@pytest.mark.parametrize("launcher", LAUNCHERS)
def test_obsolete_flag_does_not_gate_behaviour(launcher: str) -> None:
    """NOO_TRELLION_ENABLED may be *mentioned* (to warn) but must not branch."""
    body = _body(launcher)
    assert not re.search(
        r'case\s+"\$\{NOO_TRELLION_ENABLED:-[^}]*\}"\s+in', body
    ), (
        f"{launcher} still branches on NOO_TRELLION_ENABLED. The flag is "
        "obsolete; gating on it is what let start and rebuild "
        "disagree about who owns the memory Alembic env."
    )


# ── fu 46: the park-port knob moved into lib-instance.sh ────────────────


@pytest.mark.parametrize("launcher", LAUNCHERS)
def test_launcher_sources_lib_instance_at_top_level(launcher: str) -> None:
    """Both launchers must source lib-instance.sh unconditionally — it
    owns the per-instance port namespace (NOO_PORT_GATEWAY, NOO_PORT_MCP,
    POSTGRES_PORT, …).
    An indented source is the same conditional-shape bug the exports above
    guard against."""
    body = _body(launcher)
    matches = re.findall(r"^([ \t]*)\. .*lib-instance\.sh", body, re.MULTILINE)
    assert matches, f"{launcher} never sources lib-instance.sh"
    assert any(i == "" for i in matches), (
        f"{launcher} only sources lib-instance.sh from an indented "
        "(conditional) block"
    )


def test_lib_instance_owns_the_park_port() -> None:
    """Trellion's dead hub mapping parks at 3199. Nothing publishes 3100
    any more: the gateway's plain-HTTP operator-door listener was removed
    in stack-v0.2.40 (the door is /mcp/operator on the gateway port), so
    the knob that published it must be gone too — a leftover default would
    re-publish a listener that no longer exists and fail compose on a
    port nothing binds."""
    body = _body("lib-instance.sh")
    assert "export NOO_MCP_GATEWAY_HOST_PORT" not in body, (
        "lib-instance.sh still exports NOO_MCP_GATEWAY_HOST_PORT — the 3100 "
        "listener it published was removed in stack-v0.2.40"
    )
    compose = (SCRIPTS.parent / "docker-compose.cluster.yml").read_text()
    # Trellion's parked mapping (host 3199 -> container 3100) may stay; the
    # gateway's publish of a host port onto ITS container :3100 may not.
    assert "NOO_MCP_GATEWAY_HOST_PORT" not in compose and "3100}:3100" not in compose, (
        "docker-compose.cluster.yml still publishes the removed 3100 listener"
    )
    assert 'NOO_PORT_MCP="$((3199 + o))"' in body, (
        "trellion's NOO_PORT_MCP must park at 3199+o — its hub is retired "
        "and two services must never default onto the same host port"
    )
    # The deriving function must RUN on source, not merely be defined.
    assert re.search(r"^noo_instance_env$", body, re.MULTILINE), (
        "lib-instance.sh defines noo_instance_env but never calls it at "
        "top level — sourcing it would export nothing"
    )

def test_worker_rides_controller_and_trellion_serves_ml() -> None:
    """Phase-5 flip pins: the slim worker is ALWAYS-ON (controller
    profile) and trellion defaults to the ML surfaces — two halves of one
    contract; breaking either strands the core subjects or double-serves
    them permanently."""
    compose = open("docker-compose.cluster.yml").read()
    assert '"controller", "worker-core"' in compose.replace("'", '"'), (
        "the worker service must carry the controller profile"
    )
    # Parse rather than string-match: the env block became an anchored
    # MAP when trellion-intel started sharing it.
    # trellion is an OVERLAY since read its own file.
    from tests._compose_projection import load_raw, untag
    from pathlib import Path as _P
    _REPO = _P(__file__).resolve().parents[1]
    tdoc = untag(load_raw(_REPO / "docker-compose.trellion.yml"))
    assert "trellion" not in (yaml_services := __import__("yaml").safe_load(compose)["services"]), (
        "trellion is back in the base file — it is an overlay"
    )
    trellion = tdoc["services"]["trellion"]
    assert (
        str(trellion["environment"]["NOO_WORKER_SURFACES"])
        == "${NOO_WORKER_SURFACES:-ml}"
    ), "trellion must default to surfaces=ml after the flip"
    assert not trellion.get("profiles"), (
        "trellion must carry no profile — composing its overlay is the switch; "
        "the 2026-08-13 rehearsal showed a profile-gated opt-out disabling behavior "
        "while the container still started"
    )
    # Intelligent tier: an OVERLAY that `extends` this service across files
    #. Its no-drift property is only visible in the
    # COMPOSED projection — the overlay's text carries three keys and the
    # container gets the whole inherited allowlist — so that is what the
    # rest of this test reads.
    from tests._compose_projection import env_of, load_raw, projection, untag
    REPO = Path(__file__).resolve().parents[1]
    raw = untag(load_raw(REPO / "docker-compose.trellion-intel.yml"))["services"]["trellion-intel"]
    assert raw.get("extends") == {"file": "docker-compose.trellion.yml", "service": "trellion"}, (
        "trellion-intel must EXTEND the base trellion service — restating the "
        "environment would be a second home for the allowlist"
    )
    proj = projection("docker-compose.trellion.yml", "docker-compose.trellion-intel.yml")["services"]
    p_trellion, p_intel = proj["trellion"], proj["trellion-intel"]
    assert "profiles" not in p_intel or not p_intel["profiles"], (
        "the intel overlay must `!reset` the profile it inherits — with it, the "
        "file is passed and the service stays hidden"
    )
    assert not p_intel.get("ports"), "the parked 3199 mapping must not double-bind (ports: !reset [])"
    e_trellion, e_intel = env_of(p_trellion), env_of(p_intel)
    assert e_intel["NOO_WORKER_SURFACES"] == "ml-intel"
    assert e_intel["NOO_SKIP_MIGRATIONS"] == "1"
    # trellion-intel diverges from trellion in exactly three places, and each
    # one is deliberate: its surface, its migrations flag, and — since
    # noomesh the design — the per-consumer gateway key that ONLY it holds.
    # Anything else diverging is drift.
    # the earlier change the key arrives as a FILE: the env carries the
    # `NOO_GATEWAY_KEY_FILE` pointer, and the pointer's variable is what
    # differs (test_compose_secret_files.py resolves pointer → secret →
    # source to prove the FILE differs too).
    per_consumer = "NOO_GATEWAY_KEY_FILE"
    # the same holds for the bus-principal key, and the
    # audience name beside it — intel's own, never trellion's.
    for bus in ("NOO_BUS_KEY_FILE", "NOO_BUS_AUDIENCE"):
        assert e_trellion[bus] != e_intel[bus], f"trellion and trellion-intel share {bus}"
    # BOTH hold this, and that is not drift — what
    # matters is that each is fed from its OWN registry secret. Same key
    # NAME, different SOURCE.
    assert e_trellion[per_consumer] != e_intel[per_consumer], (
        f"trellion and trellion-intel interpolate the same value for {per_consumer} — "
        "that is one secret with two holders, not two per-consumer keys "
        "(see tests/test_per_consumer_key_is_not_shared.py)"
    )
    divergent = ("NOO_WORKER_SURFACES", "NOO_SKIP_MIGRATIONS", per_consumer, "NOO_BUS_KEY_FILE", "NOO_BUS_AUDIENCE")
    shared_intel = {k: v for k, v in e_intel.items() if k not in divergent}
    shared_trellion = {k: v for k, v in e_trellion.items() if k not in divergent}
    assert len(shared_intel) > 20, f"the intel projection inherited only {len(shared_intel)} vars — extends did not resolve"
    assert shared_intel == shared_trellion, (
        "trellion-intel must inherit trellion's env allowlist verbatim (via extends); diff: "
        f"{sorted(set(shared_intel.items()) ^ set(shared_trellion.items()))}"
    )
    # And the build is replaced, not merged: a merged build keeps the parent's
    # args and contexts, and the intel Dockerfile then builds against both.
    b_intel = p_intel.get("build") or {}
    assert "DEPS_BASE" not in (b_intel.get("args") or {}), "intel build merged the parent's args (build: !override)"
    # The core carries no add-on build recipe: intel builds from its own repository.
    assert "trellion_intel" not in (b_intel.get("additional_contexts") or {}), b_intel.get("additional_contexts")
