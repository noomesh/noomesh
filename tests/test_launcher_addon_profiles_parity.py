# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every launcher must select the SAME add-on profiles, from ONE helper.

Found live, 2026-09-18. `noo security secrets rotate` recreates the stack by
running `noomesh-restart.sh --force`. That script assembled its compose
profiles from the default profile plus the GPU tier and never asked which
add-ons were on, while `noomesh-start.sh` did. So a rotation of
NOO_CONTROLLER_SECRET recreated every core consumer with the new value and
left `noo-trellion-intel` — profile-gated, never selected — running on the
old one. Every extraction call it made from 2026-09-14 to 2026-09-18 was a
silent 401, fifty at a time, every twenty-five seconds.

`noomesh-rebuild.sh` had drifted the other way: it still parsed
NOO_TRELLION_INTEL_ENABLED / NOO_VOICE_ENABLED out of .env by hand — flags
`addons_guard_retired_flags` refuses to START on — so rebuild always saw
those add-ons as off.

Two kinds of assertion, on purpose. The SHAPE ones read the launchers'
source, because a hand-mirrored copy of a decision is exactly what drifted
and only "calls the shared helper" is a property a test can hold. The
BEHAVIOUR one runs the helper under a fake add-on map, because a helper that
exists but echoes the wrong flags would pass every shape check.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
LAUNCHERS = ("noomesh-start.sh", "noomesh-restart.sh", "noomesh-rebuild.sh")


def _body(name: str) -> str:
    path = SCRIPTS / name
    assert path.exists(), f"{path} is missing"
    return path.read_text()


@pytest.mark.parametrize("launcher", LAUNCHERS)
def test_launcher_sources_the_shared_addon_helper(launcher: str) -> None:
    assert "lib-addons.sh" in _body(launcher), (
        f"{launcher}: must source scripts/lib-addons.sh — the add-on "
        "decision lives there, and a launcher that cannot ask it recreates "
        "the core stack and strands the add-ons on old secrets"
    )


@pytest.mark.parametrize("launcher", LAUNCHERS)
@pytest.mark.parametrize("flag", ("NOO_TRELLION_INTEL_ENABLED", "NOO_VOICE_ENABLED"))
def test_no_launcher_branches_on_a_retired_flag(launcher: str, flag: str) -> None:
    """The flags may be *named* (the guard's error text names them) but must
    not decide anything."""
    body = _body(launcher)
    assert not re.search(rf'case\s+"?\$\{{?{flag}[^\n]*\bin\b', body), (
        f"{launcher} still branches on {flag}; lib-addons.sh declares that "
        "flag retired and refuses to start on it, so this branch is always OFF"
    )


def test_restart_selects_every_addon_profile_and_overlay() -> None:
    """Restart is what `secrets rotate --force` runs. It must ask the helper
    for the profiles, and take its compose FILE list from the one home
    (an earlier change: lib-compose.sh carries the evolve overlay)."""
    body = _body("noomesh-restart.sh")
    assert "addon_profile_args" not in body, (
        "there is no add-on profile helper since an earlier change — every add-on is "
        "an overlay in COMPOSE_FILES"
    )
    assert "lib-compose.sh" in body and "compose_file_args" in body, (
        "noomesh-restart.sh must take COMPOSE_FILES from lib-compose.sh::"
        "compose_file_args — that is where the evolve overlay is decided"
    )
    assert 'trellion-intel) echo' not in body, (
        "trellion-intel is an overlay: compose sees it whenever "
        "the add-on is on; mapping it to a profile would select a profile no service has"
    )


@pytest.mark.parametrize("launcher", ("noomesh-start.sh", "noomesh-rebuild.sh"))
def test_start_and_rebuild_resolve_intel_and_voice_through_addon_on(launcher: str) -> None:
    body = _body(launcher)
    assert "addon_on trellion_intel 0" in body, f"{launcher}: intel via addon_on (opt-in)"
    assert "addon_on voice 0" in body, f"{launcher}: voice via addon_on (opt-in)"


def _run_helper(addon_map: str, fn: str) -> str:
    """Source lib-addons.sh with a canned NOO_ADDON_MAP and echo one helper.

    The yaml loader is bypassed on purpose: this tests the DECISION, not the
    parser. `addon_on` reads $NOO_ADDON_MAP directly.
    """
    script = f"""
set -e
cd "{SCRIPTS.parent}"
NOO_ADDON_MAP_OVERRIDE=1
. scripts/lib-addons.sh
NOO_ADDON_MAP=$'{addon_map}'
{fn}
"""
    out = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=30
    )
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def _overlays(addon_map: str) -> list[str]:
    got = _run_helper(addon_map, "addon_compose_overlay_args").split()
    return [Path(p).name for p in got if p != "-f"]


def test_helper_composes_exactly_the_enabled_overlays() -> None:
    """Every add-on is an overlay: the helper composes one file
    per enabled add-on, trellion first (the Intelligent tier extends it)."""
    assert _overlays("trellion=1\\ntrellion_intel=1\\nvoice=0") == [
        "docker-compose.trellion.yml", "docker-compose.trellion-intel.yml",
    ]
    assert _overlays("trellion=1\\ntrellion_intel=1\\nvoice=1\\nevolve=1") == [
        "docker-compose.trellion.yml", "docker-compose.voice.yml",
        "docker-compose.trellion-intel.yml", "docker-compose.evolve.yml",
    ]


def test_helper_honours_trellion_opt_out_polarity() -> None:
    # No declaration at all: trellion defaults ON, the rest default OFF.
    assert _overlays("") == ["docker-compose.trellion.yml"]
    assert _overlays("trellion=0") == []


def test_helper_is_silent_when_nothing_is_on() -> None:
    got = _run_helper("trellion=0\\ntrellion_intel=0\\nvoice=0\\nevolve=0", "addon_compose_overlay_args")
    assert got == "", f"a fully-off map must echo nothing, got {got!r}"


def test_there_is_no_addon_profile_helper() -> None:
    """A profile helper is where a second switch would grow back."""
    body = (SCRIPTS / "lib-addons.sh").read_text()
    assert "addon_profile_args() {" not in body, "addon_profile_args came back — add-ons are overlays"
    for name in ("noomesh-start.sh", "noomesh-restart.sh", "noomesh-rebuild.sh", "noomesh-sandbox.sh"):
        assert "addon_profile_args" not in (SCRIPTS / name).read_text(), name


def test_no_overlay_service_is_profile_gated() -> None:
    """An add-on delivered as an OVERLAY has ONE switch: the launcher composes
    the file or it does not. A profile inside the overlay is
    a second switch, and a launcher that passes the file without it recreates
    everything except that service — what happened to noo-evolve on
    2026-09-22 (#410). Phase B deleted evolve's `profiles: ["pro"]`; this
    holds it deleted, for every overlay."""
    from tests._compose_projection import load_raw, untag
    overlays = sorted(SCRIPTS.parent.glob("docker-compose.*.yml"))
    # The base, the GPU tier, the site override and the dist pin are NOT
    # add-on overlays; profiles are their legitimate selector.
    not_addons = {"docker-compose.cluster.yml", "docker-compose.gpu-embed.yml",
                  "docker-compose.override.yml", "docker-compose.dist.yml"}
    checked = 0
    for path in overlays:
        if path.name in not_addons:
            continue
        doc = untag(load_raw(path))
        # `profiles: !reset []` is the overlay UN-gating what it inherits
        # via extends; untag() reads it as the empty list it is.
        gated = {
            name: svc.get("profiles")
            for name, svc in (doc.get("services") or {}).items()
            if svc.get("profiles")
        }
        assert not gated, (
            f"{path.name} gates {gated} behind a profile — an overlay's presence is "
            "its only switch; delete the profile, do not teach the helper to emit it"
        )
        checked += 1
    assert checked, "found no add-on overlay to check — the glob or the exclusion list broke"


def test_the_pro_profile_has_one_home() -> None:
    """start.sh and rebuild.sh each used to add `--profile pro` themselves,
    which is why the helper never learned it and restart never got it. Since
    phase B there is no pro profile to select at all: no script may name it."""
    for path in sorted(SCRIPTS.glob("*.sh")):
        live = [
            l for l in path.read_text().splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]
        hits = [l.strip() for l in live if "PRO_PROFILE" in l or "--profile pro" in l]
        assert not hits, (
            f"{path.name} still selects the pro profile: {hits} — evolve is composed "
            "by file (lib-compose.sh); the profile left its overlay in an earlier change"
        )
