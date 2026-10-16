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

import os
import re
import shutil
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
    (an earlier change: lib-compose.sh composes every add-on overlay)."""
    body = _body("noomesh-restart.sh")
    assert "addon_profile_args" not in body, (
        "there is no add-on profile helper since an earlier change — every add-on is "
        "an overlay in COMPOSE_FILES"
    )
    assert "lib-compose.sh" in body and "compose_file_args" in body, (
        "noomesh-restart.sh must take COMPOSE_FILES from lib-compose.sh::"
        "compose_file_args — that is where every add-on overlay is decided"
    )
    assert 'trellion-intel) echo' not in body, (
        "trellion-intel is an overlay: compose sees it whenever "
        "the add-on is on; mapping it to a profile would select a profile no service has"
    )


@pytest.mark.parametrize("launcher", ("noomesh-start.sh", "noomesh-rebuild.sh"))
def test_start_and_rebuild_resolve_addons_through_the_helper(launcher: str) -> None:
    """Voice (a core overlay) is decided by `addon_on`; every licensed
    add-on is reported and, when off, stopped by the generic helpers — the
    launcher names none of them (N6: their overlays travel in their
    bundles)."""
    body = _body(launcher)
    assert "addon_on voice 0" in body, f"{launcher}: voice via addon_on (opt-in)"
    assert "addons_report_licensed" in body, f"{launcher}: licensed add-ons via addons_report_licensed"
    assert "addons_stop_disabled" in body, f"{launcher}: a switched-off licensed add-on is stopped"
    for retired in ("addons_evolve_overlay", "addons_trellion_intel_overlay"):
        assert retired not in body, f"{launcher} still calls {retired} — the generic loop replaced it"


def _run_helper(addon_map: str, fn: str, *, root: Path | None = None,
                env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Source lib-addons.sh with a canned NOO_ADDON_MAP and run one helper.

    The yaml loader is bypassed on purpose: this tests the DECISION, not the
    parser. `addon_on` reads $NOO_ADDON_MAP directly. `root` is an install
    tree holding its own copy of scripts/lib-addons.sh (the helper resolves
    overlays relative to the file it was sourced from).
    """
    root = root or SCRIPTS.parent
    script = f"""
set -e
cd "{root}"
NOO_ADDON_MAP_OVERRIDE=1
. scripts/lib-addons.sh
NOO_ADDON_MAP=$'{addon_map}'
{fn}
"""
    full_env = {k: v for k, v in os.environ.items()
                if not (k.startswith("NOO_") and k.endswith("_PATH")) and k != "CORE_ONLY"}
    full_env.update(env or {})
    out = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=30, env=full_env
    )
    assert out.returncode == 0, out.stderr
    return out


def _overlays(addon_map: str, **kw) -> list[str]:
    got = _run_helper(addon_map, "addon_compose_overlay_args", **kw).stdout.split()
    return [p for p in got if p != "-f"]


def _names(addon_map: str, **kw) -> list[str]:
    return [Path(p).name for p in _overlays(addon_map, **kw)]


_SYNTH_OVERLAY = """services:
  noo-example-addon:
    image: ${NOO_ADDON_IMAGE_EXAMPLE:-ghcr.io/example/noo-example-addon:0.0.0}
"""


@pytest.fixture
def install(tmp_path: Path) -> Path:
    """A synthetic install: the shipped helper, the two core overlays, and
    a licensed add-on (`example_addon`) materialised from its bundle at
    addons/<name>/docker-compose.yml. Nested one level so the dev-checkout
    default (`../noo-<kebab>`) cannot find anything by accident."""
    root = tmp_path / "box" / "install"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(SCRIPTS / "lib-addons.sh", root / "scripts" / "lib-addons.sh")
    for core in ("docker-compose.trellion.yml", "docker-compose.voice.yml"):
        (root / core).write_text("services: {}\n")
    bundle = root / "addons" / "example_addon"
    bundle.mkdir(parents=True)
    (bundle / "docker-compose.yml").write_text(_SYNTH_OVERLAY)
    return root


def test_core_overlays_compose_in_order(install: Path) -> None:
    """trellion first (a licensed add-on's overlay may extend it), then voice."""
    assert _names("trellion=1\\nvoice=1", root=install) == [
        "docker-compose.trellion.yml", "docker-compose.voice.yml",
    ]
    assert _names("trellion=1\\nvoice=0", root=install) == ["docker-compose.trellion.yml"]


def test_a_licensed_addon_that_is_on_composes_its_bundle(install: Path) -> None:
    got = _overlays("trellion=1\\nvoice=0\\nexample_addon=1", root=install)
    assert [Path(p).name for p in got[:1]] == ["docker-compose.trellion.yml"], got
    assert got[1:] == [str(install / "addons" / "example_addon" / "docker-compose.yml")], got


def test_a_licensed_addon_that_is_off_or_unstated_is_not_composed(install: Path) -> None:
    assert _names("trellion=1\\nexample_addon=0", root=install) == ["docker-compose.trellion.yml"]
    # a bundle on disk is not a switch: licensed add-ons default OFF
    assert _names("trellion=1", root=install) == ["docker-compose.trellion.yml"]


def test_the_legacy_root_overlay_composes_with_a_warn_only_without_a_bundle(install: Path) -> None:
    legacy = install / "docker-compose.example-addon.yml"
    legacy.write_text(_SYNTH_OVERLAY)
    # bundle present: the bundle wins, no warning
    out = _run_helper("trellion=0\\nexample_addon=1", "addon_compose_overlay_args", root=install)
    assert out.stdout.split() == ["-f", str(install / "addons" / "example_addon" / "docker-compose.yml")]
    assert "WARN" not in out.stderr, out.stderr
    # no bundle: the deprecated root file composes, and says so
    shutil.rmtree(install / "addons" / "example_addon")
    out = _run_helper("trellion=0\\nexample_addon=1", "addon_compose_overlay_args", root=install)
    assert out.stdout.split() == ["-f", str(legacy)]
    assert "WARN" in out.stderr and "example_addon" in out.stderr, out.stderr
    # neither: nothing composes, nothing to warn about
    legacy.unlink()
    out = _run_helper("trellion=0\\nexample_addon=1", "addon_compose_overlay_args", root=install)
    assert out.stdout.strip() == "" and "WARN" not in out.stderr, (out.stdout, out.stderr)


def test_a_dev_checkout_wins_over_the_bundle(install: Path, tmp_path: Path) -> None:
    dev = tmp_path / "dev-example"
    dev.mkdir()
    (dev / "docker-compose.example-addon.yml").write_text(_SYNTH_OVERLAY)
    (install / "docker-compose.example-addon.yml").write_text(_SYNTH_OVERLAY)
    got = _overlays("trellion=0\\nexample_addon=1", root=install,
                    env={"NOO_EXAMPLE_ADDON_PATH": str(dev)})
    assert got == [str(dev / "docker-compose.example-addon.yml")], got
    # a NOO_<NAME>_PATH with no overlay in it falls through to the bundle
    got = _overlays("trellion=0\\nexample_addon=1", root=install,
                    env={"NOO_EXAMPLE_ADDON_PATH": str(tmp_path / "nope")})
    assert got == [str(install / "addons" / "example_addon" / "docker-compose.yml")], got


def test_core_only_defers_every_non_core_addon_but_not_trellion(install: Path) -> None:
    (install / "addons" / "other_addon").mkdir()
    (install / "addons" / "other_addon" / "docker-compose.yml").write_text(_SYNTH_OVERLAY)
    m = "trellion=1\\nvoice=1\\nexample_addon=1\\nother_addon=1"
    assert len(_overlays(m, root=install)) == 4  # the premise: all on without CORE_ONLY
    assert _names(m, root=install, env={"CORE_ONLY": "true"}) == ["docker-compose.trellion.yml"]


def test_licensed_names_come_from_the_map_and_the_bundles(install: Path) -> None:
    got = _run_helper("trellion=1\\nvoice=1\\nmap_only=0", "addon_licensed_names", root=install)
    assert got.stdout.split() == ["example_addon", "map_only"], got.stdout


def test_helper_honours_trellion_opt_out_polarity() -> None:
    # No declaration at all: trellion defaults ON, the rest default OFF.
    assert _names("") == ["docker-compose.trellion.yml"]
    assert _names("trellion=0") == []


def test_helper_is_silent_when_nothing_is_on() -> None:
    got = _run_helper("trellion=0\\nvoice=0", "addon_compose_overlay_args").stdout.strip()
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


def test_identity_is_a_gateway_feature_not_a_missing_overlay(install: Path) -> None:
    """`identity` is a free gateway feature flag with no container and no
    overlay (docs/getting-started/add-ons.md). The 0.6.3 -> 0.6.4 roll
    (2026-10-15) printed "addons.identity is true but no overlay was found"
    on every start because every non-core-overlay name counted as licensed."""
    out = _run_helper("trellion=1\\nidentity=1", "addons_report_licensed", root=install)
    assert "no overlay" not in out.stdout + out.stderr, out.stdout + out.stderr
    assert out.stdout.strip() == "Add-on identity: ENABLED (gateway feature)", out.stdout
    # unstated (the default) or off: nothing to say
    for m in ("trellion=1", "trellion=1\\nidentity=0"):
        out = _run_helper(m, "addons_report_licensed", root=install)
        assert out.stdout.strip() == "" and out.stderr.strip() == "", (m, out.stdout, out.stderr)
    # never a licensed name, so never composed, stopped or pin-checked
    got = _run_helper("trellion=1\\nidentity=1", "addon_licensed_names", root=install)
    assert "identity" not in got.stdout.split(), got.stdout
    # the premise: a licensed add-on with no overlay still warns
    out = _run_helper("trellion=1\\nnobundle_addon=1", "addons_report_licensed", root=install)
    assert "addons.nobundle_addon is true but no overlay was found" in out.stdout, out.stdout


def test_gateway_feature_addons_mirror_the_cli_rows() -> None:
    """GATEWAY_FEATURE_ADDONS is exactly the CLI's ADDON_ROWS that are not
    licensed and not a core overlay: a new feature-flag add-on declared in
    the CLI without the launcher learning it would warn again."""
    body = (SCRIPTS / "lib-addons.sh").read_text()
    decl = lambda name: set(re.search(rf'^{name}="([^"]*)"', body, re.M).group(1).split())  # noqa: E731
    rows = (SCRIPTS.parent / "noo-cli/src/commands/addons.rs").read_text()
    table = rows[rows.index("pub const ADDON_ROWS"):rows.index("];", rows.index("pub const ADDON_ROWS"))]
    parsed = re.findall(r'key:\s*"([a-z_]+)".*?licensed:\s*(None|Some)', table, re.S)
    assert len(parsed) >= 4, f"parsed {parsed} from ADDON_ROWS: the read broke"
    free = {k for k, lic in parsed if lic == "None"}
    assert "identity" in free
    assert decl("GATEWAY_FEATURE_ADDONS") == free - decl("CORE_OVERLAY_ADDONS")
