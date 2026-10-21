# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A dist start runs each licensed add-on that is on from the image its own
signed lock pins for THIS stack tag, present locally by digest, or it does not
start. The launcher never pulls an add-on and holds no registry credential.

scripts/lib-dist.sh::require_addon_pins is exercised for real against a fake
`docker` and a fake `noo` on PATH (no registry, no daemon). The fake `noo`
answers `addons launch-pins` with the protocol the real one prints (one `pin`
or `refuse` line per licensed add-on); the Rust side of that verb is unit-tested
in noo-cli/src/commands/addon_pins.rs.

Core ships no licensed add-on overlay (N6: each travels in its add-on's signed
bundle, materialised at `addons/<name>/docker-compose.yml`). So the launcher
libraries are copied into a tmp install root beside SYNTHETIC bundles for two
made-up add-ons, `example_addon` and `other_addon` — the shell logic is what is
under test, and it must not depend on which add-on it is."""

from __future__ import annotations

import os
import stat
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

EXAMPLE_REF = "ghcr.io/example/example-addon@sha256:" + "1" * 64
OTHER_REF = "ghcr.io/example/other-addon@sha256:" + "2" * 64

# Synthetic add-on bundles, shaped like a real one: a service whose `image:`
# reads its NOO_ADDON_IMAGE_<NAME> pin with an unpinned sentinel, and (in
# example_addon) a one-shot that runs the same image.
EXAMPLE_OVERLAY = """services:
  example-addon:
    image: ${NOO_ADDON_IMAGE_EXAMPLE_ADDON:-noo-addon-unpinned.invalid/example-addon:run-noo-addons-upgrade}
    restart: unless-stopped
  example-addon-routes:
    image: ${NOO_ADDON_IMAGE_EXAMPLE_ADDON:-noo-addon-unpinned.invalid/example-addon:run-noo-addons-upgrade}
    restart: "no"
"""
OTHER_OVERLAY = """services:
  other-addon:
    image: ${NOO_ADDON_IMAGE_OTHER_ADDON:-noo-addon-unpinned.invalid/other-addon:run-noo-addons-upgrade}
"""


def _root(tmp_path: Path) -> Path:
    """A tmp install root: the two launcher libraries under scripts/ (they
    locate the install root from their own path) and the synthetic bundles
    under addons/<name>/docker-compose.yml, where the CLI materialises them."""
    root = tmp_path / "root"
    if not root.exists():
        (root / "scripts").mkdir(parents=True)
        for lib in ("lib-addons.sh", "lib-dist.sh"):
            shutil.copy(REPO / "scripts" / lib, root / "scripts" / lib)
        for name, text in (("example_addon", EXAMPLE_OVERLAY), ("other_addon", OTHER_OVERLAY)):
            (root / "addons" / name).mkdir(parents=True)
            (root / "addons" / name / "docker-compose.yml").write_text(text)
    return root

FAKE_DOCKER = """#!/bin/sh
# FAKE_LOCAL: space-separated refs present locally.
case "$1 $2" in
  "image inspect") for r in $FAKE_LOCAL; do [ "$r" = "$3" ] && exit 0; done; exit 1 ;;
  pull*) echo "$*" >> "$FAKE_LOG"; exit 0 ;;
esac
case "$1" in pull|login) echo "$*" >> "$FAKE_LOG" ;; esac
exit 0
"""

FAKE_NOO = """#!/bin/sh
# FAKE_PINS: the launch-pins answer (lines). FAKE_NOO_RC: its exit code.
echo "$*" >> "$FAKE_NOO_LOG"
[ "$1 $2" = "addons launch-pins" ] || exit 2
printf '%b' "$FAKE_PINS"
exit "${FAKE_NOO_RC:-0}"
"""


def _bin(tmp_path: Path, name: str, text: str) -> None:
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    f = d / name
    f.write_text(text)
    f.chmod(f.stat().st_mode | stat.S_IEXEC)


def _run(tmp_path: Path, body: str, **env: str) -> subprocess.CompletedProcess:
    _bin(tmp_path, "docker", FAKE_DOCKER)
    _bin(tmp_path, "noo", FAKE_NOO)
    root = _root(tmp_path)
    script = f"""
set -u
cd {tmp_path}
. {root}/scripts/lib-addons.sh
. {root}/scripts/lib-dist.sh
{body}
"""
    full_env = {
        "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "NOO_ADDON_MAP_OVERRIDE": "1",
        "NOO_ADDON_MAP": env.pop("MAP", "example_addon=1\nother_addon=1\nvoice=0\n"),
        "DIST_MODE": "1",
        "DIST_TAG": "v0.6.0",
        "NOO_IMAGE_PREFIX": "ghcr.io/noomesh",
        "NOO_IMAGE_TAG": "v0.6.0",
        "FAKE_LOCAL": f"{EXAMPLE_REF} {OTHER_REF}",
        "FAKE_PINS": (f"pin example_addon NOO_ADDON_IMAGE_EXAMPLE_ADDON {EXAMPLE_REF}\\n"
                      f"pin other_addon NOO_ADDON_IMAGE_OTHER_ADDON {OTHER_REF}\\n"),
        "FAKE_LOG": str(tmp_path / "docker.log"),
        "FAKE_NOO_LOG": str(tmp_path / "noo.log"),
    }
    full_env.update(env)
    return subprocess.run(["bash", "-c", script], env=full_env, capture_output=True, text=True)


def _exports(r: subprocess.CompletedProcess) -> dict[str, str]:
    return dict(l.split("=", 1) for l in r.stdout.splitlines() if l.startswith("NOO_ADDON_IMAGE_"))


SHOW = 'require_addon_pins; rc=$?; env | grep "^NOO_ADDON_IMAGE_" | sort; exit $rc'


def test_verified_local_pins_are_exported_for_the_overlays(tmp_path):
    r = _run(tmp_path, SHOW)
    assert r.returncode == 0, r.stderr
    assert _exports(r) == {"NOO_ADDON_IMAGE_EXAMPLE_ADDON": EXAMPLE_REF, "NOO_ADDON_IMAGE_OTHER_ADDON": OTHER_REF}
    asked = (tmp_path / "noo.log").read_text().split()
    # The pins are read from the launcher's install root, whatever the cwd is.
    assert asked[:4] == ["addons", "launch-pins", "--root", str(tmp_path / "root")], asked
    assert asked[4] == "v0.6.0", asked
    assert set(asked[5:]) == {"trellion", "example_addon", "other_addon"}, "only composed add-ons are asked about"
    assert not (tmp_path / "docker.log").exists(), "the launcher must never pull or log in"


VERDICT = 'require_addon_pins; rc=$?; printf "VERIFIED=%s\\n" "${NOO_ADDONS_VERIFIED-<unset>}"; exit $rc'

PINS_WITH_VERDICT = (
    "verified example_addon 1.0.0 v0.6.0\\n"
    f"pin example_addon NOO_ADDON_IMAGE_EXAMPLE_ADDON {EXAMPLE_REF}\\n"
    "verified other_addon 2.1.0 v0.6.0\\n"
    f"pin other_addon NOO_ADDON_IMAGE_OTHER_ADDON {OTHER_REF}\\n"
)


def _verdict(r: subprocess.CompletedProcess) -> str:
    (line,) = [l for l in r.stdout.splitlines() if l.startswith("VERIFIED=")]
    return line.removeprefix("VERIFIED=")


def test_the_launcher_hands_the_gateway_the_verdict_it_computed(tmp_path):
    r = _run(tmp_path, VERDICT, FAKE_PINS=PINS_WITH_VERDICT)
    assert r.returncode == 0, r.stderr
    assert _verdict(r) == "example_addon=1.0.0@v0.6.0,other_addon=2.1.0@v0.6.0"


def test_nothing_composed_is_verified_none_in_dist_and_dev_in_a_checkout(tmp_path):
    r = _run(tmp_path, VERDICT, MAP="example_addon=0\nother_addon=0\n")
    assert r.returncode == 0, r.stderr
    assert _verdict(r) == "none"
    r = _run(tmp_path, VERDICT, MAP="example_addon=0\nother_addon=0\n", DIST_MODE="0")
    assert _verdict(r) == "dev"
    r = _run(tmp_path, VERDICT, DIST_MODE="0")
    assert _verdict(r) == "dev", "a source checkout builds its add-ons: there is no signed lock"


def test_an_inherited_verdict_is_dropped_never_trusted(tmp_path):
    # A shell export or an .env line must not vouch for an add-on.
    r = _run(tmp_path, VERDICT, MAP="example_addon=0\nother_addon=0\n", NOO_ADDONS_VERIFIED="other_addon=9.9.9@v0.6.0")
    assert _verdict(r) == "none"


def test_a_refusal_exports_no_verdict_and_stops_the_start(tmp_path):
    r = _run(tmp_path, VERDICT, MAP="other_addon=1\n", FAKE_PINS="refuse other_addon its lock does not list v0.6.0\\n")
    assert r.returncode == 1
    assert _verdict(r) == "<unset>"


def test_a_cli_that_cannot_report_leaves_the_verdict_unset_and_says_so(tmp_path):
    # `pin` lines with no `verified` beside them: a noo binary older than this
    # launcher. Reporting "none" would make the gateway refuse a good add-on.
    r = _run(tmp_path, VERDICT)
    assert r.returncode == 0, r.stderr
    assert _verdict(r) == "<unset>"
    assert "does not report verified add-on locks" in r.stderr and "noo upgrade" in r.stderr


DEV_VERDICT = (
    'require_addon_pins; rc=$?; printf "VERIFIED=%s\\n" "${NOO_ADDONS_VERIFIED-<unset>}"; '
    'printf "DEV=%s\\n" "${NOO_ADDONS_DEV-<unset>}"; exit $rc'
)


def _dev(r: subprocess.CompletedProcess) -> str:
    (line,) = [l for l in r.stdout.splitlines() if l.startswith("DEV=")]
    return line.removeprefix("DEV=")


def test_a_dev_signed_addon_is_handed_to_the_gateway_with_its_expiry(tmp_path):
    # i163 part A: `dev <addon> <unix>` after the verdict line.
    pins = PINS_WITH_VERDICT.replace(
        "verified other_addon 2.1.0 v0.6.0\\n", "verified other_addon 2.1.0 v0.6.0\\ndev other_addon 1793750400\\n"
    )
    assert "dev other_addon" in pins
    r = _run(tmp_path, DEV_VERDICT, FAKE_PINS=pins)
    assert r.returncode == 0, r.stderr
    assert _verdict(r) == "example_addon=1.0.0@v0.6.0,other_addon=2.1.0@v0.6.0"
    assert _dev(r) == "other_addon=1793750400"


def test_no_dev_line_leaves_the_dev_variable_unset_and_an_inherited_one_is_dropped(tmp_path):
    r = _run(tmp_path, DEV_VERDICT, FAKE_PINS=PINS_WITH_VERDICT, NOO_ADDONS_DEV="example_addon=9999999999")
    assert r.returncode == 0, r.stderr
    assert _dev(r) == "<unset>"


def test_a_dev_line_alone_vouches_for_nothing(tmp_path):
    # A `dev` line for an add-on with no `verified` line is not passed on.
    pins = PINS_WITH_VERDICT + "dev stray_addon 1793750400\\n"
    r = _run(tmp_path, DEV_VERDICT, FAKE_PINS=pins)
    assert r.returncode == 0, r.stderr
    assert _dev(r) == "<unset>"


def test_a_malformed_dev_line_refuses(tmp_path):
    pins = PINS_WITH_VERDICT + "dev other_addon soon;rm\\n"
    r = _run(tmp_path, DEV_VERDICT, FAKE_PINS=pins)
    assert r.returncode == 1 and "unreadable dev expiry" in r.stderr
    assert _dev(r) == "<unset>"


def test_a_malformed_verdict_line_refuses(tmp_path):
    r = _run(tmp_path, VERDICT, MAP="other_addon=1\n", FAKE_PINS="verified other_addon 1.0;rm v0.6.0\\n")
    assert r.returncode == 1 and "unreadable verdict" in r.stderr


def test_addons_off_make_no_call_at_all(tmp_path):
    r = _run(tmp_path, SHOW, MAP="example_addon=0\nother_addon=0\n")
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "noo.log").exists()
    # An unlicensed add-on that is on is the CLI's to ignore: no line, no pin.
    r = _run(tmp_path, SHOW, MAP="example_addon=0\nvoice=1\n", FAKE_PINS="")
    assert r.returncode == 0, r.stderr
    assert _exports(r) == {}


def test_not_dist_mode_is_a_noop(tmp_path):
    r = _run(tmp_path, SHOW, DIST_MODE="0", FAKE_PINS="refuse other_addon nope\\n")
    assert r.returncode == 0, r.stderr


def test_a_refused_pin_names_the_addon_the_reason_and_the_remedy(tmp_path):
    r = _run(tmp_path, SHOW, MAP="other_addon=1\n",
             FAKE_PINS="refuse other_addon other_addon's cached lock no longer verifies: Add-on lock signature invalid\\n")
    assert r.returncode == 1
    assert "REFUSING: the other_addon add-on is on and has no verified pin for v0.6.0" in r.stderr
    assert "cached lock no longer verifies" in r.stderr
    assert "noo addons upgrade other_addon" in r.stderr
    assert _exports(r) == {}


def test_a_pinned_image_missing_locally_refuses_and_is_never_pulled(tmp_path):
    r = _run(tmp_path, SHOW, FAKE_LOCAL=EXAMPLE_REF)
    assert r.returncode == 1
    assert "REFUSING: the other_addon add-on is on, and its pinned image is not on this host" in r.stderr
    assert OTHER_REF in r.stderr and "noo addons upgrade other_addon" in r.stderr
    assert not (tmp_path / "docker.log").exists(), "the launcher must never pull an add-on"


def test_an_env_file_value_cannot_name_an_addon_image(tmp_path):
    # An operator export (or an .env line a loader exported) is dropped: only
    # a pin that verified may set the variable.
    r = _run(tmp_path, SHOW, MAP="other_addon=0\n", NOO_ADDON_IMAGE_OTHER_ADDON="mine/other-addon:latest")
    assert r.returncode == 0, r.stderr
    assert _exports(r) == {}
    r = _run(tmp_path, SHOW, MAP="other_addon=1\n", NOO_ADDON_IMAGE_OTHER_ADDON="mine/other-addon:latest",
             FAKE_PINS="refuse other_addon other_addon has no pin in addons.lock\\n")
    assert r.returncode == 1 and _exports(r) == {}


def test_a_failing_reader_refuses(tmp_path):
    r = _run(tmp_path, SHOW, FAKE_NOO_RC="1", FAKE_PINS="boom\\n")
    assert r.returncode == 1
    assert "the add-on pins could not be read" in r.stderr and "noo addons verify" in r.stderr


def test_a_reader_line_that_is_not_an_addon_variable_is_refused(tmp_path):
    r = _run(tmp_path, SHOW, MAP="other_addon=1\n", FAKE_PINS=f"pin other_addon PATH {OTHER_REF}\\n")
    assert r.returncode == 1 and "not an add-on image variable" in r.stderr


def test_addon_services_are_derived_from_the_overlays(tmp_path):
    # Core's own files (the base and its overlays) contribute no add-on
    # service; the bundles contribute every service that reads a pin.
    root = _root(tmp_path)
    files = (f"-f docker-compose.cluster.yml -f docker-compose.trellion.yml "
             f"-f {root}/addons/example_addon/docker-compose.yml "
             f"-f {root}/addons/other_addon/docker-compose.yml -f docker-compose.voice.yml")
    r = subprocess.run(["bash", "-c", f"cd {REPO}; . scripts/lib-dist.sh; addon_services {files}"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["example-addon", "example-addon-routes", "other-addon"]


# A compose whose `config` needs `--profile standalone` (else it rejects the
# whole project), whose `--images <svc>` prints a dependency's image FIRST
# (as real compose does), and whose `--format json` carries each service's own.
FAKE_COMPOSE_RENDER = """#!/bin/sh
[ "$1" = "compose" ] || exit 0
case "$*" in *" config "*) ;; *) exit 0 ;; esac
case "$*" in *"--profile standalone"*) ;; *)
  echo 'service "ollama-embed-cpu" depends on undefined service "ollama-embed": invalid compose project' >&2; exit 15 ;;
esac
[ -n "$FAKE_RENDER_FAIL" ] && { echo "boom: required variable X is missing" >&2; exit 1; }
IMG="${NOO_ADDON_IMAGE_OTHER_ADDON:-noo-addon-unpinned.invalid/other-addon:run-noo-addons-upgrade}"
case "$*" in
  *"--format json"*) printf '{"services":{"gateway":{"image":"ghcr.io/noomesh/gateway:v0.6.0"},"other-addon":{"image":"%s"}}}' "$IMG" ;;
  *"--images"*) echo ghcr.io/noomesh/gateway:v0.6.0; echo "$IMG" ;;
esac
exit 0
"""


def test_rendered_addon_refs_must_be_their_pins(tmp_path):
    # A fake compose that renders the add-on service's image from the env.
    fake = FAKE_COMPOSE_RENDER
    _bin(tmp_path, "docker", fake)
    overlay = _root(tmp_path) / "addons/other_addon/docker-compose.yml"
    body = f"cd {REPO}; . scripts/lib-dist.sh; _ADDON_PINS=(\"NOO_ADDON_IMAGE_OTHER_ADDON={OTHER_REF}\"); dist_assert_addon_refs -f {overlay} --profile standalone"
    env = {"PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}", "DIST_TAG": "v0.6.0", "DIST_MODE": "1"}
    ok = subprocess.run(["bash", "-c", body], env={**env, "NOO_ADDON_IMAGE_OTHER_ADDON": OTHER_REF},
                        capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    bad = subprocess.run(["bash", "-c", body], env=env, capture_output=True, text=True)
    assert bad.returncode == 1
    assert "other-addon would run noo-addon-unpinned.invalid/other-addon" in bad.stderr
    # compose cannot render the ref: a refusal, never a skip.
    broken = subprocess.run(["bash", "-c", body], env={**env, "NOO_ADDON_IMAGE_OTHER_ADDON": OTHER_REF, "FAKE_RENDER_FAIL": "1"},
                            capture_output=True, text=True)
    assert broken.returncode == 1 and "could not render" in broken.stderr, broken.stderr
    # ...and the refusal carries compose's own error, indented, with the exit
    # status, and points at the render error rather than `noo addons verify`.
    assert "         boom: required variable X is missing" in broken.stderr, broken.stderr
    assert "exited with status 1" in broken.stderr, broken.stderr
    assert "see the lines above" in broken.stderr and "noo addons verify" not in broken.stderr, broken.stderr


def test_a_pull_that_cannot_list_images_shows_compose_error(tmp_path):
    fake = """#!/bin/sh
echo "boom: required variable X is missing" >&2
exit 1
"""
    _bin(tmp_path, "docker", fake)
    body = f"cd {REPO}; . scripts/lib-dist.sh; dist_assert_pull_refs -f docker-compose.yml; echo rc=$?"
    env = {"PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}", "DIST_TAG": "v0.6.0", "DIST_MODE": "1"}
    r = subprocess.run(["bash", "-c", body], env=env, capture_output=True, text=True)
    assert "rc=0" in r.stdout
    assert "boom: required variable X is missing" in r.stderr, r.stderr


def test_a_failed_service_listing_is_reported_not_swallowed(tmp_path):
    fake = """#!/bin/sh
echo "boom: required variable X is missing" >&2
exit 1
"""
    _bin(tmp_path, "docker", fake)
    body = f"cd {REPO}; . scripts/lib-dist.sh; compose_active_services -f x.yml; echo out=[$COMPOSE_OUT]"
    env = {"PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}
    r = subprocess.run(["bash", "-c", body], env=env, capture_output=True, text=True)
    assert "out=[]" in r.stdout
    assert "boom: required variable X is missing" in r.stderr, r.stderr


def test_a_lock_image_name_the_overlay_does_not_read_is_refused(tmp_path):
    # The lock calls the image `noo-other-addon`, so the pin is exported as
    # NOO_ADDON_IMAGE_NOO_OTHER_ADDON; the overlay reads
    # NOO_ADDON_IMAGE_OTHER_ADDON and would render its unpinned sentinel.
    # Refused, naming the variable.
    r = _run(tmp_path, SHOW, MAP="trellion=0\nother_addon=1\n",
             FAKE_PINS=f"pin other_addon NOO_ADDON_IMAGE_NOO_OTHER_ADDON {OTHER_REF}\\n")
    assert r.returncode == 1, r.stderr
    assert "runs ${NOO_ADDON_IMAGE_OTHER_ADDON}, and no verified pin supplies it" in r.stderr


def test_core_only_gates_exactly_what_is_composed(tmp_path):
    # --core-only defers every licensed add-on: their overlays are not
    # composed, so a declared-but-unpinned add-on does not refuse the start.
    r = _run(tmp_path, SHOW, CORE_ONLY="true", FAKE_PINS="refuse other_addon nope\\n")
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "noo.log").exists()


def test_a_dev_start_runs_the_dev_build_names(tmp_path):
    r = _run(tmp_path, SHOW, DIST_MODE="0", NOO_IMAGE_PREFIX="noomesh", NOO_IMAGE_TAG="latest",
             NOO_ADDON_IMAGE_OTHER_ADDON="mine/other-addon:x")
    assert r.returncode == 0, r.stderr
    assert _exports(r) == {"NOO_ADDON_IMAGE_OTHER_ADDON": "noomesh/other-addon:latest",
                           "NOO_ADDON_IMAGE_EXAMPLE_ADDON": "noomesh/example-addon:latest"}
    assert not (tmp_path / "noo.log").exists(), "a dev start verifies nothing and asks the CLI nothing"


def test_restart_gates_and_asserts_before_it_recreates():
    """noomesh-restart.sh runs require_addon_pins after its env loaders and
    dist_assert_addon_refs once COMPOSE_FILES is known, both before any `up`;
    noomesh-start.sh asserts after COMPOSE_FILES whether or not it pulls."""
    restart = (REPO / "scripts/noomesh-restart.sh").read_text()
    pins = restart.index("require_addon_pins || exit 1")
    files = restart.index('COMPOSE_FILES="$(compose_file_args .)"')
    asserted = restart.index("dist_assert_addon_refs $COMPOSE_FILES $PROFILE_ARGS || exit 1")
    first_up = restart.index(" up -d")
    assert restart.index("load_secrets ||") < pins < files < asserted < first_up
    start = (REPO / "scripts/noomesh-start.sh").read_text()
    files = start.index('COMPOSE_FILES="$(compose_file_args .)"')
    asserted = start.index("dist_assert_addon_refs $COMPOSE_FILES $PROFILE_ARGS || exit 1")
    assert files < asserted < start.index('if [ "$PULL" = true ]; then')


# test_evolve_routes_runs_the_same_image_as_evolve: moved with the overlay to the add-on repo (N6)


def test_both_launchers_call_the_gate_before_any_pull_and_the_old_paths_are_gone():
    start = (REPO / "scripts/noomesh-start.sh").read_text()
    restart = (REPO / "scripts/noomesh-restart.sh").read_text()
    lib = (REPO / "scripts/lib-dist.sh").read_text()
    assert "require_addon_pins || exit 1" in restart
    assert "require_addon_pins || exit 1" in start
    assert start.index("require_addon_pins || exit 1") < start.index("ui_step \"Pulling images\"")
    for gone in ("resolve_intel_image", "require_addon_images", "_addon_ref ", "_addon_ref(", "_addon_probe"):
        for name, text in (("noomesh-start.sh", start), ("noomesh-restart.sh", restart), ("lib-dist.sh", lib)):
            code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
            assert gone not in code, f"{gone} is retired but {name} still calls it"
    assert "dist_assert_addon_refs \"$@\" || return 1" in lib, "the pull guard covers add-on refs"


def test_the_retired_addon_image_keys_are_warned_about():
    keys = (REPO / "scripts/retired-env-keys").read_text()
    for k in ("NOO_INTEL_IMAGE", "NOO_EVOLVE_IMAGE", "NOO_INTEL_IMAGE_PREFIX", "NOO_EVOLVE_IMAGE_PREFIX"):
        assert f"\n{k}|" in keys, k


def test_the_gate_needs_the_profile_flags_and_reads_the_services_own_image(tmp_path):
    _bin(tmp_path, "docker", FAKE_COMPOSE_RENDER)
    base = f'cd {REPO}; . scripts/lib-dist.sh; _ADDON_PINS=("NOO_ADDON_IMAGE_OTHER_ADDON={OTHER_REF}"); '
    env = {"PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}", "DIST_TAG": "v0.6.0", "DIST_MODE": "1",
           "NOO_ADDON_IMAGE_OTHER_ADDON": OTHER_REF}
    f = f"-f {_root(tmp_path) / 'addons/other_addon/docker-compose.yml'}"
    # Without the launcher's profile flags compose rejects the project: refusal
    # carrying compose's own message.
    r = subprocess.run(["bash", "-c", base + f"dist_assert_addon_refs {f}"], env=env, capture_output=True, text=True)
    assert r.returncode == 1 and "invalid compose project" in r.stderr, r.stderr
    # With them it passes, although `--images` would have printed the gateway first.
    r = subprocess.run(["bash", "-c", base + f"dist_assert_addon_refs {f} --profile standalone"], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_without_python3_the_pin_is_found_among_the_images_lines(tmp_path):
    _bin(tmp_path, "docker", FAKE_COMPOSE_RENDER)
    # PATH with docker and the basics but no python3.
    nopy = tmp_path / "nopy"
    nopy.mkdir()
    for t in ("bash", "sh", "head", "tail", "sed", "cat", "mktemp", "rm", "sort", "awk", "printf", "env"):
        src = shutil.which(t)
        if src:
            (nopy / t).symlink_to(src)
    overlay = _root(tmp_path) / "addons/other_addon/docker-compose.yml"
    body = f'cd {REPO}; . scripts/lib-dist.sh; _ADDON_PINS=("NOO_ADDON_IMAGE_OTHER_ADDON={OTHER_REF}"); dist_assert_addon_refs -f {overlay} --profile standalone'
    env = {"PATH": f"{tmp_path / 'bin'}:{nopy}", "DIST_TAG": "v0.6.0", "DIST_MODE": "1",
           "NOO_ADDON_IMAGE_OTHER_ADDON": OTHER_REF}
    r = subprocess.run([str(nopy / "bash"), "-c", body], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
