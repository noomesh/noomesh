# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A dist start runs each licensed add-on that is on from the image its own
signed lock pins for THIS stack tag, present locally by digest, or it does not
start. The launcher never pulls an add-on and holds no registry credential.

scripts/lib-dist.sh::require_addon_pins is exercised for real against a fake
`docker` and a fake `noo` on PATH (no registry, no daemon). The fake `noo`
answers `addons launch-pins` with the protocol the real one prints (one `pin`
or `refuse` line per licensed add-on); the Rust side of that verb is unit-tested
in noo-cli/src/commands/addon_pins.rs."""

from __future__ import annotations

import os
import stat
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

INTEL_REF = "ghcr.io/example/trellion-intel@sha256:" + "1" * 64
EVOLVE_REF = "ghcr.io/example/evolve@sha256:" + "2" * 64

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
    script = f"""
set -u
cd {tmp_path}
. {REPO}/scripts/lib-addons.sh
. {REPO}/scripts/lib-dist.sh
{body}
"""
    full_env = {
        "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "NOO_ADDON_MAP_OVERRIDE": "1",
        "NOO_ADDON_MAP": env.pop("MAP", "trellion_intel=1\nevolve=1\nvoice=0\n"),
        "DIST_MODE": "1",
        "DIST_TAG": "v0.6.0",
        "NOO_IMAGE_PREFIX": "ghcr.io/noomesh",
        "NOO_IMAGE_TAG": "v0.6.0",
        "FAKE_LOCAL": f"{INTEL_REF} {EVOLVE_REF}",
        "FAKE_PINS": (f"pin trellion_intel NOO_ADDON_IMAGE_TRELLION_INTEL {INTEL_REF}\\n"
                      f"pin evolve NOO_ADDON_IMAGE_EVOLVE {EVOLVE_REF}\\n"),
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
    assert _exports(r) == {"NOO_ADDON_IMAGE_TRELLION_INTEL": INTEL_REF, "NOO_ADDON_IMAGE_EVOLVE": EVOLVE_REF}
    asked = (tmp_path / "noo.log").read_text().split()
    # The pins are read from the launcher's install root, whatever the cwd is.
    assert asked[:4] == ["addons", "launch-pins", "--root", str(REPO)], asked
    assert asked[4] == "v0.6.0", asked
    assert set(asked[5:]) == {"trellion", "trellion_intel", "evolve"}, "only composed add-ons are asked about"
    assert not (tmp_path / "docker.log").exists(), "the launcher must never pull or log in"


def test_addons_off_make_no_call_at_all(tmp_path):
    r = _run(tmp_path, SHOW, MAP="trellion_intel=0\nevolve=0\n")
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "noo.log").exists()
    # An unlicensed add-on that is on is the CLI's to ignore: no line, no pin.
    r = _run(tmp_path, SHOW, MAP="trellion_intel=0\nvoice=1\n", FAKE_PINS="")
    assert r.returncode == 0, r.stderr
    assert _exports(r) == {}


def test_not_dist_mode_is_a_noop(tmp_path):
    r = _run(tmp_path, SHOW, DIST_MODE="0", FAKE_PINS="refuse evolve nope\\n")
    assert r.returncode == 0, r.stderr


def test_a_refused_pin_names_the_addon_the_reason_and_the_remedy(tmp_path):
    r = _run(tmp_path, SHOW, MAP="evolve=1\n",
             FAKE_PINS="refuse evolve evolve's cached lock no longer verifies: Add-on lock signature invalid\\n")
    assert r.returncode == 1
    assert "REFUSING: the evolve add-on is on and has no verified pin for v0.6.0" in r.stderr
    assert "cached lock no longer verifies" in r.stderr
    assert "noo addons upgrade evolve" in r.stderr
    assert _exports(r) == {}


def test_a_pinned_image_missing_locally_refuses_and_is_never_pulled(tmp_path):
    r = _run(tmp_path, SHOW, FAKE_LOCAL=INTEL_REF)
    assert r.returncode == 1
    assert "REFUSING: the evolve add-on is on, and its pinned image is not on this host" in r.stderr
    assert EVOLVE_REF in r.stderr and "noo addons upgrade evolve" in r.stderr
    assert not (tmp_path / "docker.log").exists(), "the launcher must never pull an add-on"


def test_an_env_file_value_cannot_name_an_addon_image(tmp_path):
    # An operator export (or an .env line a loader exported) is dropped: only
    # a pin that verified may set the variable.
    r = _run(tmp_path, SHOW, MAP="evolve=0\n", NOO_ADDON_IMAGE_EVOLVE="mine/evolve:latest")
    assert r.returncode == 0, r.stderr
    assert _exports(r) == {}
    r = _run(tmp_path, SHOW, MAP="evolve=1\n", NOO_ADDON_IMAGE_EVOLVE="mine/evolve:latest",
             FAKE_PINS="refuse evolve evolve has no pin in addons.lock\\n")
    assert r.returncode == 1 and _exports(r) == {}


def test_a_failing_reader_refuses(tmp_path):
    r = _run(tmp_path, SHOW, FAKE_NOO_RC="1", FAKE_PINS="boom\\n")
    assert r.returncode == 1
    assert "the add-on pins could not be read" in r.stderr and "noo addons verify" in r.stderr


def test_a_reader_line_that_is_not_an_addon_variable_is_refused(tmp_path):
    r = _run(tmp_path, SHOW, MAP="evolve=1\n", FAKE_PINS=f"pin evolve PATH {EVOLVE_REF}\\n")
    assert r.returncode == 1 and "not an add-on image variable" in r.stderr


def test_addon_services_are_derived_from_the_overlays():
    files = "-f docker-compose.cluster.yml -f docker-compose.trellion-intel.yml -f docker-compose.evolve.yml -f docker-compose.voice.yml"
    r = subprocess.run(["bash", "-c", f"cd {REPO}; . scripts/lib-dist.sh; addon_services {files}"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["noo-evolve", "noo-evolve-routes", "trellion-intel"]


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
IMG="${NOO_ADDON_IMAGE_TRELLION_INTEL:-noo-addon-unpinned.invalid/trellion-intel:run-noo-addons-upgrade}"
case "$*" in
  *"--format json"*) printf '{"services":{"gateway":{"image":"ghcr.io/noomesh/gateway:v0.6.0"},"trellion-intel":{"image":"%s"}}}' "$IMG" ;;
  *"--images"*) echo ghcr.io/noomesh/gateway:v0.6.0; echo "$IMG" ;;
esac
exit 0
"""


def test_rendered_addon_refs_must_be_their_pins(tmp_path):
    # A fake compose that renders the add-on service's image from the env.
    fake = FAKE_COMPOSE_RENDER
    _bin(tmp_path, "docker", fake)
    body = f"cd {REPO}; . scripts/lib-dist.sh; _ADDON_PINS=(\"NOO_ADDON_IMAGE_TRELLION_INTEL={INTEL_REF}\"); dist_assert_addon_refs -f docker-compose.trellion-intel.yml --profile standalone"
    env = {"PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}", "DIST_TAG": "v0.6.0", "DIST_MODE": "1"}
    ok = subprocess.run(["bash", "-c", body], env={**env, "NOO_ADDON_IMAGE_TRELLION_INTEL": INTEL_REF},
                        capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr
    bad = subprocess.run(["bash", "-c", body], env=env, capture_output=True, text=True)
    assert bad.returncode == 1
    assert "trellion-intel would run noo-addon-unpinned.invalid/trellion-intel" in bad.stderr
    # compose cannot render the ref: a refusal, never a skip.
    broken = subprocess.run(["bash", "-c", body], env={**env, "NOO_ADDON_IMAGE_TRELLION_INTEL": INTEL_REF, "FAKE_RENDER_FAIL": "1"},
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
    # The lock calls the image `noo-evolve`, so the pin is exported as
    # NOO_ADDON_IMAGE_NOO_EVOLVE; the overlay reads NOO_ADDON_IMAGE_EVOLVE and
    # would render its unpinned sentinel. Refused, naming the variable.
    r = _run(tmp_path, SHOW, MAP="trellion=0\nevolve=1\n",
             FAKE_PINS=f"pin evolve NOO_ADDON_IMAGE_NOO_EVOLVE {EVOLVE_REF}\\n")
    assert r.returncode == 1, r.stderr
    assert "runs ${NOO_ADDON_IMAGE_EVOLVE}, and no verified pin supplies it" in r.stderr


def test_core_only_gates_exactly_what_is_composed(tmp_path):
    # --core-only defers evolve and trellion_intel: their overlays are not
    # composed, so a declared-but-unpinned add-on does not refuse the start.
    r = _run(tmp_path, SHOW, CORE_ONLY="true", FAKE_PINS="refuse evolve nope\\n")
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "noo.log").exists()


def test_a_dev_start_runs_the_dev_build_names(tmp_path):
    r = _run(tmp_path, SHOW, DIST_MODE="0", NOO_IMAGE_PREFIX="noomesh", NOO_IMAGE_TAG="latest",
             NOO_ADDON_IMAGE_EVOLVE="mine/evolve:x")
    assert r.returncode == 0, r.stderr
    assert _exports(r) == {"NOO_ADDON_IMAGE_EVOLVE": "noomesh/evolve:latest",
                           "NOO_ADDON_IMAGE_TRELLION_INTEL": "noomesh/trellion-intel:latest"}
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


def test_evolve_routes_runs_the_same_image_as_evolve():
    import yaml
    svcs = yaml.safe_load((REPO / "docker-compose.evolve.yml").read_text())["services"]
    assert svcs["noo-evolve-routes"]["image"] == svcs["noo-evolve"]["image"]


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
    base = f'cd {REPO}; . scripts/lib-dist.sh; _ADDON_PINS=("NOO_ADDON_IMAGE_TRELLION_INTEL={INTEL_REF}"); '
    env = {"PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}", "DIST_TAG": "v0.6.0", "DIST_MODE": "1",
           "NOO_ADDON_IMAGE_TRELLION_INTEL": INTEL_REF}
    f = "-f docker-compose.trellion-intel.yml"
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
    body = f'cd {REPO}; . scripts/lib-dist.sh; _ADDON_PINS=("NOO_ADDON_IMAGE_TRELLION_INTEL={INTEL_REF}"); dist_assert_addon_refs -f docker-compose.trellion-intel.yml --profile standalone'
    env = {"PATH": f"{tmp_path / 'bin'}:{nopy}", "DIST_TAG": "v0.6.0", "DIST_MODE": "1",
           "NOO_ADDON_IMAGE_TRELLION_INTEL": INTEL_REF}
    r = subprocess.run([str(nopy / "bash"), "-c", body], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
