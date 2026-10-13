# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A public (dist) install that turns a licensed add-on on must stop with a
message that names the add-on, the prefix tried and the licence, instead of
reaching `compose pull` and dying on a bare "pull access denied".

scripts/lib-dist.sh::require_addon_images is exercised for real against a fake
`docker` on PATH (no registry, no daemon). Each case pins one row of the
failure-semantics table in that function's comment: switched off, local image,
denied, not found, unreachable, unknown, digest absent from the lock, and the
two overlays' image overrides resolving the same way."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

FAKE_DOCKER = """#!/bin/sh
# FAKE_LOCAL: space-separated refs present locally. FAKE_MANIFEST_ERR: stderr of
# a failing `manifest inspect` (empty = success).
case "$1 $2" in
  "image inspect") for r in $FAKE_LOCAL; do [ "$r" = "$3" ] && exit 0; done; exit 1 ;;
  "manifest inspect")
    echo "$3" >> "$FAKE_LOG"
    if [ -n "$FAKE_MANIFEST_ERR" ]; then echo "$FAKE_MANIFEST_ERR" >&2; exit 1; fi
    exit 0 ;;
esac
exit 0
"""


def _run(tmp_path: Path, body: str, **env: str) -> subprocess.CompletedProcess:
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    d = bindir / "docker"
    d.write_text(FAKE_DOCKER)
    d.chmod(d.stat().st_mode | stat.S_IEXEC)
    log = tmp_path / "manifest.log"
    script = f"""
set -u
cd {tmp_path}
. {REPO}/scripts/lib-addons.sh
. {REPO}/scripts/lib-dist.sh
{body}
"""
    full_env = {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "NOO_ADDON_MAP_OVERRIDE": "1",
        "NOO_ADDON_MAP": env.pop("MAP", "trellion_intel=1\nevolve=1\n"),
        "DIST_MODE": "1",
        "NOO_IMAGE_PREFIX": "ghcr.io/noomesh",
        "NOO_IMAGE_TAG": "v0.6.0",
        "FAKE_LOCAL": "",
        "FAKE_MANIFEST_ERR": "",
        "FAKE_LOG": str(log),
    }
    full_env.update(env)
    return subprocess.run(["bash", "-c", script], env=full_env, capture_output=True, text=True)


def test_both_addons_off_is_not_looked_at(tmp_path):
    r = _run(tmp_path, "require_addon_images", MAP="trellion_intel=0\nevolve=0\n",
             FAKE_MANIFEST_ERR="denied: boom")
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "manifest.log").exists(), "an off add-on must make no registry call"


def test_not_dist_mode_is_a_noop(tmp_path):
    r = _run(tmp_path, "require_addon_images", DIST_MODE="0", FAKE_MANIFEST_ERR="denied: boom")
    assert r.returncode == 0, r.stderr


def test_registry_denied_names_the_addon_prefix_and_licence(tmp_path):
    r = _run(tmp_path, "require_addon_images", MAP="evolve=1\n",
             NOO_EVOLVE_IMAGE_PREFIX="ghcr.io/personifai-addons",
             FAKE_MANIFEST_ERR="denied: requested access to the resource is denied")
    assert r.returncode == 1
    err = r.stderr
    assert "evolve" in err and "ghcr.io/personifai-addons" in err
    assert "licensed" in err and "PRIVATE registry" in err
    assert "NOO_EVOLVE_IMAGE_PREFIX" in err and "addons.evolve: false" in err
    assert "requested access" in err  # the registry's own line is quoted
    assert "No NOO_ENTITLEMENT" in err


def test_entitlement_present_drops_the_entitlement_hint(tmp_path):
    r = _run(tmp_path, "require_addon_images", MAP="evolve=1\n", NOO_ENTITLEMENT="noo-ent-x",
             FAKE_MANIFEST_ERR="unauthorized: authentication required")
    assert r.returncode == 1 and "No NOO_ENTITLEMENT" not in r.stderr


def test_core_prefix_without_the_image_is_notfound_with_the_remedy(tmp_path):
    # Prefix var unset: falls back to the core prefix, which carries no add-on.
    r = _run(tmp_path, "require_addon_images", MAP="trellion_intel=1\n",
             FAKE_MANIFEST_ERR="manifest unknown")
    assert r.returncode == 1
    assert "ghcr.io/noomesh/trellion-intel:v0.6.0" in r.stderr
    assert "NOT in the public stack" in r.stderr and "NOO_INTEL_IMAGE_PREFIX" in r.stderr


def test_unreachable_registry_is_not_called_a_licence_problem(tmp_path):
    r = _run(tmp_path, "require_addon_images", MAP="evolve=1\n",
             FAKE_MANIFEST_ERR="dial tcp: lookup registry.example: no such host")
    assert r.returncode == 1
    assert "could not be reached" in r.stderr and "refused us" not in r.stderr


def test_unclassified_failure_still_refuses_and_quotes(tmp_path):
    r = _run(tmp_path, "require_addon_images", MAP="evolve=1\n", FAKE_MANIFEST_ERR="weird thing")
    assert r.returncode == 1 and "weird thing" in r.stderr


def test_local_image_passes_without_a_registry_call(tmp_path):
    r = _run(tmp_path, "require_addon_images", MAP="evolve=1\n",
             FAKE_LOCAL="ghcr.io/noomesh/evolve:v0.6.0", FAKE_MANIFEST_ERR="denied: x")
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / "manifest.log").exists()


def test_reachable_without_a_lock_digest_proceeds_but_says_unpinned(tmp_path):
    r = _run(tmp_path, "require_addon_images", MAP="evolve=1\n", NOO_EVOLVE_IMAGE_PREFIX="reg/x")
    assert r.returncode == 0, r.stderr
    assert "unpinned" in r.stderr and "reg/x/evolve:v0.6.0" in r.stderr


def test_a_digest_in_the_lock_is_probed_and_not_called_unpinned(tmp_path):
    r = _run(tmp_path, "require_addon_images", MAP="evolve=1\n", NOO_EVOLVE_IMAGE_PREFIX="reg/x",
             NOO_IMAGE_DIGEST_EVOLVE="@sha256:abc")
    assert r.returncode == 0 and "unpinned" not in r.stderr
    assert "reg/x/evolve:v0.6.0@sha256:abc" in (tmp_path / "manifest.log").read_text()


def test_full_reference_override_wins_for_both(tmp_path):
    r = _run(tmp_path, "require_addon_images", NOO_EVOLVE_IMAGE="mine/e:1", NOO_INTEL_IMAGE="mine/i:1")
    assert r.returncode == 0, r.stderr
    log = (tmp_path / "manifest.log").read_text().split()
    assert sorted(log) == ["mine/e:1", "mine/i:1"]
    assert "unpinned" not in r.stderr  # an operator-set reference is the operator's pin


def test_one_bad_addon_fails_even_if_the_other_is_fine(tmp_path):
    r = _run(tmp_path, "require_addon_images", FAKE_LOCAL="ghcr.io/noomesh/evolve:v0.6.0",
             FAKE_MANIFEST_ERR="denied: x")
    assert r.returncode == 1
    assert "trellion-intel" in r.stderr and "REFUSING: the evolve" not in r.stderr


# resolve_intel_image must not turn "refused" or "public install" into "old tag".
def test_intel_fallback_still_applies_to_a_tag_before_the_dedicated_image(tmp_path):
    r = _run(tmp_path, 'resolve_intel_image; echo "INTEL=${NOO_INTEL_IMAGE:-}"',
             NOO_IMAGE_TAG="v0.2.5", FAKE_MANIFEST_ERR="manifest unknown")
    assert "INTEL=ghcr.io/noomesh/trellion:v0.2.5" in r.stdout


@pytest.mark.parametrize("err,tag", [
    ("denied: x", "v0.2.5"),            # refused says nothing about the tag
    ("no such host", "v0.2.5"),          # nor does an unreachable registry
    ("manifest unknown", "v0.6.0"),      # absent on a NEW tag = not in this registry
    ("manifest unknown", "latest"),      # unknown tag cannot be shown old
])
def test_intel_fallback_does_not_mask_a_licence_or_registry_problem(tmp_path, err, tag):
    r = _run(tmp_path, 'resolve_intel_image; echo "INTEL=${NOO_INTEL_IMAGE:-}"',
             NOO_IMAGE_TAG=tag, FAKE_MANIFEST_ERR=err)
    assert "INTEL=\n" in r.stdout + "\n", r.stdout


def test_both_launchers_call_the_gate_before_any_pull():
    start = (REPO / "scripts/noomesh-start.sh").read_text()
    restart = (REPO / "scripts/noomesh-restart.sh").read_text()
    assert "require_addon_images || exit 1" in restart
    assert "require_addon_images || exit 1" in start
    assert start.index("require_addon_images || exit 1") < start.index("ui_step \"Pulling images\"")
