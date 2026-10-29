# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Distribution mode: the dist overlay must stay in sync with the release pipeline.

`noo stack start --dist` runs the stack from the published GHCR images instead
of building from source. That only works if two files agree:

  docker-compose.dist.yml          — which services are pull-only
  .github/workflows/images-release.yml — which images actually get published

If they drift, `--dist` fails at runtime with a confusing "manifest unknown"
mid-pull. These tests catch the drift at commit time instead.
"""
from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO_ROOT = Path(__file__).resolve().parents[1]
BASE_COMPOSE = REPO_ROOT / "docker-compose.cluster.yml"
DIST_COMPOSE = REPO_ROOT / "docker-compose.dist.yml"
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "images-release.yml"


def _load(path: Path) -> dict:
    with path.open() as fh:
        return yaml.safe_load(fh)


# The licensed add-on images are NOT built or locked by the stack release
# (core-only, by design): the add-ons' own repos release them with their own
# signed lock, and the overlays take them from the pin (NOO_ADDON_IMAGE_<NAME>).
ADDON_IMAGES = {"trellion-intel", "evolve"}


def _published_images() -> set[str]:
    """Registry image names the stack release pushes, plus the add-on images
    (declared above; released elsewhere, so the overlays may still name them)."""
    return _core_published_images() | ADDON_IMAGES


def test_the_stack_release_pushes_no_addon_image() -> None:
    assert not (_core_published_images() & ADDON_IMAGES), "the stack release must not push an add-on image"
    text = RELEASE_WORKFLOW.read_text()
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    assert "addon-image-resolve" not in code


def _core_published_images() -> set[str]:
    """Registry image names the core release workflow pushes."""
    wf = _load(RELEASE_WORKFLOW)
    jobs = wf["jobs"]
    published = {
        entry.get("image", entry["name"])
        for entry in jobs["images"]["strategy"]["matrix"]["include"]
    }
    # Standalone jobs (deps-core, deps-base, the ffmpeg mirror) push with an
    # explicit `-t "$REGISTRY/$OWNER/<image>:$TAG"`: read the tag they push
    # rather than keeping a hand list here.
    import re

    for job in jobs.values():
        for step in job.get("steps", []):
            run = step.get("run") or ""
            for m in re.finditer(r'-t\s+"\$REGISTRY/\$(?:DHI_)?OWNER/([a-z0-9._-]+):\$TAG"', run):
                published.add(m.group(1))
    published.add("static-ffmpeg")  # mirrored via manifest copy, no -t
    return published


def _image_basename(ref: str) -> str:
    """'${NOO_IMAGE_PREFIX:-x}/postgres-pgvector:${TAG:-latest}' -> 'postgres-pgvector'."""
    without_tag = ref.rsplit(":", 1)[0] if not ref.rstrip().endswith("}") else ref
    # Strip a trailing ':${...}' tag interpolation.
    if ":${" in without_tag:
        without_tag = without_tag.split(":${")[0]
    return without_tag.rsplit("/", 1)[-1]


def test_dist_overlay_exists() -> None:
    assert DIST_COMPOSE.exists(), "docker-compose.dist.yml is required by 'noo stack start --dist'"


def test_every_dist_service_is_pull_only() -> None:
    """The whole point of the overlay: nothing may build in dist mode."""
    dist = _load(DIST_COMPOSE)
    for name, svc in dist["services"].items():
        assert svc.get("pull_policy") == "missing", (
            f"{name} in docker-compose.dist.yml must set pull_policy: missing, "
            f"otherwise dist mode silently builds it from source"
        )


def test_every_dist_service_image_is_published() -> None:
    """A service can only be pull-only if the pipeline actually publishes it."""
    dist = _load(DIST_COMPOSE)
    base = _load(BASE_COMPOSE)
    published = _published_images()

    # An add-on service lives in its overlay, not the base:
    # the dist pin for trellion-intel resolves against that overlay.
    from tests._compose_projection import ADDON_OVERLAYS, load_raw, untag
    addon_services = {}
    for o in ADDON_OVERLAYS:
        addon_services.update(untag(load_raw(REPO_ROOT / o)).get("services") or {})
    for name, svc in dist["services"].items():
        # The overlay may override the image; otherwise inherit from the base
        # or from the add-on overlay that defines the service.
        ref = svc.get("image") or (base["services"].get(name) or addon_services[name])["image"]
        image = _image_basename(ref)
        assert image in published, (
            f"service '{name}' resolves to image '{image}', which the release "
            f"workflow does not publish. Add it to the images matrix in "
            f".github/workflows/images-release.yml or drop it from the dist overlay. "
            f"Published: {sorted(published)}"
        )


def test_every_addon_overlay_image_is_published() -> None:
    """An add-on overlay's services are pull-only on a dist install. The
    unlicensed ones (voice, trellion) pull stack release images, so those must
    be in the release matrix. The licensed ones run the digest ref their own
    signed lock pins: every image line reads ${NOO_ADDON_IMAGE_<NAME>:-…}, set
    only by scripts/lib-dist.sh require_addon_pins, and names no stack-release
    image. (Since an earlier change the dist overlay has no rows for these
    services, so the guarantee lives here.)"""
    import re

    from tests._compose_projection import ADDON_OVERLAYS, load_raw, untag
    published = _core_published_images()
    checked = pinned = 0
    for name in ADDON_OVERLAYS:
        for svc_name, svc in (untag(load_raw(REPO_ROOT / name)).get("services") or {}).items():
            ref = svc.get("image")
            if not ref:
                continue
            if "NOO_ADDON_IMAGE_" in ref:
                m = re.fullmatch(r"\$\{(NOO_ADDON_IMAGE_[A-Z0-9_]+):-noo-addon-unpinned\.invalid/([a-z0-9-]+):run-noo-addons-upgrade\}", ref)
                assert m, f"{name}: {svc_name!r} must read its pin with only the .invalid sentinel as fallback: {ref}"
                assert m.group(2) in ADDON_IMAGES, f"{name}: {svc_name!r} is pin-sourced but names {m.group(2)!r}"
                assert m.group(1) == "NOO_ADDON_IMAGE_" + m.group(2).upper().replace("-", "_"), ref
                pinned += 1
                continue
            if "NOO_IMAGE_PREFIX" not in ref:
                continue
            image = _image_basename(ref)
            assert image not in ADDON_IMAGES, (
                f"{name}: service {svc_name!r} runs licensed add-on image {image!r} without its pin "
                f"(NOO_ADDON_IMAGE_*): {ref}")
            assert image in published, (
                f"{name}: service {svc_name!r} pulls image {image!r}, which the release "
                f"workflow does not publish. Published: {sorted(published)}"
            )
            checked += 1
    assert checked >= 2, f"checked only {checked} published add-on images — the overlay scan broke"
    # The pin-sourced (licensed) overlays: moved with the overlay to the add-on
    # repo (N6). A core overlay is released with the stack, so never pin-sourced.
    assert pinned == 0, f"a core overlay reads a licensed add-on pin ({pinned} services)"


# Profiles the CONTROLLER host starts. `noo stack start` selects controller
# plus these opt-ins, so a --dist install must be able to pull all of them.
#
# Worker/GPU-node profiles (llamacpp, airllm, tei-compose, gpu-tier2, ...) are
# deliberately NOT here. Widening the check to every profile flags six more
# services — airllm, llamacpp and four stunnel-* sidecars — which is a real
# gap but a different one: those run on worker nodes, need arm64 variants, and
# publishing them is a release-pipeline decision, not a bug fix. Tracked
# separately rather than smuggled in behind a voice change.
_CONTROLLER_PROFILES = {"controller", "standalone", "trellion", "voice"}


def test_dist_covers_all_first_party_controller_services() -> None:
    """Any controller-side service that builds locally must be in the overlay.

    `--dist` is a pull-only install. A first-party service that builds from
    source with no dist entry silently becomes a local build.

    This used to check only the `controller` profile, which let the voice
    providers through: whisper and piper are `profiles: ["voice"]`, so
    enabling voice on a --dist install built them from source. Being opt-in at
    RUNTIME is not a reason to be unpublished — an operator who turns a
    profile on still expects a pull.

    Build-only bases (deps-core, deps-base, sandbox-base) are excluded:
    nothing runs them, so they have no dist entry by design.
    """
    base = _load(BASE_COMPOSE)
    dist_services = set(_load(DIST_COMPOSE)["services"])

    missing = []
    for name, svc in base["services"].items():
        if not isinstance(svc, dict):
            continue
        profiles = set(svc.get("profiles") or [])
        if not profiles & _CONTROLLER_PROFILES:
            continue
        if svc.get("pull_policy") != "build":
            continue
        if name not in dist_services:
            missing.append(name)

    assert not missing, (
        f"controller-side services build from source but are absent from "
        f"docker-compose.dist.yml: {sorted(missing)}. Publish them in the "
        f"release workflow and add a pull_policy: missing entry to the "
        f"overlay, or --dist silently builds them."
    )



def test_every_stunnel_door_has_a_dist_override() -> None:
    """A dist install ships no Dockerfile.stunnel, so every service built from
    it needs an image-only dist override, or `--dist` dies with "failed to read
    dockerfile: Dockerfile.stunnel" (rc.1: stunnel-vllm, stunnel-llamacpp)."""
    base = _load(BASE_COMPOSE)["services"]
    dist = _load(DIST_COMPOSE)["services"]
    doors = [
        n
        for n, svc in base.items()
        if isinstance(svc, dict) and isinstance(svc.get("build"), dict) and svc["build"].get("dockerfile") == "Dockerfile.stunnel"
    ]
    assert doors, "no Dockerfile.stunnel services found in the base compose; the guard is parsing nothing"
    missing = sorted(d for d in doors if d not in dist)
    assert not missing, f"Dockerfile.stunnel services with no docker-compose.dist.yml override: {missing}"
    for d in doors:
        assert dist[d].get("pull_policy") == "missing", f"{d}: dist override must set pull_policy: missing"
        assert "/stunnel:" in dist[d].get("image", ""), f"{d}: dist override must use the published stunnel image"
        assert "entrypoint" not in dist[d], f"{d}: dist override must not replace the compose self-pin entrypoint"


def test_service_network_mode_targets_have_dist_overrides() -> None:
    """An engine in `network_mode: service:<x>` cannot start without <x>. If <x>
    builds from source, <x> must be pulled on a dist install."""
    base = _load(BASE_COMPOSE)["services"]
    dist = _load(DIST_COMPOSE)["services"]
    missing = []
    for name, svc in base.items():
        nm = svc.get("network_mode") if isinstance(svc, dict) else None
        if not (isinstance(nm, str) and nm.startswith("service:")):
            continue
        target = nm.split(":", 1)[1]
        tsvc = base.get(target) or {}
        if tsvc.get("build") and target not in dist:
            missing.append(f"{name} -> {target}")
    assert not missing, f"network_mode targets that build from source with no dist override: {missing}"


def test_release_matrix_entries_are_well_formed() -> None:
    """Each matrix entry needs the fields the build step interpolates."""
    wf = _load(RELEASE_WORKFLOW)
    for entry in wf["jobs"]["images"]["strategy"]["matrix"]["include"]:
        for field in ("name", "image", "dockerfile", "context", "platforms"):
            assert field in entry, f"matrix entry {entry.get('name')!r} is missing '{field}'"
        assert "extra_args" in entry, (
            f"matrix entry {entry['name']!r} must define extra_args (empty string is fine) — "
            f"the build step interpolates it unconditionally"
        )
        dockerfile = REPO_ROOT / entry["dockerfile"]
        assert dockerfile.exists(), (
            f"matrix entry {entry['name']!r} points at {entry['dockerfile']}, which does not exist"
        )


# Images the node agent runs on EVERY node, arm64 ones included (host6 under
# Docker Desktop, host9, host2). An amd64-only entry for one of these ships
# an image an arm64 node cannot pull: node-agent is the agent itself; stunnel
# is the mTLS sidecar the agent runs beside each backend it starts (followup
# 1244 §B — without arm64 the agent falls back to alpine + apk on every start).
_NODE_RUN_IMAGES = {"node-agent", "stunnel"}


def test_node_run_images_are_multi_arch() -> None:
    wf = _load(RELEASE_WORKFLOW)
    entries = {e["image"]: e for e in wf["jobs"]["images"]["strategy"]["matrix"]["include"]}
    missing = _NODE_RUN_IMAGES - set(entries)
    assert not missing, f"node-run images absent from the release matrix: {sorted(missing)}"
    for image in sorted(_NODE_RUN_IMAGES):
        platforms = {p.strip() for p in entries[image]["platforms"].split(",")}
        assert {"linux/amd64", "linux/arm64"} <= platforms, (
            f"matrix entry {image!r} publishes {sorted(platforms)} — nodes run it, "
            f"arm64 ones included, so it must build linux/amd64 AND linux/arm64"
        )


def test_legacy_compose_files_are_retired() -> None:
    """A bare `docker compose up` must not resurrect the pre-Rust Python stack."""
    assert not (REPO_ROOT / "docker-compose.yml").exists(), (
        "docker-compose.yml is back in the repo root — a bare 'docker compose up' "
        "would load it (plus docker-compose.override.yml) and start the dead "
        "pre-Rust stack. It belongs in legacy/."
    )
    assert not (REPO_ROOT / "docker-compose.prod.yml").exists(), (
        "docker-compose.prod.yml belongs in legacy/ (pre-Rust Python stack)"
    )


# ── #43b guard: compose consumers must be dist-aware ─────────────────────
# Finding #43 was restart.sh composing without the dist overlay and dying
# building unshipped Dockerfiles; the #43b sweep found the same blindness in
# the host-watcher (the gateway's own restart button), bootstrap-standby and
# the model-switch paths. The shared block now lives in scripts/lib-dist.sh.
# This test pins the contract: every lifecycle script that runs `docker
# compose ... up` against the stack either sources lib-dist.sh or is on the
# explicit exemption list below (dev-by-design, with the reason).

SCRIPTS_DIR = REPO_ROOT / "scripts"

# Scripts allowed to run `docker compose ... up` without lib-dist.sh.
DIST_EXEMPT_UP_CONSUMERS = {
    # The launcher carries its own richer dist block (fatal tag resolution,
    # ghcr login precheck, --build conflict) — the reference implementation.
    "noomesh-start.sh",
    # Dev-only builder; its stack-recreate step now REFUSES under dist.
    "noomesh-rebuild.sh",
    # Sandbox harness drives noomesh-start.sh --dist for the actual stack.
    "noomesh-sandbox.sh",
}


def test_compose_up_consumers_source_lib_dist() -> None:
    offenders = []
    for script in sorted(SCRIPTS_DIR.glob("*.sh")):
        text = script.read_text(errors="replace")
        runs_compose_up = any(
            "compose" in line and " up " in f" {line} "
            for line in text.splitlines()
            if not line.lstrip().startswith("#") and "docker compose" in line
        )
        if not runs_compose_up:
            continue
        if script.name in DIST_EXEMPT_UP_CONSUMERS:
            continue
        if "lib-dist.sh" not in text:
            offenders.append(script.name)
    assert not offenders, (
        f"{offenders} run 'docker compose ... up' without sourcing "
        "scripts/lib-dist.sh — the #43 class. Source it (see "
        "noomesh-restart.sh) or add an exemption WITH a reason above."
    )


def test_lib_dist_neutralizes_every_dev_overlay_var() -> None:
    """The overlay-neutralization list must cover every dev bind-mount var
    the base compose file interpolates, or a dist recreate mounts the source
    tree over a released image."""
    lib = (SCRIPTS_DIR / "lib-dist.sh").read_text()
    # The base plus every add-on overlay: trellion's TRELLION_SRC mount moved
    # with its service into docker-compose.trellion.yml.
    from tests._compose_projection import ADDON_OVERLAYS
    composed = BASE_COMPOSE.read_text() + "".join((REPO_ROOT / o).read_text() for o in ADDON_OVERLAYS)
    # (NOO_UI_INDEX_OVERLAY is exported too for parity with start.sh but no
    # longer appears in the base file, so it is not asserted here.)
    for var in ("NOO_SRC_OVERLAY", "NOO_UI_STATIC_OVERLAY", "TRELLION_SRC"):
        assert f"${{{var}" in composed, f"{var} no longer in any compose file — update this test + lib-dist.sh"
        assert f"export {var}=" in lib, f"lib-dist.sh does not neutralize {var}"
    # And the add-on pull policy (phase E): overlays cannot have dist rows.
    assert 'export NOO_PULL_POLICY="missing"' in lib, "lib-dist.sh must export NOO_PULL_POLICY=missing in dist mode"
    assert "${NOO_PULL_POLICY:-build}" in (REPO_ROOT / "docker-compose.trellion.yml").read_text()


def test_a_dist_start_never_builds() -> None:
    """`--no-build` on the dist `up`. Several overlay comments asserted the
    launcher already did this; it did not, and that assumption is what let
    trellion reach the build path on a standalone controller."""
    launcher = (SCRIPTS_DIR / "noomesh-start.sh").read_text()
    block = launcher[launcher.index("BUILD_FLAG=\"\""):]
    assert 'BUILD_FLAG="--no-build"' in block[:400], (
        "scripts/noomesh-start.sh must set BUILD_FLAG=--no-build when DIST=true"
    )
    assert "$BUILD_FLAG" in launcher, "and must still pass it to `up`"


def test_every_buildable_addon_overlay_service_is_pull_only_in_dist() -> None:
    """A service that carries BOTH `build:` and `image:` builds by default, and
    an add-on overlay cannot be given a dist row (a row for a service the
    overlay did not compose is a bare service compose refuses). So every such
    service must interpolate its pull policy. trellion did and voice did not;
    voice was covered only by a comment claiming the launcher passes
    --no-build, which it does not."""
    # load_raw, not yaml.safe_load: the overlays carry compose's own `!override`
    # / `!reset` tags, which SafeLoader refuses.
    from tests._compose_projection import ADDON_OVERLAYS, load_raw

    offenders = []
    for overlay in ADDON_OVERLAYS:
        doc = load_raw(REPO_ROOT / overlay)
        for name, svc in (doc.get("services") or {}).items():
            if not isinstance(svc, dict) or "build" not in svc:
                continue
            policy = str(svc.get("pull_policy", ""))
            if policy != "missing" and "NOO_PULL_POLICY" not in policy:
                offenders.append(f"{overlay}:{name} (pull_policy={policy or 'unset'})")
    assert not offenders, (
        f"{offenders} build in dev and would build in DIST too. Add "
        "`pull_policy: ${NOO_PULL_POLICY:-build}` — both dist blocks export "
        "missing."
    )


def test_both_dist_implementations_export_the_same_vars() -> None:
    """There are TWO dist blocks — lib-dist.sh's `apply_dist_mode` and the
    launcher's own, which is exempt from the lib-dist rule above because it is
    the richer reference implementation. Every `noo stack start` and every
    `noo upgrade --stack` takes the LAUNCHER's. So a var added to one and not
    the other is live on the path nothing checked: NOO_PULL_POLICY arrived in
    lib-dist.sh with an earlier change and never reached the launcher, the
    `${NOO_PULL_POLICY:-build}` fallback won, and a standalone controller
    rolling v0.2.72 tried to BUILD trellion from a sibling checkout it does
    not have (host8, 2026-09-23). Neither file is the authority here; they
    must simply agree."""
    import re

    def exports(text: str) -> set[str]:
        return set(re.findall(r"^\s*export ([A-Z_0-9]+)=", text, re.M))

    lib = (SCRIPTS_DIR / "lib-dist.sh").read_text()
    launcher = (SCRIPTS_DIR / "noomesh-start.sh").read_text()
    # lib-dist: the body of apply_dist_mode only. Its sibling helpers
    # (resolve_intel_image) export vars the launcher reaches by other means.
    body = lib[lib.index("apply_dist_mode() {"):]
    lib_vars = exports(body[: body.index("\n}\n")])
    # The launcher: from the --dist guard to the end. Its dist block is not a
    # function, and an export below it is still on the dist path.
    launcher_vars = exports(launcher[launcher.index('ERROR: --dist requires docker-compose.dist.yml'):])
    missing = {v for v in lib_vars if v not in launcher_vars}
    assert not missing, (
        f"scripts/lib-dist.sh exports {sorted(missing)} in dist mode and "
        "scripts/noomesh-start.sh does not. The launcher is the path every "
        "`noo stack start` takes — add the export there too."
    )


# ── evolve ships as a release image (2026-09-14) ─────────────────────────
#
# test_the_evolve_overlay_runs_the_pinned_image_and_builds_nothing and
# test_evolve_and_intel_overlays_resolve_their_image_the_same_way: moved with
# the overlay to the add-on repo (N6).


def test_the_stack_lock_does_not_wait_for_an_addon_image() -> None:
    """The add-ons are released elsewhere; a lock that waited for them would never be signed."""
    lock = _load(RELEASE_WORKFLOW)["jobs"]["lock"]
    assert not ({"evolve", "trellion-intel"} & set(lock["needs"])), lock["needs"]


def test_the_dist_pull_never_pulls_an_addon() -> None:
    """The launcher never pulls a licensed add-on: the CLI pulled it by digest
    with the registry token, and require_addon_pins refused a start whose image
    is not local. The exclusion is derived from the overlays (addon_services),
    not a list of add-on names."""
    src = (REPO_ROOT / "scripts/noomesh-start.sh").read_text()
    assert "NOO_IMAGE_DIGEST_EVOLVE" not in src
    assert "grep -vxF -f <(addon_services $COMPOSE_FILES" in src
    assert "noo-evolve" not in src.split('ui_step "Pulling images"')[1].split("compose_pull")[0]
