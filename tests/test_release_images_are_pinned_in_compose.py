# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every image the release matrix builds and the lock pins must be what the
compose file RUNS on a dist install — the `${NOO_IMAGE_PREFIX}/<img>:${NOO_IMAGE_TAG}${NOO_IMAGE_DIGEST_<IMG>:-}`
expression, never a local build name. `llamacpp` named `noomesh/llamacpp:latest`
while the lock carried its digest, so `--profile llamacpp` on a dist box tried
to build from a Dockerfile the deploy slice does not ship (2026-09-07)."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

# Matrix images that are build stages or base layers, not compose services.
NOT_A_COMPOSE_SERVICE = {"deps-core", "deps-base", "static-ffmpeg"}
# Matrix image name → compose service name where they differ.
# `stunnel` is one image behind several sidecars; the one a dist install
# runs on the controller is the standalone embedder's (the others are on
# inference-node profiles and still build locally — docker-compose.dist.yml).
SERVICE_FOR_IMAGE = {"postgres-pgvector": "postgres", "stunnel": "stunnel-ollama-embed"}


def release_matrix_images() -> set[str]:
    wf = yaml.safe_load((ROOT / ".github/workflows/images-release.yml").read_text())
    out: set[str] = set()
    for job in wf["jobs"].values():
        for entry in (job.get("strategy", {}).get("matrix", {}) or {}).get("include", []) or []:
            if isinstance(entry, dict) and "image" in entry:
                out.add(entry["image"])
    return out


def effective_image(service: str) -> str:
    """What a dist install runs: the overlay's image when it sets one, else the base file's."""
    base = yaml.safe_load((ROOT / "docker-compose.cluster.yml").read_text())["services"]
    # An add-on's service lives in its overlay, not the base:
    # whisper, piper, trellion-intel, noo-evolve.
    from tests._compose_projection import ADDON_OVERLAYS, load_raw, untag
    for overlay in ADDON_OVERLAYS:
        for name, svc in (untag(load_raw(ROOT / overlay)).get("services") or {}).items():
            base.setdefault(name, svc)
    dist = yaml.safe_load((ROOT / "docker-compose.dist.yml").read_text())["services"]
    assert service in base, f"compose has no service `{service}` in the base or any add-on overlay"
    return (dist.get(service) or {}).get("image") or base[service].get("image", "")


def test_every_released_compose_service_uses_the_release_pin() -> None:
    checked = 0
    for img in sorted(release_matrix_images() - NOT_A_COMPOSE_SERVICE):
        svc = SERVICE_FOR_IMAGE.get(img, img)
        image = effective_image(svc)
        var = "NOO_IMAGE_DIGEST_" + img.upper().replace("-", "_")
        inner = r"\$\{NOO_IMAGE_PREFIX:[-?][^}]*\}/" + re.escape(img) + r":\$\{NOO_IMAGE_TAG:[-?][^}]*\}\$\{" + var + r":-\}"
        if img == "llamacpp":
            # llamacpp also honours LLAMACPP_IMAGE (the same override the Go
            # node agent takes) ahead of the release pin — the pin is still
            # the DEFAULT the override falls back to, so it must appear
            # unchanged inside that wrapper.
            pin = re.compile(r"^\$\{LLAMACPP_IMAGE:-" + inner + r"\}$")
        elif img == "ollama":
            # Like llamacpp: an operator's OLLAMA_IMAGE wins over the release pin.
            pin = re.compile(r"^\$\{OLLAMA_IMAGE:-" + inner + r"\}$")
        else:
            pin = re.compile("^" + inner + "$")
        assert pin.match(image), (
            f"service `{svc}` runs `{image}` on a dist install — it must be the released, lock-pinned image `{img}`"
        )
        checked += 1
    assert checked >= 9, f"only {checked} services checked — did the matrix parse?"


def test_dist_overlay_pulls_llamacpp() -> None:
    dist = yaml.safe_load((ROOT / "docker-compose.dist.yml").read_text())
    assert dist["services"].get("llamacpp", {}).get("pull_policy") == "missing", (
        "a dist box must PULL llamacpp, never fall back to the base service's build: block"
    )
