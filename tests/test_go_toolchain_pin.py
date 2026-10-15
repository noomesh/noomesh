# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The Go toolchain that node-agent-go asks for is the one the release builds with.

CI's go-node-agent job uses setup-go with go-version-file, which downloads
whatever toolchain go.mod's `go` directive names, so a dependency bump that
raises the directive passes CI. The release lanes do not: they build inside
the mirrored DHI golang image with GOTOOLCHAIN=local, and a directive above
the image's Go fails there. That is how 0.6.3-rc.2 broke: a Dependabot
group bump (nats-server v2.15.1, x/crypto, x/sys, x/time) raised `go 1.25.0`
to `go 1.26.0` while every builder stayed on golang:1.25.

So the directive's major.minor must equal the golang image every build site
names, and that image must be a mirrored lane. Raising the directive is then
a deliberate toolchain bump: mirror the new tag, move the build sites, and
this test passes again.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
GO_MOD = REPO / "node-agent-go" / "go.mod"

# Every file that names the golang builder image. A new one must be added
# here (test_no_unlisted_golang_image_site catches it).
BUILD_SITES = [
    "docker/Dockerfile.node-agent-go",
    "node-agent-go/build-cross.sh",
]

IMAGE_RE = re.compile(r"golang:(\d+\.\d+)-debian13-dev")


def _directive() -> str:
    m = re.search(r"^go (\d+)\.(\d+)(?:\.\d+)?\s*$", GO_MOD.read_text(), re.M)
    assert m, "node-agent-go/go.mod has no `go` directive"
    return f"{m.group(1)}.{m.group(2)}"


def _site_versions(rel: str) -> set[str]:
    found = set(IMAGE_RE.findall((REPO / rel).read_text()))
    assert found, f"{rel}: no golang:<x.y>-debian13-dev image found"
    return found


def _mirrored_golang() -> set[str]:
    doc = yaml.safe_load((REPO / ".github/workflows/mirror-images.yml").read_text())
    lanes = doc["jobs"]["mirror"]["strategy"]["matrix"]["include"]
    out = set()
    for lane in lanes:
        m = IMAGE_RE.fullmatch(lane.get("dest", "").split("/")[-1])
        if m:
            out.add(m.group(1))
    assert out, "mirror-images.yml mirrors no golang:<x.y>-debian13-dev lane"
    return out


def test_every_build_site_uses_the_go_mod_toolchain():
    want = _directive()
    for rel in BUILD_SITES:
        assert _site_versions(rel) == {want}, (
            f"{rel} builds with golang {sorted(_site_versions(rel))} but "
            f"node-agent-go/go.mod says go {want}; the release builds with "
            "GOTOOLCHAIN=local, so these must match (bump both deliberately)"
        )


def test_the_build_image_is_mirrored():
    want = _directive()
    assert want in _mirrored_golang(), (
        f"golang:{want}-debian13-dev is not a lane in mirror-images.yml; "
        "the release builds FROM the ghcr mirror"
    )


def test_no_unlisted_golang_image_site():
    roots = [".github", "docker", "scripts", "node-agent-go"]
    sites = set()
    for root in roots:
        for p in (REPO / root).rglob("*"):
            if not p.is_file() or p.suffix in {".sum", ".go"}:
                continue
            try:
                text = p.read_text()
            except (UnicodeDecodeError, OSError):
                continue
            if IMAGE_RE.search(text):
                sites.add(str(p.relative_to(REPO)))
    sites.discard(".github/workflows/mirror-images.yml")
    assert sites == set(BUILD_SITES), (
        f"golang image named in {sorted(sites - set(BUILD_SITES))}; add to BUILD_SITES"
        if sites - set(BUILD_SITES)
        else f"BUILD_SITES is stale: {sorted(set(BUILD_SITES) - sites)}"
    )
