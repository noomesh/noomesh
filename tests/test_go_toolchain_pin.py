# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The Go toolchain that node-agent-go asks for is the one the release builds with.

CI's go-node-agent job uses setup-go with go-version-file, which downloads
whatever toolchain go.mod's `go` directive names, so a dependency bump that
raises the directive passes CI. The release lanes build inside the mirrored
DHI golang image of the directive's major.minor (GOTOOLCHAIN=auto fetches a
newer patch release, but the image line is still the one that is mirrored
and scanned), and a directive above the image's Go broke them once. That is how 0.6.3-rc.2 broke: a Dependabot
group bump (nats-server v2.15.1, x/crypto, x/sys, x/time) raised `go 1.25.0`
to `go 1.26.0` while every builder stayed on golang:1.25.

So the directive's major.minor must equal the golang image every build site
names, and that image must be a mirrored lane. Raising the directive is then
a deliberate toolchain bump: mirror the new tag, move the build sites, and
this test passes again.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
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
            f"node-agent-go/go.mod says go {want}; these must match (bump both deliberately)"
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


# The patch level: the image tag above is floating (golang:1.26), so which
# 1.26.x it holds is whatever the mirror last pulled. go.mod's `toolchain`
# line names the patch release CI's govulncheck passes on (0.6.8-rc.1's
# darwin agent shipped go1.26.9 after GO-2026-6809 was fixed in 1.26.10).
# Each build site runs GOTOOLCHAIN=auto, so Go downloads that release when
# the image is older, verified by the checksum database; the guard then
# refuses anything older and prints which toolchain builds.

GUARD = REPO / "node-agent-go" / "require-toolchain.sh"


def test_every_build_site_checks_the_patch_level_before_building():
    for rel in BUILD_SITES:
        code = [l for l in (REPO / rel).read_text().splitlines() if not l.lstrip().startswith("#")]
        text = "\n".join(code)
        guard = text.find("require-toolchain.sh")
        build = text.find("go build")
        assert guard != -1, f"{rel} does not run require-toolchain.sh"
        assert guard < build, f"{rel} runs go build before require-toolchain.sh"


# Lines a build site runs (comments dropped), joined.
def _code(rel: str) -> str:
    return "\n".join(l for l in (REPO / rel).read_text().splitlines() if not l.lstrip().startswith("#"))


def test_every_build_site_selects_the_toolchain_with_verification_on():
    for rel in BUILD_SITES:
        code = _code(rel)
        assert re.search(r"GOTOOLCHAIN=auto\b", code), f"{rel} must build with GOTOOLCHAIN=auto"
        assert "GOTOOLCHAIN=local" not in code, f"{rel} pins GOTOOLCHAIN=local: a stale image ships an unpatched Go"
        for off in ("GOSUMDB=", "GONOSUMDB", "GONOSUMCHECK", "GOINSECURE", "-insecure", "GOPROXY=off", "GOPROXY=direct"):
            assert off not in code, f"{rel} sets {off}: a downloaded toolchain must be verified by sum.golang.org"
    # build-cross runs as the caller's uid: GOPATH (the sumdb cache) must be
    # writable or every toolchain download fails to verify.
    assert re.search(r"-e GOPATH=/tmp/", _code("node-agent-go/build-cross.sh"))


def _run_guard(
    tmp_path: Path, go_version: str, toolchain: str | None, image: str | None = None, sumdb: str = "sum.golang.org",
    extra: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    mod = "module x\n\ngo 1.26.0\n" + (f"toolchain go{toolchain}\n" if toolchain else "")
    (tmp_path / "go.mod").write_text(mod)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "go"
    # `go env GOVERSION` is the selected toolchain; with GOTOOLCHAIN=local it
    # is the image's own. Other `go env X` answer from FAKE_<X>.
    fake.write_text(
        "#!/bin/sh\n"
        '[ "$1" = env ] || exit 2\n'
        'if [ "$2" = GOVERSION ]; then\n'
        f'  if [ "${{GOTOOLCHAIN:-}}" = local ]; then echo go{image or go_version}; else echo go{go_version}; fi; exit 0\n'
        "fi\n"
        'eval "echo \\${FAKE_$2:-}"\n'
    )
    fake.chmod(0o755)
    env = {**os.environ, "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}", "FAKE_GOSUMDB": sumdb, **(extra or {})}
    env.pop("GOTOOLCHAIN", None)
    return subprocess.run(["sh", str(GUARD)], cwd=tmp_path, env=env, capture_output=True, text=True)


@pytest.mark.parametrize(
    ("have", "want", "ok"),
    [
        ("1.26.9", "1.26.10", False),  # the rc.1 case: sort -V, not string order
        ("1.26.10", "1.26.10", True),
        ("1.26.11", "1.26.10", True),
        ("1.27.0", "1.26.10", True),
        ("1.26.10", None, False),  # no toolchain line: nothing to hold a build to
    ],
)
def test_the_guard_refuses_an_older_go(tmp_path, have, want, ok):
    r = _run_guard(tmp_path, have, want)
    assert (r.returncode == 0) is ok, r.stdout + r.stderr
    assert f"go {have}" in r.stdout, "the build log names the Go it used"


def test_the_guard_says_which_toolchain_builds(tmp_path):
    r = _run_guard(tmp_path, "1.26.10", "1.26.10")
    assert r.returncode == 0 and "toolchain: local DHI go1.26.10" in r.stdout, r.stdout + r.stderr


@pytest.mark.parametrize(
    ("sumdb", "extra", "ok"),
    [
        ("sum.golang.org", {}, True),
        ("off", {}, False),
        ("sum.golang.org", {"FAKE_GONOSUMDB": "golang.org/toolchain"}, False),
        ("sum.golang.org", {"FAKE_GOINSECURE": "*"}, False),
        ("sum.golang.org", {"FAKE_GOFLAGS": "-mod=mod -insecure"}, False),
        ("sum.golang.org", {"FAKE_GOFLAGS": "-mod=mod"}, True),
    ],
)
def test_a_downloaded_toolchain_is_accepted_only_verified(tmp_path, sumdb, extra, ok):
    # The mirror's 1.26.9 image; Go selected (downloaded) 1.26.10.
    r = _run_guard(tmp_path, "1.26.10", "1.26.10", image="1.26.9", sumdb=sumdb, extra=extra)
    assert (r.returncode == 0) is ok, r.stdout + r.stderr
    if ok:
        assert "toolchain: downloaded go1.26.10 (sumdb-verified, sum.golang.org)" in r.stdout, r.stdout


def test_go_mod_names_a_patch_release():
    assert re.search(r"^toolchain go\d+\.\d+\.\d+\s*$", GO_MOD.read_text(), re.M), (
        "node-agent-go/go.mod needs a `toolchain goX.Y.Z` line; the build sites hold to it"
    )
