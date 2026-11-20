#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Lock rows for the third-party images the stack runs by a FIXED tag.

The signed stack lock (`stack-<tag>.lock`, images-release.yml `lock` job) has
one `<name>@sha256:` row per image the release BUILDS. A third-party image
the compose file runs straight from its upstream registry had no row, so it
was pulled by tag: `ollama/ollama:latest` re-pulled on every roll whenever
upstream moved it (91.6 s on the 0.6.3 -> 0.6.4 roll, 2026-10-15), and no
release recorded which ollama it ran.

For each row of THIRD_PARTY this reads the version the compose file names
(the `${<OVERRIDE>:-<repo>:<version>${NOO_IMAGE_DIGEST_<NAME>:-}}` default,
identical in every service that runs it), refuses `latest` or a missing
digest hook, resolves that tag's index digest from the registry and writes
`<name>@sha256:...` as a lock row. The launcher turns the row into
NOO_IMAGE_DIGEST_<NAME> like any other (noomesh-start.sh), so compose pulls
`<repo>:<version>@sha256:...`: by digest, and not at all when unchanged.

A row whose repo is OUR mirror of an upstream image (directly under the
release namespace, `<namespace>/<name>`, made by a mirror-images.yml lane
`dest_org: <namespace org>`) is held to two more gates before it is written:
  provenance  its resolved digest must equal the digest that lane copies
              from upstream; a missing lane, two lanes for one destination
              or a lane copying a moving tag is refused too;
  anonymous   the digest must be readable WITHOUT credentials (this job logs
              in to ghcr.io, so a private package would otherwise resolve
              here and then fail every stranger's install).
nats and nginx are such rows: official Docker Hub images the stack runs from
OUR mirror (`<namespace>/nats`, `<namespace>/nginx`), so an install never
dials Docker Hub for them, and a mirror that is missing, private or carries
another digest than its lane copied fails the lock job. The DHI rows
(`<namespace>/dhi/<name>`) are another family and are not gated here.

  rows   --out DIR   resolve and write DIR/<name> (the lock job)
  check              parse the compose file only, print what would be resolved
"""
from __future__ import annotations

import argparse
import importlib.util
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.cluster.yml"

# The DHI mirror the compose file's `${NOO_BASE_REGISTRY:-...}` defaults to.
# Read from the compose default itself, so the namespace has one home.
_m = re.search(r"\$\{NOO_BASE_REGISTRY:-([^}]+)\}", COMPOSE.read_text())
if not _m:
    raise SystemExit("docker-compose.cluster.yml has no ${NOO_BASE_REGISTRY:-<default>} reference")
DHI = _m.group(1)
_BASE = "${NOO_BASE_REGISTRY:-" + DHI + "}"
_VER = r"[A-Za-z0-9][A-Za-z0-9._-]*"

# The release namespace (scripts/lib-dist.sh `release_image_namespace`, its one
# home in shell). mirror-images.yml copies official upstream images to
# <namespace>/<name>:<tag> (`dest_org: noomesh`).
_ns = re.search(r"^release_image_namespace\(\)\s*\{\s*printf\s+'([^']+)';\s*\}",
                (ROOT / "scripts/lib-dist.sh").read_text(), re.M)
if not _ns:
    raise SystemExit("scripts/lib-dist.sh: release_image_namespace() not found in its one-line printf form")
NS = _ns.group(1)
MIRROR_WORKFLOW = ROOT / ".github/workflows/mirror-images.yml"


def _plan_module():
    """scripts/mirror-plan.py: the one parser of mirror-images.yml's lanes and
    the read-only (anonymous) registry reader."""
    spec = importlib.util.spec_from_file_location("mirror_plan", ROOT / "scripts/mirror-plan.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

# lock row name -> how compose spells the image and where its digest resolves:
#   compose  the literal text before `:<version>` in the compose `image:` line
#   repo     the registry reference the tag is resolved against
#   ver      regex of the version part (one repository can carry two rows)
# An optional `${ANY_OVERRIDE:-...}` wrapper around the default is allowed
# (OLLAMA_IMAGE, VLLM_IMAGE, NATS_IMAGE: an operator's own image wins).
THIRD_PARTY: dict[str, dict[str, str]] = {
    # OUR mirrors of the official Docker Hub images (mirror-images.yml lanes,
    # `dest_org: noomesh`): resolved from the mirror, held to its provenance
    # and anonymous-pull gates (mirror_org below).
    "nats": {"compose": NS + "/nats", "repo": NS + "/nats", "ver": _VER},
    "nginx": {"compose": NS + "/nginx", "repo": NS + "/nginx", "ver": _VER},
    "redis": {"compose": _BASE + "/redis", "repo": DHI + "/redis", "ver": _VER},
    "loki": {"compose": _BASE + "/loki", "repo": DHI + "/loki", "ver": _VER},
    "tempo": {"compose": _BASE + "/tempo", "repo": DHI + "/tempo", "ver": _VER},
    "prometheus": {"compose": _BASE + "/prometheus", "repo": DHI + "/prometheus", "ver": _VER},
    "alertmanager": {"compose": _BASE + "/alertmanager", "repo": DHI + "/alertmanager", "ver": _VER},
    "grafana": {"compose": _BASE + "/grafana", "repo": DHI + "/grafana", "ver": _VER},
    "node-exporter": {"compose": _BASE + "/node-exporter", "repo": DHI + "/node-exporter", "ver": _VER},
    "tei": {"compose": "ghcr.io/huggingface/text-embeddings-inference",
            "repo": "ghcr.io/huggingface/text-embeddings-inference", "ver": "(?!cpu-)" + _VER},
    "tei-cpu": {"compose": "ghcr.io/huggingface/text-embeddings-inference",
                "repo": "ghcr.io/huggingface/text-embeddings-inference", "ver": "cpu-" + _VER},
    "vllm": {"compose": "vllm/vllm-openai", "repo": "docker.io/vllm/vllm-openai", "ver": "v[A-Za-z0-9._-]*"},
}

# The lock row noo-cli's throwaway helper container rides (noo-cli/src/
# helper_image.rs: the bind-mount probe, the data-dir chown, `cluster verify`'s
# `du`). It is the nginx row, so one bump of the mirrored nginx moves the
# stack and the helper together; tests/test_helper_image_ride.py ties them.
HELPER_ROW = "nats"

ATTEMPTS = 4


class LockError(Exception):
    pass


def digest_var(name: str) -> str:
    return "NOO_IMAGE_DIGEST_" + name.upper().replace("-", "_")


def _image_re(name: str, hook: bool) -> "re.Pattern[str]":
    """An `image:` line running `name`: [${OVERRIDE:-]compose:ver<hook>[}]."""
    e = THIRD_PARTY[name]
    tail = (r"\$\{" + re.escape(digest_var(name)) + r":-(?:@sha256:[0-9a-f]{64})?\}") if hook else r""
    return re.compile(
        r"^\s*image:\s*(?:\$\{[A-Z][A-Z0-9_]*:-)?" + re.escape(e["compose"]) + r":(" + e["ver"] + r")"
        + tail + (r"\}?\s*$" if hook else r""),
        re.M,
    )


def compose_version(name: str, text: str) -> str:
    """The one version every compose service running `name` names."""
    hook = digest_var(name)
    found = set(_image_re(name, True).findall(text))
    pinned = len(_image_re(name, True).findall(text))
    mentions = len(_image_re(name, False).findall(text))
    if not found:
        raise LockError(f"no compose service runs {name} with a ${{{hook}:-}} digest hook "
                        f"({THIRD_PARTY[name]['compose']}:<version>${{{hook}:-}})")
    if mentions != pinned:
        raise LockError(f"{mentions} services run {name} but only {pinned} carry the {hook} pin: every one must")
    if len(found) != 1:
        raise LockError(f"compose names {name} at several versions {sorted(found)}: one release, one version")
    version = found.pop()
    if version == "latest":
        raise LockError(f"compose runs {name}:latest: pin a version (a lock row for a moving tag pins nothing)")
    return version


def mirror_org(name: str) -> str | None:
    """The GHCR org a row's repo is OUR mirror in (`<namespace>/<name>`, one
    path segment under the release namespace), else None: upstream registries
    and the nested DHI family are not mirror rows."""
    repo = THIRD_PARTY[name]["repo"]
    if re.fullmatch(re.escape(NS) + r"/[a-z0-9][a-z0-9._-]*", repo):
        return NS.removeprefix("ghcr.io/")
    return None


def mirror_source_digest(name: str, version: str, workflow: str) -> str:
    """The digest the mirror-images.yml lane copying `name:version` into the
    row's org is pinned to. Refuses a missing lane, two lanes for one
    destination, and a lane whose source is not pinned by digest."""
    org = mirror_org(name)
    if org is None:
        raise LockError(f"{name}: {THIRD_PARTY[name]['repo']} is not a mirror under {NS}")
    dest = f"{THIRD_PARTY[name]['repo'].rsplit('/', 1)[1]}:{version}"
    plan = _plan_module()
    found = [ln["source"] for ln in plan.lanes(workflow)
             # a lane with no dest_org copies to the repository owner, the
             # release namespace's org (mirror-images.yml's copy step)
             if ln["dest"] == dest and (ln.get("dest_org") or NS.removeprefix("ghcr.io/")) == org]
    if not found:
        raise LockError(f"no mirror-images.yml lane copies {dest} to ghcr.io/{org} (dest_org: {org}): "
                        f"the lock pins the mirror, so the mirror must be declared")
    if len(found) != 1:
        raise LockError(f"{len(found)} mirror-images.yml lanes copy {dest} to ghcr.io/{org}: one source per mirror")
    digest = plan.source_digest(found[0])
    if digest is None:
        raise LockError(f"the mirror lane for {dest} copies {found[0]}: not by digest (a moving tag proves nothing)")
    return digest


def anonymous_digest(repo: str, digest: str) -> tuple[str, str]:
    """(state, digest) of `repo@digest` read with NO credentials (an anonymous
    ghcr pull token, a manifest GET): what a stranger's install can pull."""
    return _plan_module().fetch_digest(repo.removeprefix("ghcr.io/"), digest)


def check_anonymous(repo: str, digest: str) -> None:
    state, got = anonymous_digest(repo, digest)
    if state != "present" or got != digest:
        raise LockError(f"{repo}@{digest} is not pullable anonymously ({state}): a stranger's install cannot "
                        f"pull it. Make the package public (GitHub package settings), then re-run")


def resolve(ref: str) -> str:
    """The registry's index digest for `ref`, retried on transient failure."""
    err = ""
    for attempt in range(1, ATTEMPTS + 1):
        r = subprocess.run(
            ["docker", "buildx", "imagetools", "inspect", ref, "--format", "{{json .Manifest.Digest}}"],
            capture_output=True, text=True, timeout=120,
        )
        d = r.stdout.strip().strip('"')
        if r.returncode == 0 and re.fullmatch(r"sha256:[0-9a-f]{64}", d):
            return d
        err = (r.stderr or r.stdout).strip()
        if attempt < ATTEMPTS:
            print(f"::warning::{ref}: attempt {attempt}/{ATTEMPTS} failed ({err}); retrying", file=sys.stderr)
            time.sleep(10 * attempt)
    raise LockError(f"could not resolve {ref}: {err}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mode", choices=("rows", "check"))
    ap.add_argument("--out", type=Path, help="directory for the row files (rows)")
    ap.add_argument("--compose", type=Path, default=COMPOSE)
    ap.add_argument("--mirror-workflow", type=Path, default=MIRROR_WORKFLOW)
    ap.add_argument("--only", action="append", choices=sorted(THIRD_PARTY), help="restrict to these rows (tests)")
    a = ap.parse_args(argv)
    text = a.compose.read_text()
    try:
        for name, entry in sorted(THIRD_PARTY.items()):
            if a.only and name not in a.only:
                continue
            version = compose_version(name, text)
            ref = f"{entry['repo']}:{version}"
            mirrored = mirror_org(name) is not None
            if a.mode == "check":
                src = ""
                if mirrored:
                    src = f"   (mirror of {mirror_source_digest(name, version, a.mirror_workflow.read_text())})"
                print(f"{name}: {ref}{src}")
                continue
            if a.out is None:
                ap.error("rows needs --out")
            digest = resolve(ref)
            if mirrored:
                want = mirror_source_digest(name, version, a.mirror_workflow.read_text())
                if digest != want:
                    raise LockError(f"{ref} is {digest}, but mirror-images.yml copies it from {want}: "
                                    f"the mirror is not the upstream image it names")
                print(f"  provenance ok: {name}@{digest} = mirror-images.yml lane source")
                check_anonymous(entry["repo"], digest)
                print(f"  anonymous pull ok: {entry['repo']}@{digest}")
            row = f"{name}@{digest}"
            a.out.mkdir(parents=True, exist_ok=True)
            (a.out / name).write_text(row + "\n")
            print(f"{row}   ({ref})")
    except LockError as e:
        print(f"::error::stack-lock-third-party: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
