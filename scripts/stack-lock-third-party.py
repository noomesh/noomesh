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

  rows   --out DIR   resolve and write DIR/<name> (the lock job)
  check              parse the compose file only, print what would be resolved
"""
from __future__ import annotations

import argparse
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

# lock row name -> how compose spells the image and where its digest resolves:
#   compose  the literal text before `:<version>` in the compose `image:` line
#   repo     the registry reference the tag is resolved against
#   ver      regex of the version part (one repository can carry two rows)
# An optional `${ANY_OVERRIDE:-...}` wrapper around the default is allowed
# (OLLAMA_IMAGE, VLLM_IMAGE, NATS_IMAGE: an operator's own image wins).
THIRD_PARTY: dict[str, dict[str, str]] = {
    "nats": {"compose": "nats", "repo": "docker.io/library/nats", "ver": _VER},
    "nginx": {"compose": "nginx", "repo": "docker.io/library/nginx", "ver": _VER},
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
    ap.add_argument("--only", action="append", choices=sorted(THIRD_PARTY), help="restrict to these rows (tests)")
    a = ap.parse_args(argv)
    text = a.compose.read_text()
    try:
        for name, entry in sorted(THIRD_PARTY.items()):
            if a.only and name not in a.only:
                continue
            version = compose_version(name, text)
            ref = f"{entry['repo']}:{version}"
            if a.mode == "check":
                print(f"{name}: {ref}")
                continue
            if a.out is None:
                ap.error("rows needs --out")
            row = f"{name}@{resolve(ref)}"
            a.out.mkdir(parents=True, exist_ok=True)
            (a.out / name).write_text(row + "\n")
            print(f"{row}   ({ref})")
    except LockError as e:
        print(f"::error::stack-lock-third-party: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
