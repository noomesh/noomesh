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

# lock row name -> (upstream repository as compose names it, override env var)
THIRD_PARTY: dict[str, tuple[str, str]] = {
    "ollama": ("ollama/ollama", "OLLAMA_IMAGE"),
}

ATTEMPTS = 4


class LockError(Exception):
    pass


def digest_var(name: str) -> str:
    return "NOO_IMAGE_DIGEST_" + name.upper().replace("-", "_")


def compose_version(name: str, text: str) -> str:
    """The one version every compose service running `name` names."""
    repo, override = THIRD_PARTY[name]
    pat = re.compile(
        r"^\s*image:\s*\$\{" + re.escape(override) + r":-" + re.escape(repo)
        + r":([A-Za-z0-9._-]+)\$\{" + re.escape(digest_var(name)) + r":-\}\}\s*$",
        re.M,
    )
    found = set(pat.findall(text))
    mentions = len(re.findall(r"^\s*image:.*\b" + re.escape(repo) + r"[:@]", text, re.M))
    if not found:
        raise LockError(f"no compose service runs {repo} as "
                        f"${{{override}:-{repo}:<version>${{{digest_var(name)}:-}}}}")
    if mentions != len(pat.findall(text)):
        raise LockError(f"{mentions} services name {repo} but only {len(pat.findall(text))} "
                        f"carry the {digest_var(name)} pin: every one must")
    if len(found) != 1:
        raise LockError(f"compose names {repo} at several versions {sorted(found)}: one release, one version")
    version = found.pop()
    if version == "latest":
        raise LockError(f"compose runs {repo}:latest: pin a version (a lock row for a moving tag pins nothing)")
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
    a = ap.parse_args(argv)
    text = a.compose.read_text()
    try:
        for name, (repo, _) in sorted(THIRD_PARTY.items()):
            version = compose_version(name, text)
            ref = f"docker.io/{repo}:{version}"
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
