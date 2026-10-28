# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every host-side file a compose service mounts or names must be in the
standalone deploy slice (`STANDALONE_FILES` / `STANDALONE_DIRS` in
noo-cli/build.rs), or a `--dist` install fails at `compose up` before any
container is recreated.

2026-09-10: the sandbox gained `security_opt: seccomp=./docker/seccomp-sandbox.json`
and the slice did not ship it; the v0.2.33 roll on the standalone controller
died with "opening seccomp profile … no such file or directory" on every
service, twice. The compose files and the slice list live in different
trees and nothing tied them together.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = ["docker-compose.cluster.yml", "docker-compose.dist.yml"]

# Paths compose references that the slice deliberately does NOT ship: build
# contexts (dist never builds), and things the wizard/launcher generate.
NOT_SHIPPED_PREFIXES = ("docker/Dockerfile", "docker/sandbox", "docker/tools")
GENERATED = {".env", "noomesh.yaml", "secrets", "pki", ".noo-host-spool", "docker-compose.override.yml", "stack.lock",
             # the launcher fills these with add-on bundle declarations (i163)
             ".noo-addon-systems", ".noo-addon-workloads", ".noo-addon-routes"}


def slice_lists() -> tuple[set[str], list[str]]:
    src = (ROOT / "noo-cli/build.rs").read_text()
    files = set(re.findall(r'^\s*"([^"]+)",\s*$', src[src.index("STANDALONE_FILES"):src.index("STANDALONE_DIRS")], re.M))
    dirs_src = src[src.index("const STANDALONE_DIRS"):]
    dirs = re.findall(r'"([^"]+)"', dirs_src[: dirs_src.index("];")])
    return files, dirs


def compose_host_paths() -> set[str]:
    """Relative `./x` paths in volumes, security_opt and env_file entries."""
    out: set[str] = set()
    for name in COMPOSE_FILES:
        doc = yaml.safe_load((ROOT / name).read_text())
        for svc in (doc.get("services") or {}).values():
            for v in svc.get("volumes") or []:
                src = v.split(":")[0] if isinstance(v, str) else (v.get("source") or "")
                if src.startswith("./"):
                    out.add(src[2:].rstrip("/"))
            for so in svc.get("security_opt") or []:
                m = re.match(r"^(?:seccomp|apparmor)=\./(.+)$", so)
                if m:
                    out.add(m.group(1))
            for ef in svc.get("env_file") or []:
                path = ef if isinstance(ef, str) else ef.get("path", "")
                if path.startswith("./"):
                    out.add(path[2:])
    return out


def test_every_compose_host_file_is_in_the_slice() -> None:
    files, dirs = slice_lists()
    missing = []
    for path in sorted(compose_host_paths()):
        if path in GENERATED or path.startswith(NOT_SHIPPED_PREFIXES):
            continue
        # A path under a shipped directory is covered by that directory.
        if any(path == d or path.startswith(d + "/") for d in dirs):
            continue
        # Directories the compose mounts that the slice ships file-by-file
        # (e.g. `./scripts`) are covered when at least one listed file lives there.
        if not (ROOT / path).is_file() and any(f.startswith(path + "/") for f in files):
            continue
        if path not in files:
            missing.append(path)
    assert not missing, (
        "compose references host files the standalone slice does not ship "
        "(add them to STANDALONE_FILES in noo-cli/build.rs): " + ", ".join(missing)
    )


def test_seccomp_profile_is_shipped() -> None:
    files, _ = slice_lists()
    assert "docker/seccomp-sandbox.json" in files
    assert (ROOT / "docker/seccomp-sandbox.json").is_file()


def root_overlays() -> set[str]:
    """Every compose overlay at the repo root the launcher could select.

    The generated override is excluded: it is written on the box, never
    shipped. Everything else here is a file `noo stack start` may add with
    `-f`, and a dist install has only the slice to find it in.
    """
    return {p.name for p in ROOT.glob("docker-compose.*.yml")} - GENERATED


def test_every_root_overlay_is_in_the_slice() -> None:
    """An overlay the launcher can pick must be one a dist install receives.

    `docker-compose.evolve.yml` landed on dev, the release published the
    evolve image, the controller rolled to that tag, and no evolve container
    started: the launcher's fallback looked for the overlay beside itself and
    the slice had never been told to ship it. The compose-host-path check
    above could not see this, because it only reads the two base files for
    the `./x` paths they mount — a whole extra overlay is invisible to it.
    """
    files, _ = slice_lists()
    missing = sorted(root_overlays() - files)
    assert not missing, (
        f"compose overlays at the repo root that STANDALONE_FILES does not ship: {missing} — "
        "a dist install cannot find them, so the add-on they run silently does not start"
    )
