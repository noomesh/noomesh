#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Digest-pin every third-party base/mirror image source, and refresh the pins.

followup 17a. A floating `dhi.io/uv:0-debian13-dev` means the same commit
builds different images on different days, with nothing in git to say so.
Every third-party image source this repo names is therefore written
`tag@sha256:<index digest>`: the tag documents intent, the digest pins content,
and an upstream change is a deliberate commit that goes through a rehearsal.

The SOURCES scanned (one parser, shared with tests/test_image_digest_pins_17a.py,
so the guard and the refresher cannot disagree about what a source is):

  dockerfile   every `FROM` in a tracked Dockerfile, and the `ARG X=<image>`
               default of a bare `FROM ${X}`
  mirror       `- source:` rows of .github/workflows/mirror-images.yml
  hub-mirror   rows of .github/hub-mirror.txt
  compose      `image:` lines of docker-compose*.yml; the digest lives in the
               `${NOO_IMAGE_DIGEST_<NAME>:-@sha256:...}` default (the hook the
               signed stack lock overrides at release)
  workflow     FFMPEG_UPSTREAM in images-release.yml

First-party images (ours, built by the release) are not third-party sources.

Where a digest pin is impossible the source is listed in UNPINNABLE with its
reason; nothing else may be unpinned (the guard fails CI).

Modes
  --check            parse; exit 1 if a third-party source is neither pinned
                     nor in UNPINNABLE
  (default)          resolve each pinned reference's tag to its CURRENT index
                     digest and rewrite the file; --report writes a markdown
                     old -> new table. Exit 3 if some source could not resolve
                     (the rest are still rewritten).
  --pin              also pin sources that carry no digest yet
  --new-only         with --pin: do not touch references that already carry a digest
  --via A=B          resolve `A/...` against `B/...` (repeatable). One-off use:
                     pin dhi.io sources from the GHCR mirror that holds them
                     when no dhi.io credential is at hand.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from typing import NamedTuple
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DIGEST = r"sha256:[0-9a-f]{64}"
HOOK = re.compile(r"\$\{(NOO_IMAGE_DIGEST_[A-Z0-9_]+):-(@" + DIGEST + r")?\}")

def release_image_namespace() -> str:
    """The release image namespace, read from its shell home
    (scripts/lib-dist.sh `release_image_namespace`), never typed out here
    (tests/test_image_namespace_declarations.py). Parsed, not sourced, so no
    side effects; a changed function shape fails loud."""
    text = (ROOT / "scripts/lib-dist.sh").read_text()
    m = re.search(r"^release_image_namespace\(\)\s*\{\s*printf\s+'([^']+)';\s*\}", text, re.M)
    if not m:
        raise SystemExit("scripts/lib-dist.sh: release_image_namespace() not found in its one-line printf form")
    return m.group(1)


# Images this repo builds and ships itself: never a third-party source. The
# console image lives under the release namespace (the DHI mirror under it,
# `<ns>/dhi/...`, IS third-party and stays a pinned source).
FIRST_PARTY = (
    "pai-assistant/",
    "noomesh/",
    "noo-",
    release_image_namespace() + "/mesh-ui",
    "${NOO_IMAGE_PREFIX",
)

# Sources that cannot carry a digest, each with the reason. The guard test
# fails on any unpinned source not listed here, and on any entry here that no
# longer matches a real source. Key: (file, written reference).
UNPINNABLE: dict[tuple[str, str], str] = {
    ("docker/Dockerfile.airllm", "dhi.io/pytorch:2.10-cuda13.0-debian13-dev"):
        "TODO: dhi.io needs a credential to resolve a digest and this image is "
        "deliberately not mirrored (multi-GB), so no registry we can read holds it. "
        "Resolve it in the monthly refresh run (which logs in to dhi.io) and pin it.",
    (".github/hub-mirror.txt", "library/rust:1-bookworm"):
        "TODO (17a follow-up): a CI/dev toolchain image, not a shipped base. Consumers address "
        "the row by its text: four ci.yml jobs (`hub-mirror.py ref library/rust:1-bookworm` and the "
        "`CARGO_DOCKER_IMAGE:-rust:1-bookworm` fallbacks), scripts/cargo-docker.sh and "
        "tests/test_hub_mirror.py all change together with the row, and local dev images are keyed by "
        "the tag. A wide mechanical change that wants its own CI run.",
    (".github/hub-mirror.txt", "library/alpine:latest"):
        "the workspace-reclaim steps run `docker run alpine` against whatever image the "
        "runner already has (local image first); the tag is intentionally unversioned and "
        "a digest would make every runner pull a new image.",
}


class Source(NamedTuple):
    kind: str
    path: str          # repo-relative
    lineno: int        # 1-based
    written: str       # the reference as written, without its digest
    resolve: str       # what to ask a registry for (variables expanded)
    digest: str        # "sha256:..." or ""
    slot: tuple[int, int] | None   # (start, end) columns of the digest slot in the line


def _is_first_party(ref: str) -> bool:
    return ref.startswith(FIRST_PARTY)


def _tracked(root: Path) -> list[str]:
    r = subprocess.run(["git", "-C", str(root), "ls-files"], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.splitlines()
    return [str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and ".git" not in p.parts]


def _split(token: str) -> tuple[str, str]:
    m = re.fullmatch(r"(.*?)(?:@(" + DIGEST + r"))?", token)
    return m.group(1), m.group(2) or ""


def _expand_registry(ref: str) -> str:
    ref = re.sub(r"^\$\{HUB_MIRROR\}/", "docker.io/", ref)
    ref = re.sub(r"^\$\{DHI_REGISTRY\}/", "dhi.io/", ref)
    ref = re.sub(r"^\$\{NOO_BASE_REGISTRY:-[^}]*\}/", "dhi.io/", ref)
    return ref


def dockerfile_sources(path: str, text: str) -> list[Source]:
    args: dict[str, tuple[int, str, int]] = {}   # name -> (lineno, value, col)
    stages: set[str] = set()
    out: list[Source] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        m = re.match(r"\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)", line)
        if m:
            args.setdefault(m.group(1), (i, m.group(2), m.start(2)))
        m = re.match(r"(\s*FROM\s+(?:--\S+\s+)*)(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
        if not m:
            continue
        token, col, alias = m.group(2), m.end(1), m.group(3)
        if alias:
            stages.add(alias)
        if token in stages or token == "scratch" or token.split("@")[0] in stages:
            continue
        bare = re.fullmatch(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", token)
        if bare and bare.group(1) in args:
            ai, value, vcol = args[bare.group(1)]
            written, digest = _split(value)
            if _is_first_party(written):
                continue
            end = vcol + len(written)
            out.append(Source("dockerfile", path, ai, written, _expand_registry(written), digest,
                              (end, end + (len(value) - len(written)))))
            continue
        written, digest = _split(token)
        # Expand ARG defaults inside the reference (python:${PYTHON_VERSION}-slim).
        expanded = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}",
                          lambda v: args[v.group(1)][1] if v.group(1) in args and v.group(1)
                          not in ("HUB_MIRROR", "DHI_REGISTRY") else v.group(0), written)
        if _is_first_party(expanded):
            continue
        end = col + len(written)
        out.append(Source("dockerfile", path, i, written, _expand_registry(expanded), digest,
                          (end, end + (len(token) - len(written)))))
    return out


def mirror_sources(path: str, text: str) -> list[Source]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"\s*-\s*source:\s*(\S+)\s*$", line)
        if m:
            written, digest = _split(m.group(1))
            end = m.start(1) + len(written)
            out.append(Source("mirror", path, i, written, written, digest,
                              (end, end + len(m.group(1)) - len(written))))
    return out


def hub_mirror_sources(path: str, text: str) -> list[Source]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"(\S+)", line)
        written, digest = _split(m.group(1))
        end = len(written)
        out.append(Source("hub-mirror", path, i, written, "docker.io/" + written, digest,
                          (end, end + len(m.group(1)) - len(written))))
    return out


def compose_sources(path: str, text: str) -> list[Source]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"(\s*image:\s*)(\S+)\s*$", line)
        if not m:
            continue
        value = m.group(2)
        body = re.sub(r"^\$\{[A-Z][A-Z0-9_]*:-", "", value)   # an operator override wrapper
        if _is_first_party(body) or _is_first_party(value):
            continue
        h = HOOK.search(value)
        if h:
            name = value[: h.start()]
            if name.startswith("${NOO_BASE_REGISTRY:-"):
                name = _expand_registry(name)   # the DHI namespace, spelled dhi.io
            else:
                name = re.sub(r"^\$\{[A-Z][A-Z0-9_]*:-", "", name)   # an override wrapper
            off = m.start(2)   # h's columns are relative to the value, not the line
            slot = (off + (h.start(2) if h.group(2) else h.end() - 1),
                    off + (h.end(2) if h.group(2) else h.end() - 1))
            out.append(Source("compose", path, i, name, _expand_registry(name),
                              (h.group(2) or "")[1:], slot))
        else:
            written, digest = _split(value)
            out.append(Source("compose", path, i, written, _expand_registry(written), digest, None))
    return out


def workflow_sources(path: str, text: str) -> list[Source]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r'\s*FFMPEG_UPSTREAM:\s*"([^"]+)"', line)
        if m:
            written, digest = _split(m.group(1))
            end = m.start(1) + len(written)
            out.append(Source("workflow", path, i, written, written, digest,
                              (end, end + len(m.group(1)) - len(written))))
    return out


def collect(root: Path = ROOT) -> list[Source]:
    out: list[Source] = []
    for rel in sorted(_tracked(root)):
        if rel.startswith(("tests/", "docs/")) or not (root / rel).is_file():
            continue
        name = rel.rsplit("/", 1)[-1]
        if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
            out += dockerfile_sources(rel, (root / rel).read_text())
        elif re.fullmatch(r"docker-compose[^/]*\.yml", rel):
            out += compose_sources(rel, (root / rel).read_text())
        elif rel == ".github/workflows/mirror-images.yml":
            out += mirror_sources(rel, (root / rel).read_text())
        elif rel == ".github/hub-mirror.txt":
            out += hub_mirror_sources(rel, (root / rel).read_text())
        elif rel == ".github/workflows/images-release.yml":
            out += workflow_sources(rel, (root / rel).read_text())
    return out


def unpinned(sources: list[Source]) -> list[Source]:
    return [s for s in sources if not s.digest and (s.path, s.written) not in UNPINNABLE]


# ── resolution ──────────────────────────────────────────────────────────────

def resolve_digest(ref: str, via: dict[str, str] | None = None) -> str:
    """The registry's multi-arch INDEX digest for `ref` (never a per-arch manifest)."""
    for a, b in (via or {}).items():
        if ref.startswith(a + "/"):
            ref = b + ref[len(a):]
    err = ""
    for attempt in range(1, 5):
        r = subprocess.run(
            ["docker", "buildx", "imagetools", "inspect", ref, "--format", "{{json .Manifest.Digest}}"],
            capture_output=True, text=True, timeout=120)
        d = r.stdout.strip().strip('"')
        if r.returncode == 0 and re.fullmatch(DIGEST, d):
            return d
        err = (r.stderr or r.stdout).strip()
        if attempt < 4:
            time.sleep(5 * attempt)
    raise RuntimeError(f"{ref}: {err or 'no digest'}")


def refresh(root: Path, sources: list[Source], resolver, pin_missing: bool, new_only: bool = False):
    """Rewrite files. Returns (changes, unresolved): changes are (Source, old, new)."""
    cache: dict[str, str | Exception] = {}
    changes, unresolved, edits = [], [], {}
    for s in sources:
        if (s.path, s.written) in UNPINNABLE or (not s.digest and not pin_missing) or s.slot is None:
            if not s.digest and pin_missing and s.slot is None and (s.path, s.written) not in UNPINNABLE:
                unresolved.append((s, "no place to put a digest"))
            continue
        if new_only and s.digest:
            continue
        if s.resolve not in cache:
            try:
                cache[s.resolve] = resolver(s.resolve)
            except Exception as e:   # noqa: BLE001 - reported, never swallowed
                cache[s.resolve] = e
        new = cache[s.resolve]
        if isinstance(new, Exception):
            unresolved.append((s, str(new)))
            continue
        if new != s.digest:
            edits.setdefault(s.path, []).append((s, new))
            changes.append((s, s.digest, new))
    for rel, items in edits.items():
        p = root / rel
        lines = p.read_text().split("\n")
        for s, new in sorted(items, key=lambda x: (x[0].lineno, x[0].slot[0]), reverse=True):
            ln = lines[s.lineno - 1]
            lines[s.lineno - 1] = ln[: s.slot[0]] + "@" + new + ln[s.slot[1]:]
        p.write_text("\n".join(lines))
    return changes, unresolved


def report(changes, unresolved, today: str) -> str:
    out = [f"Digests re-resolved on {today}. Each new value is the tag's CURRENT multi-arch index digest.", ""]
    if changes:
        out += ["| source | file | old | new |", "|---|---|---|---|"]
        for s, old, new in changes:
            o = old[7:19] if old else "(floating)"
            out.append(f"| `{s.written}` | `{s.path}:{s.lineno}` | `{o}` | `{new[7:19]}` |")
    else:
        out.append("No digest moved.")
    if unresolved:
        out += ["", "UNRESOLVED (left as they were):", ""]
        out += [f"- `{s.written}` in `{s.path}:{s.lineno}`: {why}" for s, why in unresolved]
    out += ["", "A moved digest is a different base image. Rehearse a release candidate before it ships."]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None, resolver=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--pin", action="store_true")
    ap.add_argument("--new-only", action="store_true", help="with --pin: leave existing pins alone")
    ap.add_argument("--report", type=Path)
    ap.add_argument("--via", action="append", default=[], metavar="A=B")
    a = ap.parse_args(argv)
    sources = collect(a.root)
    if not sources:
        print("error: parsed zero image sources: the parser is broken", file=sys.stderr)
        return 2
    if a.check:
        bad = unpinned(sources)
        for s in bad:
            print(f"UNPINNED {s.kind} {s.path}:{s.lineno} {s.written}", file=sys.stderr)
        print(f"{len(sources)} sources, {len(bad)} unpinned")
        return 1 if bad else 0
    via = dict(v.split("=", 1) for v in a.via)
    resolver = resolver or (lambda ref: resolve_digest(ref, via))
    changes, unresolved = refresh(a.root, sources, resolver, a.pin, a.new_only)
    text = report(changes, unresolved, time.strftime("%Y-%m-%d", time.gmtime()))
    print(text)
    if a.report:
        a.report.write_text(text)
    return 3 if unresolved else 0


if __name__ == "__main__":
    sys.exit(main())
