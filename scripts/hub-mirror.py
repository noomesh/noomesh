#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Mirror the Docker Hub images CI uses into GHCR, and pick mirror-or-Hub at use.

Every self-hosted runner sits behind one home IP and Docker Hub limits
anonymous pulls per IP: rust-gateway, noo-cli and
standalone-smoke jobs failed repeatedly on "toomanyrequests". The
inventory is `.github/hub-mirror.txt` (one Hub path per row; official images
under `library/`). An image `<path>:<tag>` is mirrored to
`<prefix>/<path>:<tag>`, so mirror and Hub differ by ONE prefix: the mirror
(`$HUB_MIRROR`, default `ghcr.io/<owner>/mirror`) or `docker.io`.

  sync      (mirror-hub-images.yml, weekly + dispatch) For each row: read the
            source's index digest, newest `created` and version annotation,
            and the same for the current mirror. Equal digests: unchanged.
            Absent mirror: copy. Changed: copy, and print old -> new. A change
            that LOOKS LIKE A DOWNGRADE (the source is older than what the
            mirror holds, or its version annotation sorts lower) is NOT
            copied and fails the run, printing both sides, so nobody's base
            image silently goes back in time. A digest-pinned row must copy
            to exactly that digest. Copies use `docker buildx imagetools
            create` (registry to registry, every platform, no local pull).
            Writes a `<row> <source digest> <created>` record to --record and
            the job summary.

  prefix    (CI and image builds) Print the prefix to use for the given rows:
            the mirror when every one of them is present there, else
            `docker.io` with a ::warning:: naming what is missing. Never fails:
            a stale or missing mirror must cost a Hub pull, not a red build.

  ref       Same decision for one row, printing the full image reference.

Kill switch, no PR: `gh variable set HUB_MIRROR_OFF --body 1` (the workflows
pass it as HUB_MIRROR_OFF) makes `prefix`/`ref` answer docker.io.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / ".github/hub-mirror.txt"
HUB = "docker.io"


class MirrorError(Exception):
    pass


ATTEMPTS = 5
RATE_LIMITED = re.compile(r"429|toomanyrequests|too many requests", re.I)


def _seconds(env: str, default: float) -> float:
    try:
        return max(0.0, float(os.environ.get(env, default)))
    except ValueError:
        return default


def _run(cmd: list[str], timeout: int) -> subprocess.CompletedProcess:
    """Run a registry command, retrying a rate-limit answer (HTTP 429) up to
    ATTEMPTS times. The wait grows with the attempt (HUB_MIRROR_BACKOFF
    seconds per attempt, default 20) and honours a `Retry-After: <seconds>` the
    registry printed. Any other failure is returned at once."""
    for attempt in range(1, ATTEMPTS + 1):
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0 or attempt == ATTEMPTS or not RATE_LIMITED.search(r.stderr):
            return r
        m = re.search(r"retry-after\D{0,3}(\d+)", r.stderr, re.I)
        wait = max(_seconds("HUB_MIRROR_BACKOFF", 20) * attempt, float(m.group(1)) if m else 0.0)
        print(f"::warning::hub-mirror: rate limited (attempt {attempt}/{ATTEMPTS}); retrying in {wait:.0f}s",
              file=sys.stderr)
        time.sleep(wait)
    return r  # unreachable


def rows(path: Path = INVENTORY) -> list[str]:
    out = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line.split()[0])
    return out


def split(row: str) -> tuple[str, str, str]:
    """(path, tag, digest or '') of `path:tag[@sha256:…]`."""
    m = re.fullmatch(r"([a-z0-9][a-z0-9._/-]*):([A-Za-z0-9._-]+)(?:@(sha256:[0-9a-f]{64}))?", row)
    if not m or "/" not in m.group(1):
        raise MirrorError(f"inventory row {row!r} is not <namespace>/<name>:<tag>[@sha256:…]")
    return m.group(1), m.group(2), m.group(3) or ""


def mirror_ref(prefix: str, row: str) -> str:
    path, tag, _ = split(row)
    return f"{prefix.rstrip('/')}/{path}:{tag}"


def use_ref(prefix: str, row: str) -> str:
    """The reference a consumer pulls: <prefix>/<path>:<tag>[@digest]."""
    path, tag, digest = split(row)
    return f"{prefix.rstrip('/')}/{path}:{tag}" + (f"@{digest}" if digest else "")


def source_ref(row: str) -> str:
    path, tag, digest = split(row)
    return f"{HUB}/{path}:{tag}" + (f"@{digest}" if digest else "")


def default_prefix() -> str:
    explicit = os.environ.get("HUB_MIRROR", "").strip()
    if explicit:
        return explicit
    owner = os.environ.get("GITHUB_REPOSITORY_OWNER", "").strip()
    if not owner:
        raise MirrorError("no HUB_MIRROR and no GITHUB_REPOSITORY_OWNER to derive ghcr.io/<owner>/mirror from")
    return f"ghcr.io/{owner}/mirror"


def _inspect(ref: str, fmt: str) -> object | None:
    r = _run(["docker", "buildx", "imagetools", "inspect", ref, "--format", fmt], 180)
    if r.returncode != 0:
        err = r.stderr.strip()
        if re.search(r"not found|manifest unknown|MANIFEST_UNKNOWN|NAME_UNKNOWN", err, re.I):
            return None
        raise MirrorError(f"inspect {ref}: {err[-300:]}")
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError as e:
        raise MirrorError(f"inspect {ref}: unparseable output ({e})") from e


def describe(ref: str) -> dict | None:
    """{digest, created, version} of an image, or None when it does not exist."""
    man = _inspect(ref, "{{json .Manifest}}")
    if man is None:
        return None
    img = _inspect(ref, "{{json .Image}}") or {}
    configs = [img] if "created" in img or "config" in img else list(img.values())
    created = max((c.get("created") or "" for c in configs if isinstance(c, dict)), default="")
    versions = set()
    for m in [man, *(man.get("manifests") or [])]:
        v = (m.get("annotations") or {}).get("org.opencontainers.image.version")
        if v:
            versions.add(v)
    for c in configs:
        v = ((c.get("config") or {}).get("Labels") or {}).get("org.opencontainers.image.version") \
            if isinstance(c, dict) else None
        if v:
            versions.add(v)
    return {"digest": man.get("digest", ""), "created": created,
            "version": sorted(versions)[-1] if versions else ""}


def _vkey(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v))


def looks_like_downgrade(old: dict, new: dict) -> str:
    """Why `new` looks older than `old`, or '' when it does not."""
    if old["version"] and new["version"] and _vkey(new["version"]) < _vkey(old["version"]):
        return f"version {old['version']} -> {new['version']}"
    if old["created"] and new["created"] and new["created"] < old["created"]:
        return f"created {old['created']} -> {new['created']}"
    return ""


def sync(prefix: str, inventory: list[str], record: Path | None) -> int:
    failures, lines = [], []
    for n, row in enumerate(inventory):
        if n:
            # Space the images out: the registry's per-account allowance is
            # spent by bursts, not by the total.
            time.sleep(_seconds("HUB_MIRROR_SPACING", 5))
        src, dst = source_ref(row), mirror_ref(prefix, row)
        _, _, pinned = split(row)
        try:
            new = describe(src)
            if new is None:
                raise MirrorError(f"source {src} does not exist")
            if pinned and new["digest"] != pinned:
                raise MirrorError(f"{src} resolved to {new['digest']}, not the pinned digest")
            old = describe(dst)
            if old and old["digest"] == new["digest"]:
                print(f"unchanged  {row}  {new['digest']}")
            else:
                if old:
                    why = looks_like_downgrade(old, new)
                    if why:
                        raise MirrorError(
                            f"DOWNGRADE? {row}: the mirror holds {old['digest']} (created "
                            f"{old['created'] or '?'}, version {old['version'] or '?'}); the source "
                            f"now serves {new['digest']} (created {new['created'] or '?'}, version "
                            f"{new['version'] or '?'}) — {why}. NOT copied. If the upstream really "
                            f"rolled the tag back, delete the mirror tag and re-run")
                    print(f"CHANGED    {row}  {old['digest']} -> {new['digest']}  "
                          f"(created {old['created'] or '?'} -> {new['created'] or '?'}, "
                          f"version {old['version'] or '?'} -> {new['version'] or '?'})")
                else:
                    print(f"new        {row}  {new['digest']}")
                r = _run(["docker", "buildx", "imagetools", "create", "--tag", dst, src], 900)
                if r.returncode != 0:
                    raise MirrorError(f"copy {src} -> {dst}: {r.stderr.strip()[-300:]}")
                got = describe(dst)
                if not got or got["digest"] != new["digest"]:
                    raise MirrorError(f"{dst} is {got and got['digest']} after the copy, "
                                      f"not the source's {new['digest']}")
            lines.append(f"{row} {new['digest']} {new['created'] or '-'}")
        except (MirrorError, subprocess.TimeoutExpired) as e:
            print(f"::error::hub-mirror: {e}")
            failures.append(row)
    if record:
        record.write_text("".join(f"{ln}\n" for ln in lines))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(f"### Docker Hub mirror -> {prefix}\n\n```\n" + "\n".join(lines) + "\n```\n")
            if failures:
                f.write("\n**Failed:** " + ", ".join(failures) + "\n")
    return 1 if failures else 0


def dockerfile_rows(path: Path) -> list[str]:
    """Inventory rows a Dockerfile pulls through `${HUB_MIRROR}/…` FROMs, with
    its own ARG defaults substituted (`python:${PYTHON_VERSION}-slim`)."""
    args, out = {}, []
    for line in path.read_text().splitlines():
        m = re.match(r"\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)", line)
        if m:
            args.setdefault(m.group(1), m.group(2))
        m = re.match(r"\s*FROM\s+(?:--\S+\s+)*\$\{HUB_MIRROR\}/(\S+)", line)
        if m:
            ref = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", lambda v: args.get(v.group(1), v.group(0)),
                         m.group(1))
            if "${" in ref:
                raise MirrorError(f"{path}: cannot resolve {m.group(1)!r} from its ARG defaults")
            out.append(ref)
    return out


def present(prefix: str, row: str) -> bool:
    try:
        return describe(mirror_ref(prefix, row)) is not None
    except (MirrorError, subprocess.TimeoutExpired, OSError):
        return False


def choose_prefix(wanted: list[str]) -> str:
    if os.environ.get("HUB_MIRROR_OFF", "").strip() not in ("", "0", "false"):
        print("::warning::hub-mirror: HUB_MIRROR_OFF is set — pulling from Docker Hub", file=sys.stderr)
        return HUB
    try:
        prefix = default_prefix()
        missing = [w for w in wanted if not present(prefix, w)]
    except MirrorError as e:
        print(f"::warning::hub-mirror: {e} — falling back to Docker Hub", file=sys.stderr)
        return HUB
    if missing:
        print(f"::warning::hub-mirror: {', '.join(missing)} not in the mirror {prefix} (stale, "
              "missing, or this job cannot read it) — falling back to Docker Hub, which is rate "
              "limited per IP. Run the `mirror hub images` workflow.", file=sys.stderr)
        return HUB
    return prefix


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sync")
    s.add_argument("--record", type=Path)
    s.add_argument("--inventory", type=Path, default=INVENTORY)
    p = sub.add_parser("prefix")
    p.add_argument("rows", nargs="+")
    r = sub.add_parser("ref")
    r.add_argument("row")
    d = sub.add_parser("dockerfile", help="prefix for the ${HUB_MIRROR}/ FROMs of a Dockerfile")
    d.add_argument("path", type=Path)
    a = ap.parse_args(argv)
    if a.cmd == "dockerfile":
        try:
            wanted = dockerfile_rows(a.path)
        except (MirrorError, OSError) as e:
            print(f"::warning::hub-mirror: {e} — falling back to Docker Hub", file=sys.stderr)
            print(HUB)
            return 0
        a.cmd, a.rows = "prefix", wanted
        if not wanted:
            # Nothing pulled from Hub: the value is unused; keep it the mirror.
            try:
                print(default_prefix())
            except MirrorError:
                print(HUB)
            return 0
    if a.cmd == "sync":
        try:
            prefix = default_prefix()
            inv = rows(a.inventory)
            for row in inv:
                split(row)
        except MirrorError as e:
            print(f"::error::hub-mirror: {e}")
            return 1
        return sync(prefix, inv, a.record)
    known = set(rows())
    asked = a.rows if a.cmd == "prefix" else [a.row]
    unknown = [w for w in asked if w not in known]
    if unknown:
        # A row nobody mirrors can never be in the mirror: say so, use Hub.
        print(f"::warning::hub-mirror: {', '.join(unknown)} is not in .github/hub-mirror.txt",
              file=sys.stderr)
        prefix = HUB
    else:
        prefix = choose_prefix(asked)
    print(prefix if a.cmd == "prefix" else use_ref(prefix, a.row))
    return 0


if __name__ == "__main__":
    sys.exit(main())
