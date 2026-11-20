#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The harrier embedder artifact, pinned by digest into the signed stack lock.

harrier (the default embedder) ships as an OCI image of three files
(publish-harrier.yml). Until 0.6.29 every install pulled it by the MUTABLE tag
`harrier:v1` and checked it with the `harrier.sha256` that travels inside the
same image, which proves nothing about the tag. The release now pins the image
by the digest in scripts/harrier-artifact.json, and every pull is
`<prefix>/harrier@sha256:...` from the lock's row.

  ref    --registry R --owner O      print <R>/<O>/harrier@<digest> (the release-line check)
  rows   --registry R --owner O --out DIR
         pull that exact digest, check every file against its harrier.sha256 and
         that file against the pinned gguf_sha256, then write DIR/harrier
         (`harrier@<digest>`) and DIR/harrier-gguf (`# harrier-gguf-sha256 <hex>`)
         for the lock job. Never resolves a tag.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = ROOT / "scripts" / "harrier-artifact.json"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
HEX = re.compile(r"[0-9a-f]{64}")
ATTEMPTS = 4


class PinError(Exception):
    pass


def load(path: Path = PIN) -> dict:
    pin = json.loads(path.read_text())
    if pin.get("image") != "harrier":
        raise PinError(f"{path}: image must be harrier, not {pin.get('image')!r}")
    if not DIGEST.fullmatch(str(pin.get("digest", ""))):
        raise PinError(f"{path}: digest must be sha256:<64 lowercase hex>, not {pin.get('digest')!r}")
    if not HEX.fullmatch(str(pin.get("gguf_sha256", ""))):
        raise PinError(f"{path}: gguf_sha256 must be 64 lowercase hex, not {pin.get('gguf_sha256')!r}")
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.gguf", str(pin.get("gguf", ""))):
        raise PinError(f"{path}: gguf must be a bare .gguf file name, not {pin.get('gguf')!r}")
    return pin


def ref(pin: dict, registry: str, owner: str) -> str:
    """The ONE reference anything here pulls: by digest, never a tag."""
    return f"{registry.rstrip('/')}/{owner.strip('/')}/harrier@{pin['digest']}"


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def fetch(reference: str, dest: Path) -> None:
    """Pull `reference` (a digest ref) and copy its /harrier/ files into dest."""
    if "@sha256:" not in reference:
        raise PinError(f"refusing to pull {reference}: not a digest reference")
    err = ""
    for _ in range(ATTEMPTS):
        r = _run(["docker", "pull", "-q", reference], timeout=900)
        if r.returncode == 0:
            break
        err = (r.stderr or r.stdout).strip()
    else:
        raise PinError(f"could not pull {reference}: {err}")
    name = "harrier-pin-src"
    _run(["docker", "rm", "-f", name])
    try:
        for cmd in (["docker", "create", "--name", name, reference], ["docker", "cp", f"{name}:/harrier/.", str(dest)]):
            r = _run(cmd, timeout=300)
            if r.returncode != 0:
                raise PinError(f"{' '.join(cmd)}: {(r.stderr or r.stdout).strip()}")
    finally:
        _run(["docker", "rm", "-f", name])


def check_files(pin: dict, d: Path) -> None:
    """Every file harrier.sha256 names matches it, and it names the pinned GGUF sha."""
    sums = d / "harrier.sha256"
    if not sums.is_file():
        raise PinError("the image carries no harrier.sha256")
    named = {}
    for line in sums.read_text().splitlines():
        parts = line.split()
        if len(parts) == 2:
            named[parts[1].lstrip("*")] = parts[0].lower()
    if named.get(pin["gguf"]) != pin["gguf_sha256"]:
        raise PinError(f"the image's harrier.sha256 names {pin['gguf']} as {named.get(pin['gguf'])!r}, "
                       f"but scripts/harrier-artifact.json pins {pin['gguf_sha256']}")
    r = _run(["sha256sum", "-c", "harrier.sha256"], cwd=d)
    if r.returncode != 0:
        raise PinError(f"sha256sum -c harrier.sha256 failed in the pinned image: {(r.stdout + r.stderr).strip()}")


def rows(pin: dict, out: Path) -> list[str]:
    out.mkdir(parents=True, exist_ok=True)
    lines = [f"harrier@{pin['digest']}", f"# harrier-gguf-sha256 {pin['gguf_sha256']}"]
    (out / "harrier").write_text(lines[0] + "\n")
    (out / "harrier-gguf").write_text(lines[1] + "\n")
    return lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mode", choices=("ref", "rows"))
    ap.add_argument("--registry", required=True)
    ap.add_argument("--owner", required=True)
    ap.add_argument("--out", type=Path, help="directory for the lock row files (rows)")
    ap.add_argument("--pin", type=Path, default=PIN)
    a = ap.parse_args(argv)
    try:
        pin = load(a.pin)
        reference = ref(pin, a.registry, a.owner)
        if a.mode == "ref":
            print(reference)
            return 0
        if a.out is None:
            ap.error("rows needs --out")
        with tempfile.TemporaryDirectory() as tmp:
            fetch(reference, Path(tmp))
            check_files(pin, Path(tmp))
        for line in rows(pin, a.out):
            print(f"{line}   ({reference})")
        return 0
    except PinError as e:
        print(f"::error::harrier artifact pin: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
