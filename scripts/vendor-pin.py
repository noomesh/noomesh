#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Pin a vendor CLI by version AND sha256.

    vendor-pin.py <kind> <version> [--dl-dir DIR]
    vendor-pin.py --check [<kind> ...] [--dl-dir DIR]

The controller stages each foreign harness kind's vendor CLI to the nodes
(the node never touches the internet), so what it stages is pinned in
config/harness-kinds.json: per kind a `distribution` block with a version
and a sha256 per platform the fleet has (linux-x86_64, linux-aarch64,
macos-aarch64), or one `any` digest
for a platform-independent artefact.

Pin mode resolves the block's `source` URL template for every platform,
DOWNLOADS each artefact, computes its sha256, cross-checks it against the
checksums the vendor publishes (a GitHub release
SHA256SUMS file, Claude Code's release manifest.json), and rewrites the block in config/harness-kinds.json AND its
byte-equal copy node-agent-go/internal/reconcile/harness_kinds.json. The
block's source/names/format/entry/unpack already in the file win; RECIPES
below only seeds a block that does not exist yet. To change the artefact
shape (a vendor renamed its assets), edit the block in the file and re-pin.

--check re-downloads every pinned artefact and verifies its digest (and the
vendor cross-check) without writing; exit 1 on any mismatch. It needs the
internet and is not run in CI; tests/test_vendor_pins.py pins only the shape.

Downloads are untrusted data: this script only hashes them, it never
unpacks or executes them. They land in a fresh temporary directory, removed
afterwards, unless --dl-dir names one (kept, one subdirectory per name).

Exit 0 = pinned / verified; 1 = refused (unknown name, artefact missing,
digest or cross-check mismatch); 2 = usage.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path


def _repo_root() -> Path:
    """The tree the caller stands in (git follows $PWD), as docs-check.py does;
    script-relative only outside git or in an unrelated checkout."""
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        top = ""
    if top and (Path(top) / "scripts" / Path(__file__).name).is_file():
        return Path(top)
    return Path(__file__).resolve().parent.parent


REPO = _repo_root()
TABLE = REPO / "config/harness-kinds.json"
COPY = REPO / "node-agent-go/internal/reconcile/harness_kinds.json"

# The platforms the fleet has, in noomesh's facts naming (<os>-<arch>).
PLATFORMS = ["linux-x86_64", "linux-aarch64", "macos-aarch64"]

VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")

# Seeds for a block that is not in the file yet. Field order is the order
# written. `version`/`sha256` are filled by the pin.
RECIPES: dict[str, dict] = {
    # Native single-file executable per platform (Bun-compiled).
    "claude-code": {
        "format": "binary",
        "source": "https://downloads.claude.ai/claude-code-releases/{version}/{os}-{arch}/claude",
        "names": {"os": {"linux": "linux", "macos": "darwin"},
                  "arch": {"x86_64": "x64", "aarch64": "arm64"}},
        "entry": "claude",
        "unpack": "none",
    },
    # Native single-file executable per platform in a release tarball.
    "copilot": {
        "format": "tarball",
        "source": "https://github.com/github/copilot-cli/releases/download/v{version}/copilot-{os}-{arch}.tar.gz",
        "names": {"os": {"linux": "linux", "macos": "darwin"},
                  "arch": {"x86_64": "x64", "aarch64": "arm64"}},
        "entry": "copilot",
        "unpack": "tgz",
    },
    # The vendor's packaged layout: bin/codex plus its helpers (rg, bwrap).
    "codex": {
        "format": "tarball",
        "source": "https://github.com/openai/codex/releases/download/rust-v{version}/codex-package-{arch}-{os}.tar.gz",
        "names": {"os": {"linux": "unknown-linux-musl", "macos": "apple-darwin"},
                  "arch": {"x86_64": "x86_64", "aarch64": "aarch64"}},
        "entry": "bin/codex",
        "unpack": "tgz",
    },
}

# Where each vendor publishes the checksums to cross-check against. A
# `sums` file is `<hex>  <filename>` lines keyed by the artefact's basename;
# `claude-manifest` is manifest.json's platforms.<os>-<arch>.checksum.
CROSSCHECK: dict[str, tuple[str, str]] = {
    "copilot": ("sums", "https://github.com/github/copilot-cli/releases/download/v{version}/SHA256SUMS.txt"),
    "codex": ("sums", "https://github.com/openai/codex/releases/download/rust-v{version}/codex-package_SHA256SUMS"),
    "claude-code": ("claude-manifest", "https://downloads.claude.ai/claude-code-releases/{version}/manifest.json"),
}

UA = {"User-Agent": "noomesh-vendor-pin/1"}


class Refused(Exception):
    pass


def _get(url: str) -> bytes:
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        raise Refused(f"{url}: HTTP {e.code}") from None
    except urllib.error.URLError as e:
        raise Refused(f"{url}: {e.reason}") from None


def _download(url: str, dest: Path) -> tuple[int, str]:
    """Stream url to dest; (size, sha256 hex)."""
    h256, size = hashlib.sha256(), 0
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120) as r, \
                open(dest, "wb") as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
                h256.update(chunk)
                size += len(chunk)
    except urllib.error.HTTPError as e:
        raise Refused(f"artefact missing: {url}: HTTP {e.code}") from None
    except urllib.error.URLError as e:
        raise Refused(f"artefact unreachable: {url}: {e.reason}") from None
    if size == 0:
        raise Refused(f"artefact empty: {url}")
    return size, h256.hexdigest()


def _fill(template: str, version: str, platform: str | None, names: dict | None) -> str:
    out = template.replace("{version}", version)
    if platform is None:
        if "{os}" in out or "{arch}" in out:
            raise Refused(f"source {template!r} names {{os}}/{{arch}} but the artefact is keyed 'any'")
        return out
    os_, arch = platform.split("-", 1)
    if names:
        try:
            os_, arch = names["os"][os_], names["arch"][arch]
        except KeyError as e:
            raise Refused(f"names has no mapping for {e.args[0]!r} (platform {platform})") from None
    return out.replace("{os}", os_).replace("{arch}", arch)


def _vendor_platform(platform: str, names: dict | None) -> str:
    os_, arch = platform.split("-", 1)
    if names:
        os_, arch = names["os"][os_], names["arch"][arch]
    return f"{os_}-{arch}"


class CrossCheck:
    """The vendor's published digests for one name at one version."""

    def __init__(self, name: str, version: str):
        self.name, self.version = name, version
        self._sums: dict[str, str] | None = None
        self._manifest: dict | None = None
        spec = CROSSCHECK.get(name)
        self.kind, self.url = (spec[0], spec[1].replace("{version}", version)) if spec else (None, None)

    def expected(self, url: str, platform: str | None, names: dict | None) -> tuple[str, str] | None:
        """(sha256 hex, where it came from), or None when nothing is published."""
        if self.kind == "sums":
            if self._sums is None:
                self._sums = {}
                for line in _get(self.url).decode("utf-8", "replace").splitlines():
                    parts = line.split()
                    if len(parts) == 2 and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
                        self._sums[parts[1].lstrip("*")] = parts[0]
            base = url.rsplit("/", 1)[1]
            if base not in self._sums:
                raise Refused(f"{self.url} lists no digest for {base}")
            return self._sums[base], self.url
        if self.kind == "claude-manifest":
            if self._manifest is None:
                self._manifest = json.loads(_get(self.url))
                if self._manifest.get("version") != self.version:
                    raise Refused(f"{self.url} is for version {self._manifest.get('version')!r}, not {self.version}")
            vp = _vendor_platform(platform, names) if platform else None
            row = (self._manifest.get("platforms") or {}).get(vp)
            if not row or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("checksum", ""))):
                raise Refused(f"{self.url} has no checksum for platform {vp}")
            return row["checksum"], self.url
        return None


def _resolve(name: str, version: str, block: dict, dl: Path) -> dict[str, str]:
    """Download every artefact of block at version; {sha256 key: hex}."""
    names = block.get("names")
    keys = list((block.get("sha256") or {}).keys())
    any_ = keys == ["any"]
    platforms: list[str | None] = [None] if any_ else list(PLATFORMS)
    cc = CrossCheck(name, version)
    if cc.kind is None:
        print(f"  WARNING {name}: no vendor checksum to cross-check against; the pin is trust-on-first-use")
    out: dict[str, str] = {}
    sub = dl / name.replace(":", "-")
    sub.mkdir(parents=True, exist_ok=True)
    for p in platforms:
        url = _fill(block["source"], version, p, names)
        key = p or "any"
        dest = sub / f"{key}--{url.rsplit('/', 1)[1]}"
        size, sha = _download(url, dest)
        source = "none"
        exp = cc.expected(url, p, names)
        if exp is not None:
            if exp[0] != sha:
                raise Refused(f"checksum mismatch for {url}:\n    downloaded {sha}\n    {exp[1]} says {exp[0]}")
            source = exp[1]
        print(f"  {key:14} {url}\n  {'':14} {size} bytes  sha256 {sha}  cross-check: {source}")
        out[key] = sha
    return out


def _load() -> tuple[dict, str]:
    a, b = TABLE.read_bytes(), COPY.read_bytes()
    if a != b:
        raise Refused(f"{COPY.relative_to(REPO)} differs from {TABLE.relative_to(REPO)}: "
                      "copy the shipped file over the embedded one first")
    text = a.decode("utf-8")
    doc = json.loads(text)
    if _dump(doc) != text:
        raise Refused(f"{TABLE.relative_to(REPO)} is not in the canonical indent-2 layout; "
                      "this script would reformat it")
    return doc, text


def _dump(doc: dict) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _find(doc: dict, name: str) -> tuple[dict | None, dict | None]:
    """(the block, the kind row) for name; refuse an unknown name."""
    for k in doc["kinds"]:
        if k["kind"] == name:
            if k.get("cli") is None:
                raise Refused(f"kind {name!r} has no vendor CLI, so nothing to pin")
            return k.get("distribution"), k
    raise Refused(f"unknown kind {name!r} (known: {', '.join(k['kind'] for k in doc['kinds'])})")


def _ordered(block: dict) -> dict:
    order = ["format", "source", "names", "version", "sha256", "entry", "unpack"]
    out = {k: block[k] for k in order if k in block}
    out.update({k: v for k, v in block.items() if k not in out})
    return out


def pin(name: str, version: str, dl: Path) -> None:
    if not VERSION_RE.match(version):
        raise Refused(f"version {version!r} is not x.y.z")
    doc, before = _load()
    block, row = _find(doc, name)
    block = dict(block) if block else dict(RECIPES.get(name) or {})
    if not block.get("source"):
        raise Refused(f"{name} has no distribution in the file and no seed recipe here: "
                      "write its format/source/names/entry/unpack into the file, then re-run")
    print(f"pinning {name} {version}")
    block["version"] = version
    block["sha256"] = _resolve(name, version, block, dl)
    row["distribution"] = _ordered(block)
    # Every kind carries the key: `noo` (no CLI) null, a foreign kind not
    # pinned yet null until it is.
    for k in doc["kinds"]:
        k.setdefault("distribution", None)
    after = _dump(doc)
    if after == before:
        print("unchanged")
        return
    TABLE.write_text(after, encoding="utf-8")
    COPY.write_text(after, encoding="utf-8")
    print(f"wrote {TABLE.relative_to(REPO)} and {COPY.relative_to(REPO)}")


def check(names: list[str], dl: Path) -> int:
    doc, _ = _load()
    if not names:
        names = [k["kind"] for k in doc["kinds"] if k.get("distribution")]
    bad = 0
    for name in names:
        try:
            block, _row = _find(doc, name)
            if not block:
                raise Refused(f"{name} has no pinned distribution")
            print(f"checking {name} {block['version']}")
            got = _resolve(name, block["version"], block, dl)
            for key, want in block["sha256"].items():
                if got.get(key) != want:
                    raise Refused(f"{name} {key}: pinned {want}\n    downloaded {got.get(key)}")
            if set(got) != set(block["sha256"]):
                raise Refused(f"{name}: pinned platforms {sorted(block['sha256'])} != {sorted(got)}")
            print("  ok")
        except Refused as e:
            print(f"REFUSED {name}: {e}", file=sys.stderr)
            bad += 1
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    args, dl_arg, do_check = [], None, False
    it = iter(argv)
    for a in it:
        if a == "--check":
            do_check = True
        elif a == "--dl-dir":
            dl_arg = next(it, None)
            if dl_arg is None:
                print("--dl-dir needs a directory", file=sys.stderr)
                return 2
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        elif a.startswith("-"):
            print(f"unknown option {a}", file=sys.stderr)
            return 2
        else:
            args.append(a)
    if not do_check and len(args) != 2:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    tmp = None
    if dl_arg:
        dl = Path(dl_arg)
        dl.mkdir(parents=True, exist_ok=True)
    else:
        tmp = dl = Path(tempfile.mkdtemp(prefix="vendor-pin-"))
    try:
        if do_check:
            return check(args, dl)
        pin(args[0], args[1], dl)
        return 0
    except Refused as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 1
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
