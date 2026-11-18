#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every release vouches for its PREVIOUS FINAL (i908).

A node accepts root code from the release its controller staged and from the
final before it (one step back). So each release's signed lists also carry
the previous final's root-run payloads, derived here by digest from that
final's OWN signed lists, never rebuilt:

    prev-final --this V          tags on stdin (X.Y.Z, one per line): the highest
                                 final below V's X.Y.Z, or nothing
    sums --prev P --dir D        D holds P's sha256sums.txt + .sig, P's Linux
                                 CLI binaries and noo-apply.sh / noo-fetch.sh
                                 as P's tag has them. Verifies the signature,
                                 each CLI binary against P's list, and that
                                 each embeds exactly those two scripts; prints
                                 `<sha>  <asset>@v<P>` rows for this release's
                                 sha256sums.txt
    lock --prev P --dir D        D holds stack-vP.lock + .sig. Verifies the
                                 signature and the lock's own `# stack` tag;
                                 prints the node-agent image digest it pins

The trusted keys are read from noo-cli/src/release_sig.rs (`--keys-from`),
with the repository's stdlib-only verifier. Exit 1, saying why, on any doubt.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FINAL = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
LINUX_CLI = re.compile(r"noo-[a-z0-9_]+-unknown-linux-(gnu|musl)")
# The previous final's rows copied as they are: hostd and the harness
# (gateway) for Linux and macOS, the macOS CLI and node agent.
COPIED = re.compile(r"noo-(hostd|gateway)-[a-z0-9_]+-(unknown-linux-(gnu|musl)|apple-darwin)"
                    r"|noo-[a-z0-9_]+-apple-darwin|noo-node-agent-[a-z0-9_]+-apple-darwin")


def _verifier():
    spec = importlib.util.spec_from_file_location("vrs", REPO / "scripts/verify-release-signature.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def die(msg: str) -> None:
    print(f"release-vouch-previous: {msg}", file=sys.stderr)
    sys.exit(1)


def key(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def verified(path: Path, keys_from: str) -> bytes:
    v = _verifier()
    data = path.read_bytes()
    sig = Path(f"{path}.sig").read_text().strip()
    if not sig.startswith(v.SIG_PREFIX):
        die(f"{path.name}.sig is not a release signature")
    body = sig[len(v.SIG_PREFIX):]
    raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    for k in v.keys_from_source(keys_from):
        if v.ed25519_verify(bytes.fromhex(k), raw, data):
            return data
    die(f"{path.name} does not verify against any release key in {keys_from}")
    return b""


def rows(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            out.append((parts[0].lower(), parts[1].lstrip("*").rsplit("/", 1)[-1]))
    return out


def cmd_prev_final(this: str) -> None:
    base = this.split("-rc.", 1)[0]
    if not FINAL.fullmatch(base):
        die(f"--this {this} is not X.Y.Z[-rc.N]")
    tags = {t.strip() for t in sys.stdin if FINAL.fullmatch(t.strip())}
    older = sorted((t for t in tags if key(t) < key(base)), key=key)
    if older:
        print(older[-1])


def cmd_sums(prev: str, d: Path, keys_from: str) -> None:
    if not FINAL.fullmatch(prev):
        die(f"--prev {prev} is not a final")
    listed = rows(verified(d / "sha256sums.txt", keys_from).decode())
    by_name = {n: s for s, n in listed}
    want = hashlib.sha256(f"{prev}\n".encode()).hexdigest()
    if by_name.get("noo-release-version") != want:
        die(f"the signed sha256sums.txt is not release {prev}'s (its noo-release-version row)")
    scripts = {n: (d / n).read_bytes() for n in ("noo-apply.sh", "noo-fetch.sh")}
    clis = [n for n in by_name if LINUX_CLI.fullmatch(n) and not n.startswith(("noo-hostd-", "noo-gateway-", "noo-node-agent-"))]
    if not clis:
        die(f"release {prev} lists no Linux CLI binary to prove the scripts against")
    for n in sorted(clis):
        b = (d / n).read_bytes()
        if hashlib.sha256(b).hexdigest() != by_name[n]:
            die(f"{n} as downloaded is not the one release {prev} signed")
        for s, body in scripts.items():
            if body not in b:
                die(f"{n} of release {prev} does not embed scripts/{s} at noo-cli-v{prev} byte for byte")
    out = [f"{hashlib.sha256(body).hexdigest()}  {n}@v{prev}" for n, body in scripts.items()]
    out += [f"{s}  {n}@v{prev}" for s, n in listed if COPIED.fullmatch(n)]
    print("\n".join(out))


def cmd_lock(prev: str, d: Path, keys_from: str) -> None:
    if not FINAL.fullmatch(prev):
        die(f"--prev {prev} is not a final")
    text = verified(d / f"stack-v{prev}.lock", keys_from).decode()
    named = {l[len("# stack "):].strip().removeprefix("stack-").removeprefix("v") for l in text.splitlines() if l.startswith("# stack ")}
    if named != {prev}:
        die(f"stack-v{prev}.lock is signed for {sorted(named) or 'no tag'}, not {prev}")
    digests = [l.split("@", 1)[1] for l in text.splitlines() if l.startswith("node-agent@sha256:")]
    if len(digests) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", digests[0]):
        die(f"stack-v{prev}.lock pins no single node-agent digest")
    print(digests[0])


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prev-final"); p.add_argument("--this", required=True)
    for name in ("sums", "lock"):
        p = sub.add_parser(name)
        p.add_argument("--prev", required=True)
        p.add_argument("--dir", required=True, type=Path)
        p.add_argument("--keys-from", default=str(REPO / "noo-cli/src/release_sig.rs"))
    a = ap.parse_args()
    if a.cmd == "prev-final":
        cmd_prev_final(a.this)
    elif a.cmd == "sums":
        cmd_sums(a.prev, a.dir, a.keys_from)
    else:
        cmd_lock(a.prev, a.dir, a.keys_from)


if __name__ == "__main__":
    main()
