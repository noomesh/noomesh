#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Infra images built once a day, outside the release (noomesh-internal i567).

The infra images (llama-server compiled from source, the hardened Ollama,
postgres + pgvector, the voice servers, the stunnel sidecar, the GPU
exporter) carry no noomesh source and change a few times a quarter. The
release rebuilt them for every new version anyway: llamacpp's from-source
arm64 compile under QEMU is ~60 min of every rc.1. They are built here
instead, daily (infra-staged.yml), scanned, and staged as `<image>:staged`;
the release re-tags the staged copy when its fingerprint matches the release
commit.

TODAY'S BASES (i604). Every FROM is pinned by digest in git, so a rebuild
alone never takes a distro fix. The daily job resolves each pinned FROM tag at
its SOURCE registry (BASE_SOURCES) to the digest it points at now
(resolve-bases, refusing one older than the git pin or the current :staged's),
rewrites the Dockerfile onto it (rebase-dockerfile), fingerprints the
Dockerfile AS BUILT, and records the digests in the BASES_LABEL. The release
recomputes the fingerprint from git plus that label (release-retag-plan.py
apply_staged); a copy without the label was built on the git pins.

  matrix              JSON `include` list for the daily set, read from the
                      images-release.yml matrix, so the daily build uses the
                      release's exact dockerfile/context/platforms/args.
  fingerprint IMAGE [--bases LABEL]
                      the content fingerprint of IMAGE's build inputs at this
                      checkout, built on LABEL's bases (default: the git
                      pins); exit 3 (and nothing on stdout) when it cannot
                      be computed, which means "never reuse, build".
  resolve-bases IMAGE [--staged-label LABEL]
                      the BASES_LABEL value for IMAGE's FROM tags as
                      published now; exit 3 on a base that moved backwards.
  rebase-dockerfile IMAGE --bases LABEL
                      rewrite IMAGE's Dockerfile in place onto LABEL's bases.
  new-findings        the fixable HIGH/CRITICAL (vulnerability, package) pairs
                      in --new Trivy JSON reports that the --old reports (the
                      current :staged) do not have. Exit 1 when there is one:
                      the staged tag must not move.

THE FINGERPRINT is sha256 over canonical JSON of: FINGERPRINT_SCHEMA; the
image's matrix entry (dockerfile, context, platforms, extra_args); the sha256
of every tracked file matched by the image's `inputs` in
scripts/release-image-inputs.json (the table tests/test_release_image_inputs.py
keeps complete) plus .dockerignore; and every FROM line's image reference.
the text of the release's own build step (images-release.yml "Build + push"),
so a change to how the release builds changes every fingerprint. Pinned
upstream refs and tarball hashes are ARG defaults in the Dockerfile, so its
bytes cover them. NO fingerprint (so: build, never reuse) when a FROM is
not pinned by digest, a COPY/ADD source cannot be resolved, or an input glob
matches no file. When unsure whether something is an input, it is one.

Bump FINGERPRINT_SCHEMA when the fingerprint's own recipe changes.
infra-staged.yml must build with the release's command (plus the two labels
and its own tag); tests/test_infra_staged.py compares the two.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RELEASE_WF = os.path.join(ROOT, ".github", "workflows", "images-release.yml")

FINGERPRINT_SCHEMA = 1
LABEL = "org.noomesh.build-fingerprint"
CREATED_LABEL = "org.opencontainers.image.created"
# The base digests a staged build used, `<key>=sha256:<hex>` per pinned FROM
# joined by `;` (format_bases). Absent: it was built on the git pins.
BASES_LABEL = "org.noomesh.base-digests"

# Where a FROM's registry variable points for the DAILY build: the SOURCE
# registries, so a base tag's newest digest is usable the day it is
# published (our mirrors follow later). The release never pulls a base for a
# staged image: it re-tags the staged digest.
BASE_SOURCES = {"DHI_REGISTRY": "dhi.io", "HUB_MIRROR": "docker.io"}

# Built daily and staged. Not here, and rebuilt by every release: gateway,
# node-agent, worker and trellion carry noomesh source; sandbox is built FROM
# deps-core:$TAG and COPYs src/**, so its inputs move with every release.
DAILY = ("llamacpp", "ollama", "stunnel", "postgres-pgvector", "whisper", "piper", "nvidia-exporter")

# Context-level ignore files that can change what a COPY sends.
IGNORE_FILES = (".dockerignore", "docker/.dockerignore")


def _plan_module():
    spec = importlib.util.spec_from_file_location("release_retag_plan", os.path.join(HERE, "release-retag-plan.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PLAN = _plan_module()


class NoFingerprint(Exception):
    """The inputs cannot be pinned down: build, never reuse."""


def _release_wf(path: str = RELEASE_WF) -> dict:
    import yaml  # the runner image and the test env both have PyYAML
    with open(path) as f:
        return yaml.safe_load(f)


def release_matrix(path: str = RELEASE_WF) -> list[dict]:
    return _release_wf(path)["jobs"]["images"]["strategy"]["matrix"]["include"]


def release_build_command(path: str = RELEASE_WF) -> str:
    """The `run:` text of the release's per-image build step."""
    steps = _release_wf(path)["jobs"]["images"]["steps"]
    runs = [s["run"] for s in steps if str(s.get("name", "")).startswith("Build + push")]
    if len(runs) != 1:
        raise NoFingerprint(f"images-release.yml has {len(runs)} 'Build + push' steps, expected 1")
    return runs[0]


def daily_matrix(entries: list[dict]) -> list[dict]:
    by_image = {e["image"]: e for e in entries}
    missing = [i for i in DAILY if i not in by_image]
    if missing:
        raise SystemExit(f"infra-staged: images-release.yml has no matrix entry for {missing}")
    return [by_image[i] for i in DAILY]


def from_refs(text: str) -> list[str]:
    """Every FROM image reference, in order. Raises NoFingerprint for one that
    is neither digest-pinned nor an earlier stage."""
    stages: set[str] = set()
    refs: list[str] = []
    for raw in text.splitlines():
        m = re.match(r"\s*FROM\s+(.*)$", raw, re.I)
        if not m:
            continue
        toks = [t for t in m.group(1).split() if not t.startswith("--")]
        if not toks:
            raise NoFingerprint(f"unparseable FROM: {raw.strip()}")
        ref = toks[0]
        if len(toks) >= 3 and toks[1].lower() == "as":
            stages.add(toks[2].lower())
        if ref.lower() in stages or ref == "scratch":
            refs.append(ref)
            continue
        if not re.search(r"@sha256:[0-9a-f]{64}$", ref):
            raise NoFingerprint(f"FROM {ref} is not pinned by digest")
        refs.append(ref)
    if not refs:
        raise NoFingerprint("no FROM line")
    return refs


_PINNED = re.compile(r"^(?:\$\{(?P<var>[A-Z_]+)\}/)?(?P<key>[^@\s]+:[^@\s]+)@(?P<digest>sha256:[0-9a-f]{64})$")


def pinned_bases(text: str) -> list[dict]:
    """Each digest-pinned FROM base, in order, de-duplicated: {key (the
    repo:tag after any `${VAR}/`), var, digest}. Raises NoFingerprint for an
    unpinned one (from_refs)."""
    out: list[dict] = []
    for ref in from_refs(text):
        m = _PINNED.match(ref)
        if not m:
            continue  # an earlier stage, or scratch
        b = {"key": m["key"], "var": m["var"] or "", "digest": m["digest"]}
        same = [o for o in out if o["key"] == b["key"]]
        if same and same[0]["digest"] != b["digest"]:
            raise NoFingerprint(f"{b['key']} is pinned at two digests")
        if not same:
            out.append(b)
    return out


def format_bases(bases: dict[str, str]) -> str:
    """The BASES_LABEL value: `key=digest` sorted, joined by `;`."""
    for k, d in bases.items():
        if not re.fullmatch(r"[^@\s;=]+:[^@\s;=]+", k) or not re.fullmatch(r"sha256:[0-9a-f]{64}", d):
            raise ValueError(f"bad base {k}={d}")
    return ";".join(f"{k}={d}" for k, d in sorted(bases.items()))


def parse_bases(label: str) -> dict[str, str]:
    """BASES_LABEL back to {key: digest}; ValueError on anything malformed."""
    out: dict[str, str] = {}
    for part in label.split(";"):
        k, sep, d = part.partition("=")
        if not sep or k in out:
            raise ValueError(f"bad base-digests label {label!r}")
        out[k] = d
    format_bases(out)  # validates
    return out


def rebase_text(text: str, bases: dict[str, str]) -> str:
    """`text` with each pinned FROM base in `bases` moved to that digest. A
    key that is not a pinned FROM of `text` (its tag changed in git since the
    staged build) raises NoFingerprint: the staged copy was built on another
    base."""
    keys = {b["key"] for b in pinned_bases(text)}
    unknown = sorted(set(bases) - keys)
    if unknown:
        raise NoFingerprint(f"base(s) {unknown} are not pinned FROMs at this commit")
    lines = []
    for raw in text.splitlines(keepends=True):
        if re.match(r"\s*FROM\s", raw, re.I):
            for k, d in bases.items():
                raw = re.sub(re.escape(k) + r"@sha256:[0-9a-f]{64}", lambda _m, k=k, d=d: f"{k}@{d}", raw)
        lines.append(raw)
    return "".join(lines)


def fingerprint(image: str, entry: dict, table: dict, read, tracked: list[str], build_command: str,
                bases: dict[str, str] | None = None) -> str:
    """The content fingerprint of `image`. `read(path) -> bytes` reads a repo
    file; `tracked` is every tracked repo path. `bases` ({key: digest}) is
    what a staged build resolved its FROM tags to: the Dockerfile is
    fingerprinted as built, with those digests in its FROM lines. With the
    git pins (no bases, or the same digests) the fingerprint is unchanged."""
    if bases:
        plain, dockerfile_path = read, entry["dockerfile"]

        def read(p: str, plain=plain) -> bytes:  # noqa: E306
            b = plain(p)
            return rebase_text(b.decode(), bases).encode() if p == dockerfile_path else b
    spec = table.get("images", {}).get(image)
    if not isinstance(spec, dict) or not spec.get("inputs"):
        raise NoFingerprint(f"{image}: no declared inputs in release-image-inputs.json")
    dockerfile = entry["dockerfile"]
    if spec["dockerfile"] != dockerfile:
        raise NoFingerprint(f"{image}: table says {spec['dockerfile']}, matrix says {dockerfile}")
    text = read(dockerfile).decode()
    bad = PLAN.uncovered_sources(text, entry["context"], spec["inputs"])
    if bad:
        raise NoFingerprint(f"{image}: COPY sources not pinned by the inputs table: {bad}")
    files: dict[str, str] = {}
    for g in spec["inputs"]:
        hit = [p for p in tracked if PLAN.covers([g], p)]
        if not hit:
            raise NoFingerprint(f"{image}: input {g} matches no tracked file")
        for p in hit:
            files[p] = hashlib.sha256(read(p)).hexdigest()
    for p in IGNORE_FILES:
        if p in tracked:
            files[p] = hashlib.sha256(read(p)).hexdigest()
    doc = {
        "schema": FINGERPRINT_SCHEMA,
        "image": image,
        "dockerfile": dockerfile,
        "context": os.path.normpath(entry["context"]),
        "platforms": entry["platforms"],
        "extra_args": entry.get("extra_args", ""),
        "build_command": build_command,
        "from": from_refs(text),
        "files": dict(sorted(files.items())),
    }
    blob = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def repo_fingerprint(image: str, root: str = ROOT, bases: dict[str, str] | None = None) -> str:
    wf = os.path.join(root, ".github", "workflows", "images-release.yml")
    entry = next((e for e in release_matrix(wf) if e["image"] == image), None)
    if entry is None:
        raise NoFingerprint(f"{image}: not in the images-release.yml matrix")
    try:
        tracked = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True,
                                 check=True).stdout.splitlines()
    except (OSError, subprocess.CalledProcessError) as e:
        raise NoFingerprint(f"git ls-files failed ({e})")
    with open(os.path.join(root, "scripts", "release-image-inputs.json")) as f:
        table = json.load(f)

    def read(p: str) -> bytes:
        with open(os.path.join(root, p), "rb") as fh:
            return fh.read()
    return fingerprint(image, entry, table, read, tracked, release_build_command(wf), bases)


def repo_dockerfile(image: str, root: str = ROOT) -> str:
    entry = next((e for e in release_matrix(os.path.join(root, ".github", "workflows", "images-release.yml"))
                  if e["image"] == image), None)
    if entry is None:
        raise NoFingerprint(f"{image}: not in the images-release.yml matrix")
    return entry["dockerfile"]


def resolve_bases(text: str, inspect, staged_label: str | None) -> dict[str, str]:
    """Each pinned FROM base's tag resolved at its SOURCE registry
    (BASE_SOURCES) to the digest it points at now. `inspect(ref)` returns
    (digest, created datetime) for a tag or digest reference.

    REFUSES (ValueError) a resolved digest built before the one git pins, or
    before the one the current :staged was built on (`staged_label`, its
    BASES_LABEL): a tag that moved backwards is not a security update."""
    staged = parse_bases(staged_label) if staged_label else {}
    out: dict[str, str] = {}
    for b in pinned_bases(text):
        src = BASE_SOURCES.get(b["var"]) if b["var"] else ""
        if b["var"] and not src:
            raise ValueError(f"{b['key']}: no source registry for ${{{b['var']}}}")
        repo, _, _tag = b["key"].rpartition(":")
        tag_ref = f"{src}/{b['key']}" if src else b["key"]
        at = lambda d, repo=repo: f"{src}/{repo}@{d}" if src else f"{repo}@{d}"  # noqa: E731
        digest, created = inspect(tag_ref)
        floors = [(b["digest"], "git pins")]
        if b["key"] in staged:
            floors.append((staged[b["key"]], "the current :staged was built on"))
        for floor, what in floors:
            if floor == digest:
                continue
            _, floor_created = inspect(at(floor))
            if created < floor_created:
                raise ValueError(f"{tag_ref} resolves to {digest[:19]}, built {created:%Y-%m-%d}, older than "
                                 f"{floor[:19]} ({what}, built {floor_created:%Y-%m-%d}): refusing a base that moved backwards")
        out[b["key"]] = digest
    return out


def registry_inspect(ref: str):
    """(manifest digest, created) of `ref`, read-only from the registry. The
    created time is the newest platform's."""
    def run(fmt: str) -> str:
        return subprocess.run(["docker", "buildx", "imagetools", "inspect", ref, "--format", fmt],
                              capture_output=True, text=True, check=True, timeout=120).stdout
    digest = json.loads(run("{{json .Manifest.Digest}}"))
    img = json.loads(run("{{json .Image}}"))
    configs = [img] if isinstance(img, dict) and "created" in img else list(img.values())
    created = max(PLAN._parse_time(c["created"]) for c in configs if c and c.get("created"))
    return digest, created


def findings(report: dict) -> set[tuple[str, str]]:
    """(vulnerability id, package) pairs with a fix, at HIGH or CRITICAL."""
    out = set()
    for res in report.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            if v.get("Severity") in ("HIGH", "CRITICAL") and v.get("FixedVersion"):
                out.add((v["VulnerabilityID"], v["PkgName"]))
    return out


def index_platforms(index: dict) -> list[str]:
    """`os/arch` of every image in a manifest list (attestation entries,
    platform unknown/unknown, left out); a single-platform manifest gives []
    because it names none."""
    out = []
    for m in index.get("manifests") or []:
        p = m.get("platform") or {}
        if p.get("os") and p.get("os") != "unknown" and p.get("architecture") and p.get("architecture") != "unknown":
            out.append(f"{p['os']}/{p['architecture']}")
    return out


def new_findings(new_reports: dict[str, dict], old_reports: dict[str, dict] | None) -> set[tuple[str, str]]:
    """Pairs in the new build that the current :staged lacks, PER PLATFORM:
    a platform's new report is compared with the SAME platform's old one.

    No staged copy at all (None): nothing is "new" - the first run stages
    what it built and its findings are listed, not gated. A staged copy that
    lacks a platform the new build has (2026-11-11: whisper and piper :staged
    were amd64-only, the daily build is amd64+arm64): that platform has no
    baseline, so EVERY one of its fixable HIGH/CRITICAL findings counts as
    new. Never skipped: a new platform is held to the gate in full."""
    if old_reports is None:
        return set()
    out: set[tuple[str, str]] = set()
    for platform, report in new_reports.items():
        out |= findings(report) - (findings(old_reports[platform]) if platform in old_reports else set())
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("matrix")
    fp = sub.add_parser("fingerprint")
    fp.add_argument("image")
    fp.add_argument("--bases", default="", help="the BASES_LABEL value the build used (empty: the git pins)")
    rb = sub.add_parser("resolve-bases", help="print the BASES_LABEL value for IMAGE's FROM tags as published now")
    rb.add_argument("image")
    rb.add_argument("--staged-label", default="", help="the current :staged BASES_LABEL (refuses older bases)")
    rd = sub.add_parser("rebase-dockerfile", help="rewrite IMAGE's Dockerfile in place onto --bases")
    rd.add_argument("image")
    rd.add_argument("--bases", required=True)
    sub.add_parser("platforms", help="read a manifest list (JSON) on stdin, print its os/arch list")
    nf = sub.add_parser("new-findings")
    nf.add_argument("--new", nargs="+", required=True, help="Trivy JSON reports of the new build")
    nf.add_argument("--old", nargs="*", help="Trivy JSON reports of the current :staged (omit: none staged yet)")
    a = ap.parse_args(argv)
    if a.cmd == "platforms":
        print(" ".join(index_platforms(json.load(sys.stdin))))
        return 0
    if a.cmd == "matrix":
        print(json.dumps(daily_matrix(release_matrix()), separators=(",", ":")))
        return 0
    if a.cmd == "fingerprint":
        try:
            print(repo_fingerprint(a.image, bases=parse_bases(a.bases) if a.bases else None))
        except (NoFingerprint, ValueError) as e:
            print(f"infra-staged: no fingerprint for {a.image}: {e}", file=sys.stderr)
            return 3
        return 0
    if a.cmd in ("resolve-bases", "rebase-dockerfile"):
        try:
            path = os.path.join(ROOT, repo_dockerfile(a.image))
            with open(path) as f:
                text = f.read()
            if a.cmd == "resolve-bases":
                print(format_bases(resolve_bases(text, registry_inspect, a.staged_label or None)))
            else:
                with open(path, "w") as f:
                    f.write(rebase_text(text, parse_bases(a.bases)))
        except (NoFingerprint, ValueError, subprocess.CalledProcessError, OSError) as e:
            print(f"infra-staged: {a.cmd} {a.image}: {e}", file=sys.stderr)
            return 3
        return 0

    def load(paths):
        # One report per platform, named for it (scan/new/linux-amd64.json).
        out = {}
        for p in paths:
            with open(p) as f:
                out[os.path.splitext(os.path.basename(p))[0]] = json.load(f)
        return out
    new = load(a.new)
    old = load(a.old) if a.old is not None else None
    found = sorted(new_findings(new, old))
    total = sorted(set().union(*(findings(r) for r in new.values())))
    print(f"fixable HIGH/CRITICAL in the new build: {len(total)}"
          + ("" if old is not None else " (no :staged yet: not gated)"))
    if old is not None:
        for platform in sorted(set(new) - set(old)):
            print(f"  {platform}: the current :staged has no {platform} copy, so every finding on it counts as new")
    for vid, pkg in total:
        print(f"  {'NEW ' if (vid, pkg) in found else '    '}{vid} {pkg}")
    if found:
        print(f"infra-staged: {len(found)} fixable HIGH/CRITICAL finding(s) the current :staged does not have; "
              "keeping the previous :staged", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
