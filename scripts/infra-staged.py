#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Infra images built once a day, outside the release (noomesh-internal i567).

The infra images (llama-server compiled from source, the hardened Ollama,
postgres + pgvector, the voice servers, the stunnel sidecar, the GPU
exporter) carry no noomesh source and change a few times a quarter. The
release rebuilt them for every new version anyway: llamacpp's from-source
arm64 compile under QEMU is ~60 min of every rc.1. They are built here
instead, daily (infra-staged.yml), so they also pick up the day's distro
security updates, scanned, and staged as `<image>:staged`; the release
re-tags the staged copy when its fingerprint matches the release commit.

  matrix              JSON `include` list for the daily set, read from the
                      images-release.yml matrix, so the daily build uses the
                      release's exact dockerfile/context/platforms/args.
  fingerprint IMAGE   the content fingerprint of IMAGE's build inputs at this
                      checkout; exit 3 (and nothing on stdout) when it cannot
                      be computed, which means "never reuse, build".
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


def fingerprint(image: str, entry: dict, table: dict, read, tracked: list[str], build_command: str) -> str:
    """The content fingerprint of `image`. `read(path) -> bytes` reads a repo
    file; `tracked` is every tracked repo path."""
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


def repo_fingerprint(image: str, root: str = ROOT) -> str:
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
    return fingerprint(image, entry, table, read, tracked, release_build_command(wf))


def findings(report: dict) -> set[tuple[str, str]]:
    """(vulnerability id, package) pairs with a fix, at HIGH or CRITICAL."""
    out = set()
    for res in report.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            if v.get("Severity") in ("HIGH", "CRITICAL") and v.get("FixedVersion"):
                out.add((v["VulnerabilityID"], v["PkgName"]))
    return out


def new_findings(new_reports: list[dict], old_reports: list[dict] | None) -> set[tuple[str, str]]:
    """Pairs in the new build that the current :staged lacks. No staged copy
    yet (None): nothing is "new" — the first run stages what it built and its
    findings are listed, not gated."""
    new = set().union(*(findings(r) for r in new_reports)) if new_reports else set()
    if old_reports is None:
        return set()
    old = set().union(*(findings(r) for r in old_reports)) if old_reports else set()
    return new - old


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("matrix")
    fp = sub.add_parser("fingerprint")
    fp.add_argument("image")
    nf = sub.add_parser("new-findings")
    nf.add_argument("--new", nargs="+", required=True, help="Trivy JSON reports of the new build")
    nf.add_argument("--old", nargs="*", help="Trivy JSON reports of the current :staged (omit: none staged yet)")
    a = ap.parse_args(argv)
    if a.cmd == "matrix":
        print(json.dumps(daily_matrix(release_matrix()), separators=(",", ":")))
        return 0
    if a.cmd == "fingerprint":
        try:
            print(repo_fingerprint(a.image))
        except NoFingerprint as e:
            print(f"infra-staged: no fingerprint for {a.image}: {e}", file=sys.stderr)
            return 3
        return 0

    def load(paths):
        out = []
        for p in paths:
            with open(p) as f:
                out.append(json.load(f))
        return out
    new = load(a.new)
    old = load(a.old) if a.old is not None else None
    found = sorted(new_findings(new, old))
    total = sorted(set().union(*(findings(r) for r in new)))
    print(f"fixable HIGH/CRITICAL in the new build: {len(total)}"
          + ("" if old is not None else " (no :staged yet: not gated)"))
    for vid, pkg in total:
        print(f"  {'NEW ' if (vid, pkg) in found else '    '}{vid} {pkg}")
    if found:
        print(f"infra-staged: {len(found)} fixable HIGH/CRITICAL finding(s) the current :staged does not have; "
              "keeping the previous :staged", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
