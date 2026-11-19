# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""An infra image the release BUILDS is scanned and gated like a staged one.

images-release.yml re-tags an infra image (scripts/infra-staged.py DAILY) from
`:staged` when the daily copy is usable, and otherwise builds it in the
`images` leg. That fallback build used to ship unscanned, and the rc -> final
re-tag carried it into the final. Now the leg runs infra-staged.yml's own scan
and gate (scripts/infra-scan.sh), exactly as strict, no more:

  * the scan step runs only for an infra image this leg built;
  * same pinned Trivy, same flags, every platform the leg built;
  * new-findings with --old from the current :staged; no :staged, no gate;
  * one release line per infra image, and the step summary;
  * after the push, before the lock: a failed scan keeps the digest out of
    the signed lock (the tag is already pushed; nodes install by lock digest).
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCAN_SH = ROOT / "scripts/infra-scan.sh"
REL = yaml.safe_load((ROOT / ".github/workflows/images-release.yml").read_text())
DAILY_WF = yaml.safe_load((ROOT / ".github/workflows/infra-staged.yml").read_text())
CI = (ROOT / ".github/workflows/ci.yml").read_text()


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P = _load("release_retag_plan", "scripts/release-retag-plan.py")
S = _load("infra_staged", "scripts/infra-staged.py")

STEPS = REL["jobs"]["images"]["steps"]
SCAN_NAME = "Scan ${{ matrix.name }} as infra-staged does (built here, not re-tagged)"
RETAG_NAME = "Release log — ${{ matrix.name }} re-tagged"


def _step(name):
    hits = [s for s in STEPS if s.get("name") == name]
    assert len(hits) == 1, name
    return hits[0]


def _index(pred):
    hits = [i for i, s in enumerate(STEPS) if pred(s)]
    assert len(hits) == 1
    return hits[0]


# ------------------------------------------------ rule 1: only an infra image it built

def test_the_scan_step_runs_only_for_an_infra_image_this_leg_built(monkeypatch, tmp_path):
    scan = _step(SCAN_NAME)
    assert scan["if"] == "env.RETAG != 'true' && env.INFRA == 'true'", scan["if"]
    assert "continue-on-error" not in scan, "a failed scan must fail the leg"
    assert _step(RETAG_NAME)["if"] == "env.RETAG == 'true' && env.INFRA == 'true'"
    env = REL["jobs"]["images"]["env"]
    assert env["INFRA"] == "${{ contains(fromJSON(needs.release-line.outputs.infra), matrix.image) }}"
    assert REL["jobs"]["release-line"]["outputs"]["infra"] == "${{ steps.plan.outputs.infra }}"
    # The set is infra-staged.py DAILY, as the plan writes it: not retyped.
    monkeypatch.setattr(P, "plan", lambda *a, **kw: {
        "rc_tag": "", "rc_commit": "", "rc_digests": {}, "source_tags": {}, "staged": {},
        "retag": {"x": False}, "why": {"x": "build"}})
    out = tmp_path / "out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    P.main(["--tag", "v1.3.0-rc.1", "--no-staged"])
    line = next(l for l in out.read_text().splitlines() if l.startswith("infra="))
    assert json.loads(line.removeprefix("infra=")) == list(S.DAILY)
    assert "llamacpp-cuda" in S.DAILY


# ------------------------------------------------ rule 2: the same scan

def test_the_release_scan_is_the_daily_scan_on_every_platform_it_built():
    daily = {s.get("name"): s.get("run", "") for s in DAILY_WF["jobs"]["stage"]["steps"]}
    assert daily["Install Trivy (pinned, checksum-verified)"] == "scripts/infra-scan.sh install-trivy"
    assert daily["Scan the new build and the current :staged"].startswith("scripts/infra-scan.sh scan ")
    run = _step(SCAN_NAME)["run"]
    assert "scripts/infra-scan.sh install-trivy" in run
    assert 'scripts/infra-scan.sh scan "$ref" "$PUSHED_DIGEST" "${{ matrix.platforms }}"' in run, \
        "every platform this leg built, at the digest it pushed"
    assert 'ref="$REGISTRY/$OWNER/${{ matrix.image }}"' in run
    assert "scripts/infra-scan.sh gate" in run
    rec = _step("Record digest")["run"]
    assert 'echo "PUSHED_DIGEST=$d" >> "$GITHUB_ENV"' in rec
    # infra-staged's exact flags, in the one shared copy
    sh = SCAN_SH.read_text()
    flat = re.sub(r"\s*\\\n\s*", " ", sh)
    flags = ('trivy image --skip-db-update --image-src remote --platform "$p" '
             "--severity HIGH,CRITICAL --ignore-unfixed --format json -o ")
    assert flat.count(flags + '"scan/new/$n.json" "$ref@$digest"') == 1
    assert flat.count(flags + '"scan/old/$n.json" "$ref@$old"') == 1, "the old :staged, the same flags"
    assert "trivy image --download-db-only" in sh


def test_one_trivy_pin_and_it_is_ci_yml_s():
    sh = SCAN_SH.read_text()
    ver = re.search(r'^TRIVY_VERSION="([^"]+)"$', sh, re.M).group(1)
    sha = re.search(r'^TRIVY_SHA256="([0-9a-f]{64})"$', sh, re.M).group(1)
    assert re.findall(r'TRIVY_VERSION: "([^"]+)"', CI) == [ver, ver], "ci.yml's security-scan pin moved apart"
    assert re.findall(r'TRIVY_SHA256: "([0-9a-f]{64})"', CI) == [sha, sha]
    for wf in ("infra-staged.yml", "images-release.yml"):
        assert "TRIVY_" not in (ROOT / ".github/workflows" / wf).read_text(), f"{wf} keeps a second pin"
    assert 'echo "${TRIVY_SHA256}  $dir/trivy.tgz" | sha256sum -c -' in sh


# ------------------------------------------------ rule 3: the gate, run for real

def _fakes(tmp_path, staged: bool, new_vulns, old_vulns):
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True)
    calls = tmp_path / "calls"
    (bindir / "docker").write_text(
        "#!/usr/bin/env bash\n"
        'case "$*" in\n'
        + ('  *--raw*) echo \'{"manifests":[{"platform":{"os":"linux","architecture":"amd64"}},'
           '{"platform":{"os":"linux","architecture":"arm64"}}]}\' ;;\n'
           '  *":staged --format"*) echo \'"sha256:old"\' ;;\n' if staged else
           '  *":staged --format"*) exit 1 ;;\n')
        + "esac\n")

    def report(vulns):
        return json.dumps({"Results": [{"Target": "t", "Vulnerabilities": [
            {"VulnerabilityID": v, "PkgName": p, "Severity": "HIGH", "FixedVersion": "2"} for v, p in vulns]}]})
    (bindir / "trivy").write_text(
        "#!/usr/bin/env bash\n"
        f'echo "$*" >> {calls}\n'
        '[ "$2" = "--download-db-only" ] && exit 0\n'
        'out=""; prev=""; for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done\n'
        'case "${@: -1}" in\n'
        f"  *@sha256:old) echo '{report(old_vulns)}' > \"$out\" ;;\n"
        f"  *) echo '{report(new_vulns)}' > \"$out\" ;;\n"
        "esac\n")
    for f in ("docker", "trivy"):
        (bindir / f).chmod(0o755)
    work = tmp_path / "w"
    work.mkdir()
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}
    for k in ("GITHUB_ENV", "GITHUB_STEP_SUMMARY", "GITHUB_PATH"):
        env.pop(k, None)

    def run(*args):
        return subprocess.run(["bash", str(SCAN_SH), *args], cwd=work, env=env, capture_output=True, text=True)
    return run, calls


def test_the_gate_takes_old_from_staged_and_gates_nothing_without_it(tmp_path):
    a, b = ("CVE-1", "libx"), ("CVE-2", "liby")
    # a :staged copy that lacks CVE-2: new finding, the leg fails
    run, calls = _fakes(tmp_path / "1", True, [a, b], [a])
    assert run("scan", "reg/o/llamacpp", "sha256:new", "linux/amd64,linux/arm64").returncode == 0
    r = run("gate")
    assert r.returncode == 1 and "NEW CVE-2 liby" in r.stdout, r.stdout + r.stderr
    scans = [l for l in calls.read_text().splitlines() if "--platform" in l]
    assert len(scans) == 4, "both platforms of the new build and of :staged"
    # the same findings as :staged: inherited, passes
    run, _ = _fakes(tmp_path / "2", True, [a], [a])
    run("scan", "reg/o/llamacpp", "sha256:new", "linux/amd64,linux/arm64")
    r = run("gate")
    assert r.returncode == 0 and "NEW" not in r.stdout, r.stdout
    # no :staged at all: reported, not gated
    run, calls = _fakes(tmp_path / "3", False, [a, b], [])
    run("scan", "reg/o/llamacpp-cuda", "sha256:new", "linux/amd64")
    r = run("gate")
    assert r.returncode == 0 and "fixable HIGH/CRITICAL in the new build: 2 (no :staged yet: not gated)" in r.stdout, \
        r.stdout + r.stderr
    assert all("@sha256:old" not in l for l in calls.read_text().splitlines())


# ------------------------------------------------ rule 4: the three release lines

def test_each_infra_image_gets_one_of_the_release_lines(tmp_path):
    env = {**os.environ, "GITHUB_STEP_SUMMARY": str(tmp_path / "sum")}
    (tmp_path / "scan").mkdir()

    def sh(*args):
        return subprocess.run(["bash", str(SCAN_SH), *args], cwd=tmp_path, env=env, capture_output=True, text=True)
    (tmp_path / "scan/gate.txt").write_text("fixable HIGH/CRITICAL in the new build: 3\n      CVE-1 libx\n")
    (tmp_path / "scan/old-digest").write_text("sha256:old\n")
    r = sh("verdict", "ollama")
    assert r.returncode == 0
    assert r.stdout.strip() == "ollama: built here; scanned: 3 fixable HIGH/CRITICAL, 0 new vs :staged sha256:old"
    (tmp_path / "scan/old-digest").write_text("\n")
    r = sh("verdict", "llamacpp-cuda")
    assert "llamacpp-cuda: built here; first build (no :staged), scanned, not gated: 3 fixable HIGH/CRITICAL" \
        in r.stdout, r.stdout
    r = sh("retag-line", "stunnel", "@sha256:abc", "2026-11-18T03:17:00Z")
    assert r.stdout.strip() == \
        "stunnel: re-tagged from :staged sha256:abc (built 2026-11-18T03:17:00Z, passed infra-staged's gate)"
    summary = (tmp_path / "sum").read_text()
    for want in ("0 new vs :staged sha256:old", "first build (no :staged), scanned, not gated",
                 "re-tagged from :staged sha256:abc"):
        assert want in summary, want
    # a gate result with a NEW finding is never reported as "0 new"
    (tmp_path / "scan/gate.txt").write_text("fixable HIGH/CRITICAL in the new build: 1\n  NEW CVE-2 liby\n")
    assert sh("verdict", "ollama").returncode == 1
    # the plan's own words match
    src = (ROOT / "scripts/release-retag-plan.py").read_text()
    assert "re-tag from :staged {digest[:19]} (built {staged[img]}, fingerprint matches; " in src
    assert "passed infra-staged's gate" in src and "built here, then scanned and gated as infra-staged does" in src


# ------------------------------------------------ rule 5: after the push, before the lock

def test_the_scan_sits_between_the_push_and_the_lock_and_a_failure_skips_the_lock(tmp_path):
    build = _index(lambda s: str(s.get("name", "")).startswith("Build + push"))
    record = _index(lambda s: s.get("name") == "Record digest")
    scan = _index(lambda s: s.get("name") == SCAN_NAME)
    upload = _index(lambda s: "upload-artifact" in str(s.get("uses", "")))
    assert build < record < scan < upload, "scan the pushed digest before its artifact is uploaded"
    lock = REL["jobs"]["lock"]
    assert "images" in lock["needs"]
    assert "needs.images.result == 'success'" in lock["if"], \
        "a failed images leg (a failed scan) must skip the signed lock"
    assert "always()" not in lock["if"]
    # The failing step says what happened to the already-pushed tag.
    run = _step(SCAN_NAME)["run"]
    fake = tmp_path / "scripts"
    fake.mkdir()
    (fake / "infra-scan.sh").write_text('#!/usr/bin/env bash\n[ "$1" = gate ] && exit 1\nexit 0\n')
    (fake / "infra-scan.sh").chmod(0o755)
    run = run.replace("${{ matrix.image }}", "ollama").replace("${{ matrix.platforms }}", "linux/amd64")
    env = {"PATH": os.environ["PATH"], "RUNNER_TEMP": str(tmp_path), "REGISTRY": "reg", "OWNER": "o",
           "TAG": "v1.2.3", "PUSH_LATEST": "1", "PUSHED_DIGEST": "sha256:d"}
    r = subprocess.run(["bash", "-c", run], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert r.returncode == 1, r.stdout + r.stderr
    assert ("the image is pushed as reg/o/ollama:v1.2.3 and reg/o/ollama:latest but kept out of the signed lock; "
            "nodes install by lock digest") in r.stdout, r.stdout
