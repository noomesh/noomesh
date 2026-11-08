# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The daily infra-image build (noomesh-internal i567): fingerprint and gate.

infra-staged.yml builds the infra images once a day, scans them, and moves
`<image>:staged`; the release will re-tag that staged copy when its content
fingerprint equals the one computed from the release commit. So:

  * the fingerprint changes when ANY build input changes, and there is none
    (never reuse) when an input cannot be pinned down;
  * a new fixable HIGH/CRITICAL finding keeps the previous :staged;
  * the workflow moves :staged only after the scan gate, and builds with the
    release's own command.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location("infra_staged", ROOT / "scripts/infra-staged.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


S = _load()
DAILY_WF = yaml.safe_load((ROOT / ".github/workflows/infra-staged.yml").read_text())
RELEASE_MATRIX = S.release_matrix()

PIN = "@sha256:" + "a" * 64
DOCKERFILE = f"FROM base:1{PIN} AS b\nRUN make\nFROM run:1{PIN}\nCOPY --from=b /o /o\nCOPY app.py /app.py\n"
FILES = {"docker/Dockerfile.x": DOCKERFILE.encode(), "docker/app.py": b"print(1)\n",
         ".dockerignore": b".git\n", "unrelated.txt": b"x"}
ENTRY = {"image": "x", "dockerfile": "docker/Dockerfile.x", "context": "./docker",
         "platforms": "linux/amd64,linux/arm64", "extra_args": ""}
TABLE = {"images": {"x": {"dockerfile": "docker/Dockerfile.x", "context": "./docker", "parents": [],
                          "inputs": ["docker/Dockerfile.x", "docker/app.py"]}}}
CMD = "docker buildx build --push ..."


def _fp(files=None, entry=None, table=None, cmd=CMD, tracked=None):
    files = dict(FILES if files is None else files)
    return S.fingerprint("x", entry or ENTRY, table or TABLE, lambda p: files[p],
                         list(files) if tracked is None else tracked, cmd)


# ----------------------------------------------------------- fingerprint

def test_equal_inputs_give_the_same_fingerprint_whatever_the_file_order():
    a = _fp()
    assert a.startswith("sha256:") and len(a) == 71
    assert _fp(tracked=list(reversed(list(FILES)))) == a
    assert _fp(files={**FILES, "unrelated.txt": b"changed"}) == a, "a file that is no input moved the fingerprint"


def test_every_input_class_changes_the_fingerprint(monkeypatch):
    base = _fp()
    pin2 = "@sha256:" + "b" * 64
    changed = {
        "a Dockerfile byte": dict(files={**FILES, "docker/Dockerfile.x": (DOCKERFILE + "# x\n").encode()}),
        "a COPY'd file": dict(files={**FILES, "docker/app.py": b"print(2)\n"}),
        "a FROM digest": dict(files={**FILES, "docker/Dockerfile.x": DOCKERFILE.replace(PIN, pin2, 1).encode()}),
        ".dockerignore": dict(files={**FILES, ".dockerignore": b".git\n*.md\n"}),
        "platforms": dict(entry={**ENTRY, "platforms": "linux/amd64"}),
        "build args": dict(entry={**ENTRY, "extra_args": "--build-arg X=1"}),
        "the release build command": dict(cmd=CMD + " --pull"),
    }
    for what, kw in changed.items():
        assert _fp(**kw) != base, f"{what} changed but the fingerprint did not"
    # the same files, sent from another build context
    wide = {"images": {"x": {**TABLE["images"]["x"], "inputs": ["docker/Dockerfile.x", "docker/app.py", "app.py"]}}}
    both = {**FILES, "app.py": b"print(1)\n"}
    assert _fp(files=both, table=wide) != _fp(files=both, table=wide, entry={**ENTRY, "context": "."}), "the context"
    monkeypatch.setattr(S, "FINGERPRINT_SCHEMA", S.FINGERPRINT_SCHEMA + 1)
    assert _fp() != base, "a schema bump must change every fingerprint"


def test_an_unpinned_from_has_no_fingerprint():
    for df in ("FROM python:3.12-slim\n", "FROM ${DEPS_CORE}\nCOPY app.py /a\n",
               f"FROM a{PIN} AS b\nFROM python:3.12\n"):
        with pytest.raises(S.NoFingerprint):
            _fp(files={**FILES, "docker/Dockerfile.x": df.encode()})
    # a stage name is not an image, and is fine
    assert _fp(files={**FILES, "docker/Dockerfile.x": f"FROM a{PIN} AS b\nFROM b\n".encode()})


def test_an_input_it_cannot_pin_down_has_no_fingerprint():
    missing_glob = {"images": {"x": {**TABLE["images"]["x"], "inputs": ["docker/Dockerfile.x", "docker/app.py", "docker/gone/**"]}}}
    undeclared = {**FILES, "docker/Dockerfile.x": (DOCKERFILE + "COPY other.py /o\n").encode()}
    unresolvable = {**FILES, "docker/Dockerfile.x": (DOCKERFILE + "COPY ${SRC} /o\n").encode()}
    for kw in (dict(table=missing_glob), dict(files=undeclared), dict(files=unresolvable),
               dict(table={"images": {}})):
        with pytest.raises(S.NoFingerprint):
            _fp(**kw)


def test_the_real_tree_fingerprints_every_daily_image_and_no_source_image():
    try:
        subprocess.run(["git", "ls-files", "--error-unmatch", "scripts/infra-staged.py"], cwd=ROOT,
                       capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout with this change committed")
    fps = {img: S.repo_fingerprint(img, str(ROOT)) for img in S.DAILY}
    assert len(set(fps.values())) == len(S.DAILY), fps
    # built FROM deps-core:$TAG, which no digest pins: never staged
    for img in ("sandbox", "worker"):
        with pytest.raises(S.NoFingerprint):
            S.repo_fingerprint(img, str(ROOT))


# --------------------------------------------------------------- the gate

def _report(*vulns):
    return {"Results": [{"Target": "t", "Vulnerabilities": [
        {"VulnerabilityID": v, "PkgName": p, "Severity": s, "FixedVersion": f} for v, p, s, f in vulns]}]}


HIGH = ("CVE-1", "libx", "HIGH", "1.2")
CRIT = ("CVE-2", "liby", "CRITICAL", "3.0")


def test_only_a_new_fixable_high_or_critical_finding_blocks():
    assert S.new_findings([_report(HIGH)], [_report(HIGH)]) == set(), "an inherited finding is not new"
    assert S.new_findings([_report(HIGH, CRIT)], [_report(HIGH)]) == {("CVE-2", "liby")}
    assert S.new_findings([_report(("CVE-3", "z", "MEDIUM", "1"))], [_report()]) == set()
    assert S.new_findings([_report(("CVE-4", "z", "HIGH", ""))], [_report()]) == set(), "no fix: not gated"
    # one platform's report is enough to block
    assert S.new_findings([_report(), _report(CRIT)], [_report(), _report()]) == {("CVE-2", "liby")}
    # nothing staged yet: the first run stages what it built
    assert S.new_findings([_report(CRIT)], None) == set()


def test_the_gate_exits_1_on_a_new_finding_so_staged_stays(tmp_path):
    new, old = tmp_path / "new.json", tmp_path / "old.json"
    new.write_text(json.dumps(_report(HIGH, CRIT)))
    old.write_text(json.dumps(_report(HIGH)))
    run = lambda *a: subprocess.run([sys.executable, str(ROOT / "scripts/infra-staged.py"), "new-findings", *a],
                                    capture_output=True, text=True)
    r = run("--new", str(new), "--old", str(old))
    assert r.returncode == 1 and "NEW CVE-2 liby" in r.stdout and "keeping the previous :staged" in r.stderr
    old.write_text(json.dumps(_report(HIGH, CRIT)))
    assert run("--new", str(new), "--old", str(old)).returncode == 0
    assert run("--new", str(new)).returncode == 0


# ------------------------------------------------------------ the workflow

def _steps():
    return DAILY_WF["jobs"]["stage"]["steps"]


def _idx(prefix):
    hits = [i for i, s in enumerate(_steps()) if str(s.get("name", "")).startswith(prefix)]
    assert len(hits) == 1, prefix
    return hits[0]


def test_staged_moves_only_after_the_scan_gate_and_the_build_pushes_only_a_date_tag():
    build, scan, gate, promote = (_idx("Build + push"), _idx("Scan the new build"), _idx("Gate"),
                                  _idx("Promote to :staged"))
    assert build < scan < gate < promote == len(_steps()) - 1
    for i, s in enumerate(_steps()):
        run = s.get("run", "")
        if i != promote:
            assert not re.search(r':staged["\s]', run.replace('"$REF:staged" --format', "")), \
                f"step {s.get('name')} touches :staged outside the promotion"
        assert "if" not in s or i in (_idx("Set up buildx, second attempt"),), \
            f"step {s.get('name')} is conditional: a failed gate must stop every later step"
    assert '-t "$REF:$DATE_TAG"' in _steps()[build]["run"]
    assert re.search(r"^set -\w*o pipefail$", _steps()[gate]["run"], re.M), \
        "| tee without pipefail turns a failed gate green"
    assert "new-findings" in _steps()[gate]["run"]
    assert '"$REF:staged" "$REF@$DIGEST"' in _steps()[promote]["run"]


def _buildx_lines(run):
    lines = [l.strip().rstrip("\\").strip() for l in run.split("docker buildx build", 1)[1].splitlines()]
    return [l for l in lines if l]


def test_the_daily_build_is_the_release_build_plus_labels():
    release = _buildx_lines(S.release_build_command())
    daily_run = _steps()[_idx("Build + push")]["run"].split("\nd=", 1)[0]
    daily = _buildx_lines(daily_run)
    drop_release = ("--cache-from", "--cache-to", "-t ", "${PUSH_LATEST")
    drop_daily = ("--label ", "-t ")
    norm = lambda ls, drop: [re.sub(r"\$\{\{ matrix\.\w+ \}\}", "M", l) for l in ls if not l.startswith(drop)]
    assert norm(daily, drop_daily) == norm(release, drop_release), (
        "infra-staged.yml must build exactly as images-release.yml does (only the labels, tag and cache differ)")
    labels = [l for l in daily if l.startswith("--label ")]
    assert any(S.LABEL in l for l in labels) and any(S.CREATED_LABEL in l for l in labels)


def test_the_daily_set_is_the_release_matrix_minus_the_images_that_carry_our_source():
    images = {e["image"] for e in RELEASE_MATRIX}
    assert set(S.DAILY) <= images
    assert images - set(S.DAILY) == {"gateway", "node-agent", "worker", "sandbox", "trellion"}, \
        "a new release image must be put in DAILY or explicitly left to the release"
    assert [e["image"] for e in S.daily_matrix(RELEASE_MATRIX)] == list(S.DAILY)
