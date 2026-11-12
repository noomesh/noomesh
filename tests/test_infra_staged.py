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


A64, R64 = "linux-amd64", "linux-arm64"


def test_only_a_new_fixable_high_or_critical_finding_blocks():
    assert S.new_findings({A64: _report(HIGH)}, {A64: _report(HIGH)}) == set(), "an inherited finding is not new"
    assert S.new_findings({A64: _report(HIGH, CRIT)}, {A64: _report(HIGH)}) == {("CVE-2", "liby")}
    assert S.new_findings({A64: _report(("CVE-3", "z", "MEDIUM", "1"))}, {A64: _report()}) == set()
    assert S.new_findings({A64: _report(("CVE-4", "z", "HIGH", ""))}, {A64: _report()}) == set(), "no fix: not gated"
    # one platform's report is enough to block
    assert S.new_findings({A64: _report(), R64: _report(CRIT)}, {A64: _report(), R64: _report()}) == {("CVE-2", "liby")}
    # nothing staged yet: the first run stages what it built
    assert S.new_findings({A64: _report(CRIT)}, None) == set()


def test_each_platform_is_compared_with_its_own_old_copy():
    # Before 2026-11-11 the reports were pooled: an arm64 finding that only the
    # old AMD64 copy had counted as inherited.
    assert S.new_findings({A64: _report(), R64: _report(CRIT)}, {A64: _report(CRIT), R64: _report()}) == \
        {("CVE-2", "liby")}


def test_a_platform_the_staged_copy_lacks_is_gated_in_full():
    # whisper/piper 2026-11-11: :staged amd64-only, the daily build amd64+arm64.
    # The arm64 side has no baseline: every fixable HIGH/CRITICAL on it is new.
    assert S.new_findings({A64: _report(HIGH), R64: _report(HIGH, CRIT)}, {A64: _report(HIGH)}) == \
        {("CVE-1", "libx"), ("CVE-2", "liby")}
    assert S.new_findings({A64: _report(HIGH), R64: _report()}, {A64: _report(HIGH)}) == set(), \
        "a clean new platform passes"
    assert S.new_findings({R64: _report(HIGH)}, {}) == {("CVE-1", "libx")}, \
        "a :staged with NONE of the new platforms is not 'nothing staged': still gated"


def test_the_platforms_of_a_manifest_list_leave_attestations_out(tmp_path):
    index = {"manifests": [{"platform": {"os": "linux", "architecture": "amd64"}},
                           {"platform": {"os": "unknown", "architecture": "unknown"}},
                           {"platform": {"os": "linux", "architecture": "arm64"}}]}
    assert S.index_platforms(index) == ["linux/amd64", "linux/arm64"]
    assert S.index_platforms({"mediaType": "application/vnd.oci.image.manifest.v1+json"}) == []
    r = subprocess.run([sys.executable, str(ROOT / "scripts/infra-staged.py"), "platforms"],
                       input=json.dumps(index), capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == "linux/amd64 linux/arm64"
    r = subprocess.run([sys.executable, str(ROOT / "scripts/infra-staged.py"), "platforms"],
                       input="", capture_output=True, text=True)
    assert r.returncode != 0, "an unreadable index must fail the step, not read as 'no platforms'"


def _gate(*args):
    return subprocess.run([sys.executable, str(ROOT / "scripts/infra-staged.py"), "new-findings", *args],
                          capture_output=True, text=True)


def test_the_gate_exits_1_on_a_new_finding_so_staged_stays(tmp_path):
    (tmp_path / "new").mkdir()
    (tmp_path / "old").mkdir()
    new, old = tmp_path / "new" / f"{A64}.json", tmp_path / "old" / f"{A64}.json"
    new.write_text(json.dumps(_report(HIGH, CRIT)))
    old.write_text(json.dumps(_report(HIGH)))
    r = _gate("--new", str(new), "--old", str(old))
    assert r.returncode == 1 and "NEW CVE-2 liby" in r.stdout and "keeping the previous :staged" in r.stderr
    old.write_text(json.dumps(_report(HIGH, CRIT)))
    assert _gate("--new", str(new), "--old", str(old)).returncode == 0
    assert _gate("--new", str(new)).returncode == 0


def test_the_gate_holds_a_new_platform_from_files_named_by_platform(tmp_path):
    # The real file layout: scan/new/<os-arch>.json, scan/old/<os-arch>.json.
    (tmp_path / "new").mkdir()
    (tmp_path / "old").mkdir()
    (tmp_path / "new" / f"{A64}.json").write_text(json.dumps(_report(HIGH)))
    (tmp_path / "new" / f"{R64}.json").write_text(json.dumps(_report(HIGH, CRIT)))
    (tmp_path / "old" / f"{A64}.json").write_text(json.dumps(_report(HIGH)))
    new = [str(tmp_path / "new" / f"{x}.json") for x in (A64, R64)]
    r = _gate("--new", *new, "--old", str(tmp_path / "old" / f"{A64}.json"))
    assert r.returncode == 1 and "NEW CVE-2 liby" in r.stdout and "NEW CVE-1 libx" in r.stdout, r.stdout
    assert f"{R64}: the current :staged has no {R64} copy" in r.stdout
    r = _gate("--new", *new, "--old")  # staged, but none of the new platforms
    assert r.returncode == 1, "--old with no reports is a staged copy with no baseline, not 'nothing staged'"


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


def test_the_old_staged_is_scanned_only_for_the_platforms_it_has():
    scan = _steps()[_idx("Scan the new build")]["run"]
    assert '| python3 scripts/infra-staged.py platforms)"' in scan
    assert 'case " $old_platforms " in *" $p "*)' in scan, "only a platform the old index has is scanned"
    gate = _steps()[_idx("Gate")]["run"]
    assert "shopt -s nullglob" in gate and '--old "${olds[@]}"' in gate, \
        "the gate gets exactly the old reports that exist, possibly none"


def test_the_daily_build_is_the_release_build_plus_labels():
    release = _buildx_lines(S.release_build_command())
    daily_run = _steps()[_idx("Build + push")]["run"].split("\nd=", 1)[0]
    daily = _buildx_lines(daily_run)
    drop_release = ("--cache-from", "--cache-to", "-t ", "${PUSH_LATEST")
    drop_daily = ("--label ", "-t ")
    # The base registries differ on purpose (i604): the daily build pulls its
    # FROM tags' newest digests at the SOURCE (BASE_SOURCES), the release
    # builds the git pins from our mirrors. Every other argument is the same.
    bases = tuple(f"--build-arg {v}=" for v in S.BASE_SOURCES)
    norm = lambda ls, drop: [re.sub(r"\$\{\{ matrix\.\w+ \}\}", "M", l) for l in ls
                             if not l.startswith(drop) and not l.startswith(bases)]
    assert norm(daily, drop_daily) == norm(release, drop_release), (
        "infra-staged.yml must build exactly as images-release.yml does (only the labels, tag, cache and base registries differ)")
    assert [l for l in daily if l.startswith(bases)] == [f"--build-arg {v}={src}" for v, src in S.BASE_SOURCES.items()]
    labels = [l for l in daily if l.startswith("--label ")]
    assert any(S.LABEL in l for l in labels) and any(S.CREATED_LABEL in l for l in labels)
    assert any(f"{S.BASES_LABEL}=$BASES" in l for l in labels), "the build must record the bases it used"


def test_the_daily_set_is_the_release_matrix_minus_the_images_that_carry_our_source():
    images = {e["image"] for e in RELEASE_MATRIX}
    assert set(S.DAILY) <= images
    assert images - set(S.DAILY) == {"gateway", "node-agent", "worker", "sandbox", "trellion"}, \
        "a new release image must be put in DAILY or explicitly left to the release"
    assert [e["image"] for e in S.daily_matrix(RELEASE_MATRIX)] == list(S.DAILY)
