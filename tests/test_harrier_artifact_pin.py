# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The harrier embedder artifact is pinned by digest in the signed stack lock.

Until 0.6.29 every install pulled `ghcr.io/noomesh/harrier:v1`, a MUTABLE
tag, and checked it with the `harrier.sha256` inside the same image: a moved
tag would have carried its own matching sum. The release now pins the image
digest (scripts/harrier-artifact.json), the lock job writes it into the
signed lock, every CLI pull is `<prefix>/harrier@sha256:...` from that row,
and publish-harrier.yml never overwrites a tag.

One test per check:
  * the pin file holds the 0.6.28 values; the lane writes the PINNED digest
    (and never pulls a tag);
  * the lane refuses an image whose harrier.sha256 is not the pinned GGUF;
  * the lock job and the release-line check use the pin, before signing;
  * no source pulls harrier by tag, and every pull site routes through the
    lock reader;
  * publish-harrier refuses a tag that exists (run against a fake docker).
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "harrier-artifact-pin.py"
RELEASE_WF = ROOT / ".github/workflows/images-release.yml"
PUBLISH_WF = ROOT / ".github/workflows/publish-harrier.yml"
IMG = "sha256:2fe41964a009bda0c55f299b632b122bcb4561ca4a833e3293c9f3cc685bab79"
GGUF = "5f26506ab57fd817ce4a8b9d24946a60d40bc76d82a2defa7cd754ae01e9de80"


def _mod():
    spec = importlib.util.spec_from_file_location("harrier_artifact_pin", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


M = _mod()


# ── the pin and the lane ────────────────────────────────────────────────────

def test_the_repo_pins_the_0_6_28_harrier():
    pin = M.load()
    assert pin["digest"] == IMG and pin["gguf_sha256"] == GGUF and pin["gguf"] == "harrier-Q4_K_M.gguf"
    assert M.ref(pin, "ghcr.io", "noomesh") == f"ghcr.io/noomesh/harrier@{IMG}"


def test_the_lane_writes_the_pinned_digest_and_pulls_only_it(tmp_path, monkeypatch):
    pulled = []
    monkeypatch.setattr(M, "fetch", lambda ref, dest: pulled.append(ref))
    monkeypatch.setattr(M, "check_files", lambda pin, d: None)
    assert M.main(["rows", "--registry", "ghcr.io", "--owner", "noomesh", "--out", str(tmp_path)]) == 0
    assert pulled == [f"ghcr.io/noomesh/harrier@{IMG}"], "the lane pulls the pinned digest, never a tag"
    assert (tmp_path / "harrier").read_text() == f"harrier@{IMG}\n"
    assert (tmp_path / "harrier-gguf").read_text() == f"# harrier-gguf-sha256 {GGUF}\n"


def test_the_lane_refuses_a_tag_reference(tmp_path, monkeypatch):
    ran = []
    monkeypatch.setattr(M, "_run", lambda cmd, **kw: ran.append(cmd) or subprocess.CompletedProcess(cmd, 1, "", "no"))
    with pytest.raises(M.PinError, match="not a digest reference"):
        M.fetch("ghcr.io/noomesh/harrier:v1", tmp_path)
    assert ran == [], "nothing is pulled by tag"


def _unpacked(d: Path, gguf: bytes, named: str) -> None:
    (d / "harrier-Q4_K_M.gguf").write_bytes(gguf)
    (d / "harrier.sha256").write_text(f"{named}  harrier-Q4_K_M.gguf\n")


def test_the_lane_refuses_an_image_whose_sum_is_not_the_pinned_gguf(tmp_path):
    body = b"weights"
    real = hashlib.sha256(body).hexdigest()
    pin = dict(M.load(), gguf_sha256=real)
    _unpacked(tmp_path, body, real)
    M.check_files(pin, tmp_path)                     # the pinned sha, and the file matches: passes
    other = dict(pin, gguf_sha256="0" * 64)
    with pytest.raises(M.PinError, match="pins 0000"):
        M.check_files(other, tmp_path)               # self-consistent image, wrong GGUF: refused


def test_the_lane_refuses_files_that_do_not_match_their_sum(tmp_path):
    body = b"weights"
    real = hashlib.sha256(body).hexdigest()
    pin = dict(M.load(), gguf_sha256=real)
    _unpacked(tmp_path, b"tampered", real)           # the sum file names the pin, the bytes are not it
    with pytest.raises(M.PinError, match="sha256sum -c"):
        M.check_files(pin, tmp_path)


def test_a_malformed_pin_is_refused(tmp_path):
    p = tmp_path / "pin.json"
    p.write_text('{"image": "harrier", "digest": "v1", "gguf": "harrier-Q4_K_M.gguf", "gguf_sha256": "%s"}' % GGUF)
    with pytest.raises(M.PinError, match="digest must be"):
        M.load(p)


def _steps(job: str) -> list[dict]:
    return yaml.safe_load(RELEASE_WF.read_text())["jobs"][job]["steps"]


def test_the_lock_job_writes_the_pin_before_signing_and_without_the_seed():
    steps = _steps("lock")
    names = [s.get("name", "") for s in steps]
    pin = next(i for i, s in enumerate(steps) if "harrier-artifact-pin.py rows" in s.get("run", ""))
    assert "--out digests" in steps[pin]["run"]
    download = max(i for i, s in enumerate(steps) if "download-artifact" in s.get("uses", ""))
    sign = next(i for i, n in enumerate(names) if n.startswith("Assemble + sign"))
    logins = [i for i, s in enumerate(steps) if "docker login" in s.get("run", "")]
    assert download < pin < sign, names
    assert all(pin < i for i in logins), "the pinned digest is pulled anonymously, as a fresh host does"
    assert "NOO_RELEASE_SIGNING_SEED" not in str(steps[pin])


def test_the_release_line_checks_the_pinned_digest_not_the_tag():
    steps = _steps("release-line")
    step = next(s for s in steps if "harrier" in s.get("name", ""))
    assert "harrier-artifact-pin.py ref" in step["run"] and 'docker manifest inspect "$ref"' in step["run"]
    wf = RELEASE_WF.read_text()
    assert "harrier:v1" not in wf and "harrier:latest" not in wf


def _fake_docker(tmp_path: Path, script: str) -> dict:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    d = bin_dir / "docker"
    d.write_text("#!/bin/sh\necho \"$@\" >> \"$DOCKER_LOG\"\n" + script)
    d.chmod(d.stat().st_mode | stat.S_IEXEC)
    return dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", DOCKER_LOG=str(tmp_path / "docker.log"),
                REGISTRY="ghcr.io", OWNER="noomesh", GITHUB_ENV=str(tmp_path / "github.env"))


def test_the_release_line_step_asks_the_registry_for_the_pinned_digest(tmp_path):
    step = next(s for s in _steps("release-line") if "harrier" in s.get("name", ""))
    env = _fake_docker(tmp_path, "exit 0\n")
    r = subprocess.run(["bash", "-c", step["run"]], cwd=ROOT, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "docker.log").read_text() == f"manifest inspect ghcr.io/noomesh/harrier@{IMG}\n"
    env = _fake_docker(tmp_path, "exit 1\n")
    r = subprocess.run(["bash", "-c", step["run"]], cwd=ROOT, env=env, capture_output=True, text=True)
    assert r.returncode == 1 and "not pullable anonymously" in r.stdout, r.stdout


# ── no harrier pull by tag, anywhere ────────────────────────────────────────

# An image path naming harrier (or the generic artifact `{name}`) at a tag.
TAG_PULL = re.compile(r"/harrier:(v\d|latest|\{|\$)|/\{name\}:v\d")
SCAN = ["noo-cli/src", "scripts", "docs", ".github/workflows", "docker", "node-agent-go", "gateway-rust/src"]
# The ONE writer of a harrier tag: it pushes it (and refuses an existing one).
PUSHES_THE_TAG = {".github/workflows/publish-harrier.yml"}


def test_nothing_pulls_harrier_by_tag():
    hits = []
    for top in SCAN:
        for p in (ROOT / top).rglob("*"):
            if not p.is_file() or p.suffix not in {".rs", ".go", ".py", ".sh", ".yml", ".yaml", ".md", ".json"}:
                continue
            rel = p.relative_to(ROOT).as_posix()
            if rel in PUSHES_THE_TAG:
                continue
            for n, line in enumerate(p.read_text(errors="ignore").splitlines(), 1):
                if TAG_PULL.search(line):
                    hits.append(f"{rel}:{n}: {line.strip()}")
    assert not hits, "harrier is pulled only by the signed lock's digest:\n" + "\n".join(hits)


def _fn(src: str, marker: str) -> str:
    start = src.index(marker)
    end = src.index("\n}\n", start)
    return src[start:end]


def test_every_harrier_pull_site_takes_the_ref_from_the_lock_reader():
    steps = (ROOT / "noo-cli/src/onboard/steps.rs").read_text()
    assert "controller_lock_opt()" in _fn(steps, "pub(crate) fn harrier_artifact_ref(")
    assert "match harrier_artifact_ref() {" in _fn(steps, "pub(crate) fn ensure_embed_model_core(")
    assert "ensure_embed_model_core(&model)" in _fn(steps, "fn ensure_embed_model(ctx")
    models = (ROOT / "noo-cli/src/commands/models.rs").read_text()
    assert 'ensure_embed_model_core("harrier")' in _fn(models, "fn pull_harrier(")
    upgrade = (ROOT / "noo-cli/src/commands/upgrade.rs").read_text()
    assert "ensure_embed_model_core(&model)" in _fn(upgrade, "fn ensure_embedder_after_roll(")
    migrate = (ROOT / "noo-cli/src/commands/migrate.rs").read_text()
    assert "crate::onboard::onboard(g, &fwd)" in _fn(migrate, "pub fn migrate_import(")
    stage = (ROOT / "noo-cli/src/commands/cluster_provision_subprocess.rs").read_text()
    assert "harrier_artifact_ref()?" in _fn(stage, "fn stage_artifact_into_store(")


# ── no environment variable feeds the harrier pin ───────────────────────────

def rust_fn_body(src: str, marker: str) -> str:
    """`marker` through the brace that closes its body, as test_src::fn_body
    slices it: from the marker, the first `{` opens the body (no signature
    here has a brace) and the matching `}` closes it. Never split on
    "\nfn ": that reads the NEXT fn's doc comment into this one. Line
    comments are dropped first, so a brace in a comment cannot unbalance it;
    format-string braces are balanced pairs."""
    code = "\n".join(re.sub(r"//.*$", "", line) for line in src.splitlines())
    start = code.index(marker)
    depth, open_at = 0, code.index("{", start)
    for i in range(open_at, len(code)):
        depth += {"{": 1, "}": -1}.get(code[i], 0)
        if depth == 0:
            return code[start:i + 1]
    raise AssertionError(f"{marker} never closes")


ENV_READS = re.compile(r"env::var|var_os|getenv|std::env|option_env!|\benv!\(|env_value\(|read_env\(|HARRIER_DIGEST")
# The functions that build the harrier ref or read its pin.
REF_BUILDERS = [
    ("noo-cli/src/onboard/steps.rs", "pub(crate) fn harrier_artifact_ref("),
    ("noo-cli/src/onboard/steps.rs", "pub(crate) fn harrier_ref_from("),
    ("noo-cli/src/commands/image_stage.rs", "pub(crate) fn harrier_pin_in("),
    ("noo-cli/src/commands/cluster_provision_subprocess.rs", "fn stage_artifact_into_store("),
]


def test_the_slicer_stops_at_the_end_of_the_fn():
    src = "/// a\nfn a() -> X {\n    let s = format!(\"{x}\"); // }\n    if y { z }\n}\n\n/// b reads std::env\nfn b() { std::env::var(\"K\") }\n"
    body = rust_fn_body(src, "fn a(")
    assert body.endswith("if y { z }\n}") and "std::env" not in body, body


def test_no_environment_variable_feeds_the_harrier_pin():
    """The signed lock is the ONLY source of the harrier digest: no env read
    in any function that builds the ref. The registry prefix is the one value
    read from the release environment (NOO_IMAGE_PREFIX, as for every image);
    the content stays fixed by the digest."""
    for path, marker in REF_BUILDERS:
        body = rust_fn_body((ROOT / path).read_text(), marker)
        assert "{" in body and body.rstrip().endswith("}"), (path, marker)
        hits = ENV_READS.findall(body)
        assert not hits, f"{path} {marker} reads the environment: {hits}"
        for var in re.findall(r"release_var\(\"([A-Z_]+)\"\)", body):
            assert var == "NOO_IMAGE_PREFIX", f"{marker} reads {var} from the environment"
    for top in ("noo-cli/src", "scripts", "gateway-rust/src", "node-agent-go", "docs"):
        for p in (ROOT / top).rglob("*"):
            if p.is_file() and p.suffix in {".rs", ".go", ".py", ".sh", ".md", ".yml"}:
                assert "NOO_HARRIER" not in p.read_text(errors="ignore"), p


# ── publish-harrier never overwrites a tag ──────────────────────────────────

def _publish_steps() -> list[dict]:
    return yaml.safe_load(PUBLISH_WF.read_text())["jobs"]["publish"]["steps"]


def _tag_check(tmp_path: Path, docker: str, tag: str = "v2") -> subprocess.CompletedProcess:
    step = next(s for s in _publish_steps() if s.get("name") == "The tag is new")
    env = dict(_fake_docker(tmp_path, docker), IMAGE_TAG=tag)
    return subprocess.run(["bash", "-c", step["run"]], env=env, capture_output=True, text=True)


def test_publish_refuses_a_tag_that_exists(tmp_path):
    r = _tag_check(tmp_path, "echo '{\"schemaVersion\": 2}'; exit 0\n")
    assert r.returncode == 1 and "already exists" in r.stdout, r.stdout
    assert (tmp_path / "docker.log").read_text() == "manifest inspect ghcr.io/noomesh/harrier:v2\n"


def test_publish_goes_on_only_when_the_registry_says_not_found(tmp_path):
    r = _tag_check(tmp_path, "echo 'manifest unknown' >&2; exit 1\n")
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "github.env").read_text() == "REF=ghcr.io/noomesh/harrier:v2\n"
    r = _tag_check(tmp_path, "echo 'unauthorized: authentication required' >&2; exit 1\n")
    assert r.returncode == 1 and "could not tell" in r.stdout, r.stdout


def test_publish_refuses_latest(tmp_path):
    r = _tag_check(tmp_path, "echo 'manifest unknown' >&2; exit 1\n", tag="latest")
    assert r.returncode == 1 and "never published as :latest" in r.stdout, r.stdout


def _publish_step(name: str) -> str:
    return next(s for s in _publish_steps() if s.get("name") == name)["run"]


def test_publish_pushes_one_new_tag_and_never_latest():
    names = [s.get("name") for s in _publish_steps()]
    assert names.index("The tag is new") < names.index("Build + push")
    push = _publish_step("Build + push")
    assert push.count("docker push") == 1 and 'docker push "$REF"' in push
    jobs = PUBLISH_WF.read_text().split("jobs:", 1)[1]
    assert "harrier:latest" not in jobs and "/harrier:$" not in push.replace('"$REF"', "")
    # Dispatch inputs reach the shell through env, never interpolated into it.
    for s in _publish_steps():
        assert "github.event.inputs" not in s.get("run", ""), s.get("name")


def test_publish_names_the_digest_to_pin():
    push = _publish_step("Build + push")
    assert "bump the pinned harrier digest in scripts/harrier-artifact.json to this" in push
    assert push.index("imagetools inspect") < push.index("bump the pinned harrier digest")


def test_publish_keeps_the_sum_check():
    assert "sha256sum -c harrier.sha256" in _publish_step("Fetch the release assets")


def test_publish_workflow_parses_as_bash():
    for s in _publish_steps():
        if "run" in s:
            r = subprocess.run(["bash", "-n", "-c", s["run"]], capture_output=True, text=True)
            assert r.returncode == 0, (s.get("name"), r.stderr)
