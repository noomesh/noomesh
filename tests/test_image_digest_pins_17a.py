# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Every third-party base/mirror image source is digest-pinned (followup 17a).

A floating tag means the same commit builds different images on different
days. The parser is scripts/refresh-image-digests.py's, the same one the monthly
refresh uses, so this guard and the refresher cannot disagree about what a
source is. The guard fails CI when any FROM, mirror source, hub-mirror row or
compose third-party image lacks `@sha256:`, unless the source is in
UNPINNABLE with a reason.
"""
from __future__ import annotations

import importlib.util
import re
from collections import defaultdict
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("refresh_image_digests", ROOT / "scripts/refresh-image-digests.py")
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)

SOURCES = R.collect(ROOT)
D1, D2 = "sha256:" + "1" * 64, "sha256:" + "2" * 64

# The ONLY sources allowed to float. Adding one is a decision: say why here.
#   airllm's pytorch base: dhi.io needs a credential to resolve a digest and the
#     image is not mirrored anywhere we can read (TODO in followup 17a).
#   rust:1-bookworm: the CI/dev cargo toolchain; its consumers (four ci.yml jobs,
#     cargo-docker.sh, test_hub_mirror.py) address the row by its text, so pinning
#     it is a wide change of its own (TODO in followup 17a).
#   alpine:latest: `docker run alpine` in workspace-reclaim steps, local image
#     first, deliberately unversioned.
ALLOWED_TO_FLOAT = {
    ("docker/Dockerfile.airllm", "dhi.io/pytorch:2.10-cuda13.0-debian13-dev"),
    (".github/hub-mirror.txt", "library/rust:1-bookworm"),
    (".github/hub-mirror.txt", "library/alpine:latest"),
}


def test_the_parser_found_the_sources_and_every_kind_of_them():
    # Not vacuous: a parser that finds nothing would pass the guard below.
    assert len(SOURCES) >= 50, len(SOURCES)
    kinds = {s.kind for s in SOURCES}
    assert kinds == {"dockerfile", "mirror", "hub-mirror", "compose", "workflow"}, kinds
    for k in kinds:
        assert sum(s.kind == k for s in SOURCES) >= 1, k
    # Spot checks on sources that must be seen, pinned or not.
    seen = {(s.path, s.written) for s in SOURCES}
    assert ("docker/Dockerfile.llamacpp", "${DHI_REGISTRY}/uv:0-debian13-dev") in seen
    assert (".github/workflows/mirror-images.yml", "dhi.io/uv:0-debian13-dev") in seen
    assert ("docker-compose.cluster.yml", "nats:2.14.3") in seen


def test_every_third_party_image_source_is_digest_pinned():
    bad = [f"{s.kind} {s.path}:{s.lineno} {s.written}" for s in R.unpinned(SOURCES)]
    assert not bad, (
        "floating image sources (pin them `tag@sha256:<index digest>`: "
        "scripts/refresh-image-digests.py --pin --new-only; or, if a digest is impossible, "
        "add the source to UNPINNABLE with the reason):\n  " + "\n  ".join(bad))
    for s in SOURCES:
        assert s.digest == "" or re.fullmatch(r"sha256:[0-9a-f]{64}", s.digest), s


def test_the_allowlist_is_explicit_reasoned_and_not_stale():
    assert set(R.UNPINNABLE) == ALLOWED_TO_FLOAT
    live = {(s.path, s.written): s for s in SOURCES}
    for key, why in R.UNPINNABLE.items():
        assert len(why) > 40, f"{key}: say why it cannot be pinned"
        assert key in live, f"{key}: no such source any more, drop it from UNPINNABLE"
        assert not live[key].digest, f"{key}: it is pinned now, drop it from UNPINNABLE"


def test_one_tag_has_one_digest_across_mirror_dockerfile_and_compose():
    # The mirror copies a manifest BY digest, so a FROM / compose pin on the
    # mirrored image is only valid if it names the same digest the mirror source does.
    by_ref = defaultdict(set)
    for s in SOURCES:
        if s.resolve.startswith("dhi.io/") and s.digest:
            by_ref[s.resolve].add(s.digest)
    assert len(by_ref) >= 8, sorted(by_ref)
    split = {k: v for k, v in by_ref.items() if len(v) != 1}
    assert not split, f"the same dhi.io tag is pinned to different digests: {split}"


def test_the_guard_flags_a_floating_from(tmp_path):
    text = ("ARG DHI_REGISTRY=dhi.io\nARG BASE=mwader/static-ffmpeg:7.1\nARG DEPS=noomesh/deps:latest\n"
            "FROM ${DHI_REGISTRY}/uv:0-debian13-dev AS builder\n"
            "FROM ${BASE} AS ff\nFROM ${DEPS}\nFROM builder\nFROM scratch\n"
            "FROM --platform=$BUILDPLATFORM ${DHI_REGISTRY}/golang:1.26@" + D1 + "\n")
    got = R.dockerfile_sources("docker/Dockerfile.x", text)
    assert [(s.written, bool(s.digest)) for s in got] == [
        ("${DHI_REGISTRY}/uv:0-debian13-dev", False),
        ("mwader/static-ffmpeg:7.1", False),     # the ARG default is the source of a bare ${BASE}
        ("${DHI_REGISTRY}/golang:1.26", True),
    ]
    assert [s.resolve for s in got][0] == "dhi.io/uv:0-debian13-dev"
    assert len(R.unpinned(got)) == 2


def test_compose_first_party_is_not_a_source_and_a_bare_tag_is():
    text = ("    image: noomesh/stunnel:latest\n    image: noo-browser:latest\n"
            "    image: ${NOO_IMAGE_PREFIX:?x}/sandbox:${NOO_IMAGE_TAG:-latest}${NOO_IMAGE_DIGEST_SANDBOX:-}\n"
            "    image: nginx:1.27-alpine${NOO_IMAGE_DIGEST_NGINX:-}\n"
            "    image: ${VLLM_IMAGE:-vllm/vllm-openai:v1${NOO_IMAGE_DIGEST_VLLM:-@" + D1 + "}}\n"
            "    image: redis:7\n")
    got = R.compose_sources("docker-compose.x.yml", text)
    assert [(s.written, bool(s.digest), s.slot is not None) for s in got] == [
        ("nginx:1.27-alpine", False, True),
        ("vllm/vllm-openai:v1", True, True),
        ("redis:7", False, False),   # no digest hook: cannot be pinned in place, so it is flagged
    ]


@pytest.mark.parametrize("name, text", [
    ("Dockerfile", "ARG HUB_MIRROR=ghcr.io/noomesh/mirror\nFROM ${HUB_MIRROR}/library/alpine:3.22\n"),
    ("docker-compose.t.yml", "    image: ghcr.io/huggingface/text-embeddings-inference:1.6${NOO_IMAGE_DIGEST_TEI:-}\n"),
    (".github/hub-mirror.txt", "# c\nlibrary/redis:7   consumer\n"),
    (".github/workflows/mirror-images.yml", "      matrix:\n        include:\n          - source: redis:8\n            dest: x\n"),
    (".github/workflows/images-release.yml", '  FFMPEG_UPSTREAM: "docker.io/mwader/static-ffmpeg:7.1"\n'),
])
def test_refresh_pins_and_then_moves_a_reference_in_place(tmp_path, name, text):
    f = tmp_path / name
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text)

    import subprocess
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    assert len(R.collect(tmp_path)) == 1 and not R.collect(tmp_path)[0].digest
    changes, unresolved = R.refresh(tmp_path, R.collect(tmp_path), lambda ref: D1, pin_missing=True)
    assert len(changes) == 1 and not unresolved
    pinned = R.collect(tmp_path)
    assert len(pinned) == 1 and pinned[0].digest == D1 and not R.unpinned(pinned)
    assert f.read_text().count(D1) == 1
    # A refresh moves a pin; --new-only leaves it.
    assert R.refresh(tmp_path, R.collect(tmp_path), lambda ref: D2, pin_missing=True, new_only=True)[0] == []
    changes, _ = R.refresh(tmp_path, R.collect(tmp_path), lambda ref: D2, pin_missing=False)
    assert len(changes) == 1 and D2 in f.read_text() and D1 not in f.read_text()
    # A source that does not resolve is reported and left exactly as it was.
    before = f.read_text()
    def boom(ref):
        raise RuntimeError("401")
    changes, unresolved = R.refresh(tmp_path, R.collect(tmp_path), boom, pin_missing=False)
    assert not changes and len(unresolved) == 1 and f.read_text() == before


def test_the_cli_refuses_to_pass_on_zero_sources(tmp_path, capsys):
    import subprocess
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    assert R.main(["--root", str(tmp_path), "--check"]) == 2


def test_the_monthly_workflow_is_scheduled_dispatchable_minimal_and_pinned():
    text = (ROOT / ".github/workflows/refresh-image-digests.yml").read_text()
    wf = yaml.safe_load(text)
    on = wf.get(True, wf.get("on"))
    assert on["workflow_dispatch"] is None or on["workflow_dispatch"] == {}
    crons = [c["cron"] for c in on["schedule"]]
    assert len(crons) == 1 and re.fullmatch(r"\d+ \d+ \d+ \* \*", crons[0]), crons   # a day of the month: monthly
    assert wf["permissions"] == {"contents": "read"}
    job = wf["jobs"]["refresh"]
    assert job["permissions"] == {"contents": "write", "pull-requests": "write"}
    assert "github.repository == 'noomesh/noomesh'" in job["if"]
    assert "scripts/refresh-image-digests.py" in text and "gh pr create --base dev" in text
    assert "rehearsal" in (ROOT / "scripts/refresh-image-digests.py").read_text()
    for step in job["steps"]:
        if "uses" in step:
            assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", step["uses"]), step["uses"]


def test_the_ffmpeg_mirror_copies_from_the_pinned_upstream():
    text = (ROOT / ".github/workflows/images-release.yml").read_text()
    assert re.search(r'FFMPEG_UPSTREAM: "docker.io/mwader/static-ffmpeg:7\.1@sha256:[0-9a-f]{64}"', text)
    assert '"$FFMPEG_UPSTREAM"' in text and "docker.io/mwader/static-ffmpeg:$FFMPEG_VERSION" not in text
