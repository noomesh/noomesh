# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Hardened llama.cpp (arm64) and Ollama images, noomesh-internal i323 decision 3.

The release builds `llamacpp` and `ollama` for BOTH architectures; the Ollama
image is the pinned upstream release tarball verified by sha256; the lock row
`ollama` is OUR image ; the node agent's upstream refs are fallbacks only.
"""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github/workflows/images-release.yml"
DOCKERFILE = (ROOT / "docker/Dockerfile.ollama").read_text()
COMPOSE = (ROOT / "docker-compose.cluster.yml").read_text()
BACKENDS = (ROOT / "node-agent-go/internal/docker/backends.go").read_text()

# From the ollama/ollama v0.40.5 release's sha256sum.txt (gh release download).
PIN = {
    "version": "0.40.5",
    "amd64": "dc5eabc292f9949546c90a97c820f924b035e05243b0de13c7f366182562169c",
    "arm64": "fbe71ebb1a10e59b8480c4d2839826b5f9dff1a6d5c142428b2e7db9b1a2c642",
}


def _row(name: str) -> dict:
    wf = yaml.safe_load(WF.read_text())
    for r in wf["jobs"]["images"]["strategy"]["matrix"]["include"]:
        if r.get("name") == name:
            return r
    raise AssertionError(f"no {name} row in the images matrix")


def _third_party():
    spec = importlib.util.spec_from_file_location("slt", ROOT / "scripts/stack-lock-third-party.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_llamacpp_and_ollama_are_built_for_both_arches():
    for name in ("llamacpp", "ollama"):
        r = _row(name)
        assert set(r["platforms"].split(",")) == {"linux/amd64", "linux/arm64"}, (name, r["platforms"])
        assert r["image"] == name and (ROOT / r["dockerfile"]).is_file()
    assert _row("ollama")["dockerfile"] == "docker/Dockerfile.ollama"
    # stunnel stays the precedent for a two-arch row.
    assert _row("stunnel")["platforms"] == _row("llamacpp")["platforms"]


def test_the_llamacpp_dockerfile_has_nothing_amd64_only():
    text = (ROOT / "docker/Dockerfile.llamacpp").read_text()
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    assert "-DGGML_NATIVE=OFF" in code, "a portable build, not -march=native"
    for x86 in ("-mavx", "-mfma", "-msse", "GGML_AVX", "GGML_AMX", "x86_64", "amd64", "-m64"):
        assert x86 not in code, f"x86-only flag/arch {x86!r} in a Dockerfile that now builds for arm64"
    assert "-DGGML_CUDA" not in code
    # The base is the same multi-arch DHI uv image the arm64 rows already build on.
    assert "${DHI_REGISTRY}/uv:0-debian13-dev" in code


def test_dockerfile_ollama_verifies_a_sha256_per_arch():
    assert "sha256sum -c" in DOCKERFILE, "the tarball must be verified, not just downloaded"
    assert re.search(r"ARG OLLAMA_VERSION=" + re.escape(PIN["version"]) + r"\b", DOCKERFILE)
    for arch in ("AMD64", "ARM64"):
        m = re.search(rf"ARG OLLAMA_SHA256_{arch}=([0-9a-f]+)", DOCKERFILE)
        assert m and len(m.group(1)) == 64, arch
        assert m.group(1) == PIN[arch.lower()], f"{arch}: not the v{PIN['version']} release sha256"
    assert "TARGETARCH" in DOCKERFILE and "--platform=$BUILDPLATFORM" in DOCKERFILE
    assert "releases/download/v${OLLAMA_VERSION}/" in DOCKERFILE and "latest" not in DOCKERFILE.replace("# ", "").split("FROM", 1)[1]
    # The same runtime contract as upstream ollama/ollama, which the agent's spec relies on.
    for need in ("OLLAMA_HOST=0.0.0.0:11434", "EXPOSE 11434", 'ENTRYPOINT ["/usr/bin/ollama"]', 'CMD ["serve"]', "/root/.ollama"):
        assert need in DOCKERFILE, need
    assert "NVIDIA_VISIBLE_DEVICES=all" in DOCKERFILE and "/usr/lib/ollama/" in DOCKERFILE


def test_the_ollama_pin_is_one_version_in_the_dockerfile_and_the_agent_fallback():
    assert f'upstreamOllamaImage   = "ollama/ollama:{PIN["version"]}"' in BACKENDS


def test_the_ollama_lock_row_is_ours_and_every_compose_ollama_runs_it():
    m = _third_party()
    assert "ollama" not in m.THIRD_PARTY, "the `ollama` lock row is OUR image, not an upstream pin"
    inputs = json.loads((ROOT / "scripts/release-image-inputs.json").read_text())["images"]
    assert inputs["ollama"]["dockerfile"] == "docker/Dockerfile.ollama"
    ours = "${OLLAMA_IMAGE:-${NOO_IMAGE_PREFIX:-noomesh}/ollama:${NOO_IMAGE_TAG:-latest}${NOO_IMAGE_DIGEST_OLLAMA:-}}"
    svcs = yaml.safe_load(COMPOSE)["services"]
    for n in ("ollama", "ollama-embed", "ollama-embed-cpu"):
        assert svcs[n]["image"] == ours, n
    assert "- NOO_BACKEND_IMAGE_OLLAMA=" + ours in COMPOSE


def test_the_agent_defaults_are_ours_with_upstream_only_as_the_fallback():
    assert "func hardenedDefault(" in BACKENDS and "func ensureImageWithFallback(" in BACKENDS
    assert "var ns *ImageNotStagedError" in BACKENDS
    # The arm branch that sent ARM nodes to upstream is gone.
    body = BACKENDS[BACKENDS.index("func llamacppDefaultImage()"):BACKENDS.index("func ollamaDefaultImage()")]
    assert "GOARCH" not in body
    # (d) the retired local-name lookup is deleted.
    assert "pai-assistant/llamacpp:%s" not in BACKENDS and "using hardened llamacpp build" not in BACKENDS
