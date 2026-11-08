# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The ollama convert/staging directory works for the non-root image (0.6.16 rc.2).

Since #558 the hardened Ollama image runs as uid 65532 with a root-owned `/`, so
`mkdir -p /convert` failed and a fresh install got no harrier embedder. Three
code paths stage a Modelfile + weight inside the container: onboard's harrier
step (noo-cli), `scripts/noo-model-convert.sh`, and node-agent-go's
`ollamaCreateInContainer`. One directory, under the user's own store, serves
all three; this pins that they agree and that it is not a root-level path.

The docker test at the bottom runs the real mkdir/copy/read sequence as
`--user 65532`. It is opt-in (NOO_DOCKER_USER_TEST=1, set only by a CI job
that has docker) and skips cleanly without docker.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONVERT_DIR = "/home/nonroot/.ollama/convert"


def _read(rel: str) -> str:
    return (ROOT / rel).read_text()


def _image_user() -> str:
    users = re.findall(r"^USER\s+(\S+)", _read("docker/Dockerfile.ollama"), re.M)
    assert users, "Dockerfile.ollama has no USER"
    return users[-1]


def _image_home() -> str:
    m = re.search(r"HOME=(\S+)", _read("docker/Dockerfile.ollama"))
    assert m, "Dockerfile.ollama sets no HOME"
    return m.group(1)


def test_image_is_non_root_and_the_convert_dir_is_under_its_home():
    assert _image_user().split(":")[0] == "65532"
    assert CONVERT_DIR.startswith(_image_home() + "/.ollama/")


def test_shell_script_uses_the_shared_dir_and_no_root_level_path():
    sh = _read("scripts/noo-model-convert.sh")
    assert f"OLLAMA_CONVERT_DIR={CONVERT_DIR}" in sh
    for line in sh.splitlines():
        if line.lstrip().startswith("#"):
            continue
        assert not re.search(r"(^|[\s:\"'])/convert\b", line), line


def test_rust_const_matches():
    rs = _read("noo-cli/src/onboard/steps.rs")
    m = re.search(r'const OLLAMA_CONVERT_DIR: &str = "([^"]+)"', rs)
    assert m and m.group(1) == CONVERT_DIR
    prod = rs.split("// rc.2 (0.6.16): the hardened ollama image")[0]  # not its own guard test
    assert not re.search(r'"[^"\n]*[\s:]/convert\b', prod), "a root-level /convert is back in steps.rs"


def test_go_const_derives_from_the_store_constant():
    go = _read("node-agent-go/internal/docker/ollama_model.go")
    store = re.search(r'ollamaOursStore\s*=\s*"([^"]+)"', _read("node-agent-go/internal/docker/ollama_store.go"))
    assert store and store.group(1) == "/home/nonroot/.ollama"
    assert 'const convertDir = ollamaOursStore + "/convert"' in go
    assert "CopyUIDGID: true" in go


@pytest.mark.skipif(
    shutil.which("docker") is None or os.environ.get("NOO_DOCKER_USER_TEST") != "1",
    reason="needs docker and NOO_DOCKER_USER_TEST=1 (docker-capable CI job only)",
)
def test_real_sequence_as_uid_65532():
    """mkdir under the user's store, copy in as root, read and remove as 65532."""
    name = f"noo-convert-dir-test-{os.getpid()}"
    img = "busybox:1.37"
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "w.gguf"
        f.write_text("weights")
        f.chmod(0o644)

        def d(*a, check=True):
            return subprocess.run(["docker", *a], capture_output=True, text=True, check=check)

        try:
            # A root-owned `/` plus a volume-like store the user owns.
            d("run", "-d", "--name", name, "--user", "65532:65532", "--read-only",
              "--tmpfs", "/home/nonroot/.ollama:uid=65532,gid=65532", img, "sleep", "60")
            assert d("exec", name, "mkdir", "-p", "/convert", check=False).returncode != 0
            d("exec", name, "sh", "-c", f"rm -rf {CONVERT_DIR} && mkdir -p {CONVERT_DIR}")
            d("cp", str(f), f"{name}:{CONVERT_DIR}/w.gguf")
            assert d("exec", name, "cat", f"{CONVERT_DIR}/w.gguf").stdout == "weights"
            d("exec", name, "rm", "-rf", CONVERT_DIR)
            assert d("exec", name, "test", "!", "-e", CONVERT_DIR, check=False).returncode == 0
        finally:
            d("rm", "-f", name, check=False)


def _pick(tmp_path: Path, running: list[str]) -> subprocess.CompletedProcess:
    """Run the script's own `pick_ollama_container` against a fake `docker ps`."""
    sh = _read("scripts/noo-model-convert.sh")
    m = re.search(r"^pick_ollama_container\(\) \{\n.*?^\}\n", sh, re.M | re.S)
    assert m, "noo-model-convert.sh lost pick_ollama_container"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "docker"
    names = "".join(f"{n}\\n" for n in running)
    fake.write_text(f"#!/bin/sh\n[ \"$1\" = ps ] && printf '{names}'\n")
    fake.chmod(0o755)
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}
    return subprocess.run(
        ["bash", "-c", m.group(0) + "pick_ollama_container"],
        capture_output=True, text=True, env=env, check=False,
    )


def test_the_standalone_embed_container_is_found(tmp_path):
    # i545 finding 55: a standalone box runs only noo-ollama-embed, and the
    # script used to look for noo-ollama alone and stop at "GGUF is ready".
    r = _pick(tmp_path, ["noo-gateway", "noo-ollama-embed"])
    assert r.returncode == 0 and r.stdout.strip() == "noo-ollama-embed", r


def test_the_full_ollama_wins_when_both_run(tmp_path):
    r = _pick(tmp_path, ["noo-ollama-embed", "noo-ollama"])
    assert r.returncode == 0 and r.stdout.strip() == "noo-ollama", r


def test_no_ollama_container_is_none(tmp_path):
    r = _pick(tmp_path, ["noo-gateway", "noo-ollama-embed-old"])
    assert r.returncode == 1 and r.stdout.strip() == "", r


def test_the_create_branch_uses_the_picked_container():
    sh = _read("scripts/noo-model-convert.sh")
    branch = sh.split("    container)\n", 1)[1].split(";;", 1)[0]
    assert "docker exec noo-ollama " not in branch and '"$OLLAMA_CTR"' in branch, branch
