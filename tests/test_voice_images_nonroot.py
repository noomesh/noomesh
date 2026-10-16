# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The voice add-on's images run as uid 65532, never root (i105).

`ghcr.io/noomesh/whisper` and `piper` had no USER line: `docker run --rm
--entrypoint id` printed uid=0 on v0.6.4, so the mTLS leaves the voice doors
gained in #125 went to a root reader. Both Dockerfiles now create `nonroot`
(65532:65532, the DHI convention), hand it the one directory each server
writes (whisper: HF_HOME=/models; piper: PIPER_VOICE_DIR=/voices) BEFORE the
VOLUME line, and end `USER nonroot`. The key reader table follows (noo-cli
pki.rs), and `noo cluster verify --controller` → `voice images` judges the
live uid. Static pins here; the live proof is the rc rehearsal with voice ON.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "docker-compose.voice.yml"
# image -> (Dockerfile, the env var naming the dir it writes, that dir, its volume)
IMAGES = {
    "whisper": ("docker/Dockerfile.whisper", "HF_HOME", "/models", "whisper-models"),
    "piper": ("docker/Dockerfile.piper", "PIPER_VOICE_DIR", "/voices", "piper-voices"),
}


def _instructions(path: str) -> list[tuple[str, str]]:
    """(INSTRUCTION, args) pairs with continuation lines joined, comments dropped."""
    out: list[tuple[str, str]] = []
    buf = ""
    for raw in (ROOT / path).read_text().splitlines():
        line = raw.strip()
        if not buf and (not line or line.startswith("#")):
            continue
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        word, _, rest = " ".join(buf.split()).partition(" ")
        out.append((word.upper(), rest))
        buf = ""
    assert out, f"{path}: no instructions parsed"
    return out


@pytest.mark.parametrize("name", sorted(IMAGES))
def test_the_image_ends_as_a_named_non_root_user(name):
    ins = _instructions(IMAGES[name][0])
    users = [args for word, args in ins if word == "USER"]
    assert users, f"{name}: no USER line: the image runs as root (i105)"
    assert users[-1] == "nonroot", f"{name}: final USER is {users[-1]!r}, want the named nonroot"
    # USER is set before the CMD (so the CMD and every `docker exec` run as it).
    words = [w for w, _ in ins]
    assert words.index("CMD") > len(words) - 1 - words[::-1].index("USER"), words


@pytest.mark.parametrize("name", sorted(IMAGES))
def test_nonroot_is_65532_and_owns_the_written_dir_before_its_volume(name):
    dockerfile, env, wdir, _ = IMAGES[name]
    ins = _instructions(dockerfile)
    runs = [(i, a) for i, (w, a) in enumerate(ins) if w == "RUN"]
    create = [(i, a) for i, a in runs if "useradd" in a]
    assert create, f"{name}: nonroot is never created"
    i, a = create[0]
    assert re.search(r"groupadd --gid 65532 nonroot", a), a
    assert re.search(r"useradd --uid 65532 --gid 65532 [^&]*\bnonroot( &&|$)", a), a
    assert re.search(rf"chown 65532:65532 {re.escape(wdir)}(\s|$)", a), f"{name} never hands {wdir} to 65532: {a}"
    # The dir the server writes IS the chowned dir, and the volume comes AFTER
    # the chown (Docker discards changes to a path after its VOLUME line).
    envs = " ".join(a for w, a in ins if w == "ENV")
    assert re.search(rf"\b{env}={re.escape(wdir)}\b", envs), envs
    vol = [j for j, (w, a) in enumerate(ins) if w == "VOLUME" and a == wdir]
    assert vol and vol[0] > i, f"{name}: VOLUME {wdir} must follow the chown"


@pytest.mark.parametrize("name", sorted(IMAGES))
def test_the_cmd_and_healthcheck_are_unchanged(name):
    ins = dict((w, a) for w, a in _instructions(IMAGES[name][0]))
    assert ins["CMD"] == f'["uvicorn", "{name}_server:app", "--host", "0.0.0.0", "--port", "8000"]'
    assert "http://127.0.0.1:8000/health" in ins["HEALTHCHECK"]


@pytest.mark.parametrize("name", sorted(IMAGES))
def test_compose_pins_no_user_and_mounts_the_own_volume(name):
    svc = yaml.safe_load(OVERLAY.read_text())["services"][name]
    # The image's USER decides; a numeric `user:` breaks Docker 27
    # (tests/test_compose_named_users.py), a named one would only restate it.
    user = str(svc.get("user", ""))
    assert not user or not user.split(":")[0].strip().isdigit(), f"{name}: numeric user {user!r}"
    _, _, wdir, volume = IMAGES[name]
    vols = [str(v) for v in svc["volumes"]]
    assert f"{volume}:{wdir}" in vols, vols
    # hf-cache is the operator's data-root dir (vLLM/TEI and host tooling
    # write it): it cannot be handed to 65532, so whisper no longer mounts it.
    assert not any(v.startswith("hf-cache:") for v in vols), vols


def test_the_voice_volumes_are_declared_plain_in_the_base_file():
    vols = yaml.safe_load((ROOT / "docker-compose.cluster.yml").read_text())["volumes"]
    for _, _, _, volume in IMAGES.values():
        # Plain (no bind driver_opts): a fresh one is copied up from the
        # image, owned by 65532 already.
        assert volume in vols and not vols[volume], (volume, vols.get(volume))


def test_the_launcher_re_owns_exactly_these_volumes():
    lib = (ROOT / "scripts" / "lib-reown.sh").read_text()
    for name, (_, _, _, volume) in IMAGES.items():
        assert re.search(rf"{name}\) echo {volume} ;;", lib), f"reown_volume_of does not map {name} -> {volume}"
    start = (ROOT / "scripts" / "noomesh-start.sh").read_text()
    calls = re.findall(r"reown_nonroot_volumes .*grep -xE '([^']+)'", start)
    assert calls == ["whisper|piper", "whisper|piper"], calls  # both start paths
