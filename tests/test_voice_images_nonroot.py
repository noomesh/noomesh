# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The voice add-on: non-root images, models staged by the controller and
loaded offline (i105).

1. `ghcr.io/noomesh/whisper` and `piper` had no USER line: `docker run --rm
   --entrypoint id` printed uid=0 on v0.6.4, so the mTLS leaves the voice
   doors gained in #125 went to a root reader. Both Dockerfiles now create
   `nonroot` (65532:65532, the DHI convention) and end `USER nonroot`; the
   key reader table follows (noo-cli pki.rs) and `noo cluster verify
   --controller` → `voice images` judges the live uid.
2. The controller stages everything: whisper used to build
   `WhisperModel("base")` (a huggingface_hub download) and piper called
   `download_voice` on first use. Now `noo models pull whisper:<size>` /
   `piper:<voice>` (noo-cli voice_models.rs) stage them under
   `<MODELS_DIR>/voice/{whisper,piper}`; compose mounts those READ-ONLY at
   the dirs the servers load from, runs both offline with no HF token, and
   there is no writable model volume. A model that is not staged raises
   `voice_local.NotStaged`, naming the pull line (a 404).
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "docker-compose.voice.yml"
MODELS = "${MODELS_DIR:-${NOO_DATA_ROOT:?NOO_DATA_ROOT is not set - run noo onboard --only storage or set it in .env}/models}"
# image -> (Dockerfile, server, env var naming the load dir, that dir, the staged source)
IMAGES = {
    "whisper": ("docker/Dockerfile.whisper", "docker/whisper_server.py", "WHISPER_MODEL_DIR", "/models", f"{MODELS}/voice/whisper"),
    "piper": ("docker/Dockerfile.piper", "docker/piper_server.py", "PIPER_VOICE_DIR", "/voices", f"{MODELS}/voice/piper"),
}

sys.path.insert(0, str(ROOT / "docker"))
import voice_local  # noqa: E402  (docker/voice_local.py: stdlib only)


def _instructions(path: str) -> list[tuple[str, str]]:
    """(INSTRUCTION, args) pairs, continuation lines joined, comments dropped."""
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


def _services() -> dict:
    return yaml.safe_load(OVERLAY.read_text())["services"]


def _env(svc: dict) -> dict[str, str]:
    return dict(str(e).split("=", 1) for e in svc.get("environment", []))


# ── 1. non-root ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", sorted(IMAGES))
def test_the_image_ends_as_a_named_non_root_user(name):
    ins = _instructions(IMAGES[name][0])
    users = [args for word, args in ins if word == "USER"]
    assert users, f"{name}: no USER line: the image runs as root (i105)"
    assert users[-1] == "nonroot", f"{name}: final USER is {users[-1]!r}, want the named nonroot"
    words = [w for w, _ in ins]
    last_user = len(words) - 1 - words[::-1].index("USER")
    assert words.index("CMD") > last_user, "USER must precede the CMD"


@pytest.mark.parametrize("name", sorted(IMAGES))
def test_nonroot_is_65532(name):
    runs = [a for w, a in _instructions(IMAGES[name][0]) if w == "RUN" and "useradd" in a]
    assert runs, f"{name}: nonroot is never created"
    assert re.search(r"groupadd --gid 65532 nonroot", runs[0]), runs[0]
    assert re.search(r"useradd --uid 65532 --gid 65532 [^&]*\bnonroot( &&|$)", runs[0]), runs[0]


@pytest.mark.parametrize("name", sorted(IMAGES))
def test_the_cmd_and_healthcheck_are_unchanged(name):
    ins = dict(_instructions(IMAGES[name][0]))
    assert ins["CMD"] == f'["uvicorn", "{name}_server:app", "--host", "0.0.0.0", "--port", "8000"]'
    assert "http://127.0.0.1:8000/health" in ins["HEALTHCHECK"]


@pytest.mark.parametrize("name", sorted(IMAGES))
def test_compose_pins_no_numeric_user(name):
    user = str(_services()[name].get("user", ""))
    assert not user or not user.split(":")[0].strip().isdigit(), f"{name}: numeric user {user!r} (breaks Docker 27)"


# ── 2. staged, read-only, offline ───────────────────────────────────────


@pytest.mark.parametrize("name", sorted(IMAGES))
def test_the_image_loads_from_the_mount_point_offline_with_no_volume(name):
    dockerfile, _, env, wdir, _ = IMAGES[name]
    ins = _instructions(dockerfile)
    envs = " ".join(a for w, a in ins if w == "ENV")
    assert re.search(rf"\b{env}={re.escape(wdir)}\b", envs), envs
    for flag in ("HF_HUB_OFFLINE=1", "TRANSFORMERS_OFFLINE=1"):
        assert flag in envs, f"{name}: the image is not offline by default ({flag})"
    # Nothing writes a model: no VOLUME (an anonymous writable cache), no chown.
    assert not [a for w, a in ins if w == "VOLUME"], f"{name}: a VOLUME is a writable model cache"
    assert not [a for w, a in ins if w == "RUN" and "chown" in a], f"{name}: chowns a model dir nothing should write"
    assert "COPY docker/voice_local.py /app/voice_local.py" in [f"COPY {a}" for w, a in ins if w == "COPY"]


@pytest.mark.parametrize("name", sorted(IMAGES))
def test_compose_mounts_the_staged_models_read_only_and_runs_offline(name):
    _, _, env, wdir, source = IMAGES[name]
    svc = _services()[name]
    vols = [str(v) for v in svc["volumes"]]
    assert f"{source}:{wdir}:ro" in vols, vols
    # The only non-TLS mount is that read-only one: no writable model volume.
    other = [v for v in vols if "/tls/" not in v]
    assert other == [f"{source}:{wdir}:ro"], other
    e = _env(svc)
    assert e.get(env) == wdir, e
    assert e.get("HF_HUB_OFFLINE") == "1" and e.get("TRANSFORMERS_OFFLINE") == "1", e
    # No token: nothing here talks to Hugging Face.
    assert not [k for k in e if "HUGGING_FACE" in k or k == "HF_TOKEN"], e


def test_no_voice_model_volume_is_declared_any_more():
    vols = yaml.safe_load((ROOT / "docker-compose.cluster.yml").read_text())["volumes"]
    assert "piper-voices" not in vols and "whisper-models" not in vols, sorted(vols)
    assert "volumes" not in yaml.safe_load(OVERLAY.read_text()), "the overlay declares a volume"


def test_the_launcher_creates_the_mount_sources_when_voice_runs():
    start = (ROOT / "scripts" / "noomesh-start.sh").read_text()
    assert 'mkdir -p "$models/voice/whisper" "$models/voice/piper"' in start
    # Both start paths call it, before their bind-source check.
    calls = [m.start() for m in re.finditer(r"\n\s+noo_voice_model_dirs\n", start)]
    checks = [m.start() for m in re.finditer(r"check_bind_sources ", start)]
    assert len(calls) == 2, calls
    assert all(any(c < k for k in checks) for c in calls), (calls, checks)


def _code_names(path: str) -> set[str]:
    """Every name and attribute the module's CODE uses (docstrings excluded)."""
    tree = ast.parse((ROOT / path).read_text())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
            names.update(a.name for a in node.names)
    return names


def test_piper_has_no_download_path():
    names = _code_names("docker/piper_server.py")
    assert "download_voice" not in names and "piper.download_voices" not in names, sorted(n for n in names if "download" in n)
    assert "piper_voice_files" in names


def test_whisper_loads_only_a_staged_directory():
    src = (ROOT / "docker/whisper_server.py").read_text()
    tree = ast.parse(src)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "WhisperModel"]
    assert len(calls) == 1, "one construction site"
    call = calls[0]
    # The first argument is the staged path, never the requested name.
    assert ast.unparse(call.args[0]) == "str(path)", ast.unparse(call)
    kw = {k.arg: ast.unparse(k.value) for k in call.keywords}
    assert kw.get("local_files_only") == "True", kw
    assert "path = whisper_model_dir(MODEL_DIR, name)" in src


# ── voice_local: the one place the servers resolve a model ──────────────


def _whisper_dir(root: Path, name: str, files=voice_local.WHISPER_REQUIRED) -> Path:
    d = root / name
    d.mkdir(parents=True)
    for f in files:
        (d / f).write_text("x")
    return d


def test_a_staged_whisper_model_resolves_to_its_directory(tmp_path):
    d = _whisper_dir(tmp_path, "base")
    assert voice_local.whisper_model_dir(tmp_path, "base") == d
    r = _whisper_dir(tmp_path, "org--my-ct2")
    assert voice_local.whisper_model_dir(tmp_path, "org/my-ct2") == r, "a repo id maps / -> --, like the CLI"
    assert voice_local.staged_whisper_models(tmp_path) == ["base", "org--my-ct2"]


def test_a_missing_whisper_model_names_the_pull(tmp_path):
    with pytest.raises(voice_local.NotStaged) as e:
        voice_local.whisper_model_dir(tmp_path, "small")
    assert "noo models pull whisper:small" in str(e.value)
    assert "never download" in str(e.value)
    # Weights without a tokenizer would make faster-whisper fetch one.
    _whisper_dir(tmp_path, "tiny", files=("model.bin", "config.json"))
    with pytest.raises(voice_local.NotStaged, match="tokenizer.json"):
        voice_local.whisper_model_dir(tmp_path, "tiny")


def test_a_staged_piper_voice_resolves_to_its_pair(tmp_path):
    (tmp_path / "en_US-lessac-medium.onnx").write_text("x")
    (tmp_path / "en_US-lessac-medium.onnx.json").write_text("{}")
    m, c = voice_local.piper_voice_files(tmp_path, "en_US-lessac-medium")
    assert (m.name, c.name) == ("en_US-lessac-medium.onnx", "en_US-lessac-medium.onnx.json")


def test_a_missing_piper_voice_names_the_pull(tmp_path):
    (tmp_path / "en_GB-alba-medium.onnx").write_text("x")  # no sidecar config
    with pytest.raises(voice_local.NotStaged) as e:
        voice_local.piper_voice_files(tmp_path, "en_GB-alba-medium")
    assert "noo models pull piper:en_GB-alba-medium" in str(e.value)
    assert "en_GB-alba-medium.onnx.json" in str(e.value)


@pytest.mark.parametrize("bad", ["", "..", "../etc", "a/../b", ".hidden", "a\\b", " base"])
def test_a_name_that_could_leave_the_staged_root_is_refused(tmp_path, bad):
    with pytest.raises(voice_local.NotStaged):
        voice_local.whisper_model_dir(tmp_path, bad)
    with pytest.raises(voice_local.NotStaged):
        voice_local.piper_voice_files(tmp_path, bad)


def test_voice_local_imports_nothing_that_reaches_the_network():
    mods = {n.module for n in ast.walk(ast.parse((ROOT / "docker/voice_local.py").read_text())) if isinstance(n, ast.ImportFrom)}
    mods |= {a.name for n in ast.walk(ast.parse((ROOT / "docker/voice_local.py").read_text())) if isinstance(n, ast.Import) for a in n.names}
    assert mods <= {"__future__", "pathlib"}, mods
