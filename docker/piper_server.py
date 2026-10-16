# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Minimal Piper server exposing the OpenAI-compatible speech API.

This is the compose `piper` service (profile "voice") — the first concrete
provider behind the gateway's generic TTS layer (gateway-rust/src/tts_client.rs,
wire format "openai"). Deliberately tiny and auditable instead of pulling a
full model-management stack: two synthesis endpoints, one inventory, one
health probe, no downloads. Twin of docker/whisper_server.py.

Endpoints:
  POST /v1/audio/speech   — json: {model, input, voice, speed,
                            [response_format=wav|pcm]} → audio bytes
  POST /synthesize        — json: {text, voice, speed} → audio bytes
                            (the native shape the pre-provider gateway proxy
                            spoke; tts_client wire format "piper")
  GET  /v1/audio/voices   — installed voice inventory (openai clients)
  GET  /voices            — same inventory (piper wire format)
  GET  /v1/models         — loaded/loadable voices (openai health probe)
  GET  /health            — liveness

Voice names are piper voice ids (e.g. en_US-lessac-medium). Voices are
loaded ONLY from the controller's staged files (i105): compose mounts
`<MODELS_DIR>/voice/piper` read-only at PIPER_VOICE_DIR and sets
HF_HUB_OFFLINE=1. A voice that is not staged is a 404 naming
`noo models pull piper:<voice>` (docker/voice_local.py); this server never
calls piper's download_voice. "tts-1"/"tts-1-hd"/"default" (the OpenAI cloud
model names) map to PIPER_VOICE so OpenAI-shaped clients work unchanged.

Only WAV/PCM come out: piper synthesises PCM and this image ships no mp3
encoder. Clients asking for another response_format get 400 rather than a
mislabelled body.

Env:
  PIPER_VOICE      default voice (default: en_US-lessac-medium) — preloaded
  PIPER_VOICE_DIR  staged voices, read-only (default: /voices)
  PIPER_PRELOAD    set to "0" to skip startup preload (load on first request)
  PIPER_USE_CUDA   set to "1" to run onnxruntime on GPU (needs a CUDA image)
"""

from __future__ import annotations

import io
import json
import os
import threading
import wave
from pathlib import Path
from typing import Optional

from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import JSONResponse, Response
from piper import PiperVoice, SynthesisConfig

from voice_local import NotStaged, piper_voice_files

DEFAULT_VOICE = os.environ.get("PIPER_VOICE", "en_US-lessac-medium")
VOICE_DIR = Path(os.environ.get("PIPER_VOICE_DIR", "/voices"))
USE_CUDA = os.environ.get("PIPER_USE_CUDA", "0") == "1"

# OpenAI cloud model names that mean "whatever this server's default is".
_ALIASES = {"tts-1", "tts-1-hd", "default", "piper", ""}

app = FastAPI(title="noo-piper", version="1.0")

_voices: dict[str, PiperVoice] = {}
_lock = threading.Lock()


def _resolve_voice_name(requested: Optional[str]) -> str:
    if not requested or requested.strip().lower() in _ALIASES:
        return DEFAULT_VOICE
    return requested.strip()


def _get_voice(name: str) -> PiperVoice:
    """Load a staged piper voice, cached in-process. Raises NotStaged."""
    with _lock:
        if name not in _voices:
            model_path, _config = piper_voice_files(VOICE_DIR, name)
            # The config is the `<voice>.onnx.json` beside it (piper's default).
            _voices[name] = PiperVoice.load(model_path, use_cuda=USE_CUDA)
        return _voices[name]


def _installed_voices() -> list[dict]:
    """Inventory of voices actually present in the cache — never a catalogue
    of what could hypothetically be downloaded. Metadata comes from each
    voice's sidecar `<voice>.onnx.json` config."""
    out: list[dict] = []
    if not VOICE_DIR.is_dir():
        return out
    for model in sorted(VOICE_DIR.glob("*.onnx")):
        name = model.stem
        language, quality, description = "", "", f"Piper voice: {name}"
        cfg_path = model.with_suffix(".onnx.json")
        if cfg_path.is_file():
            try:
                cfg = json.loads(cfg_path.read_text())
                language = (cfg.get("language") or {}).get("code", "") or ""
                quality = (cfg.get("audio") or {}).get("quality", "") or ""
                dataset = cfg.get("dataset") or ""
                if dataset:
                    description = f"Piper voice: {dataset} ({language})"
            except Exception:  # malformed sidecar — report the name anyway
                pass
        if not language and "-" in name:
            language = name.split("-", 1)[0]
        entry = {
            "name": name,
            "language": language,
            "description": description,
            "backend": "piper",
        }
        if quality:
            entry["quality"] = quality
        out.append(entry)
    return out


def _synthesize_wav(text: str, voice_name: str, speed: float) -> bytes:
    """Synthesize to WAV bytes. `speed` is a rate multiplier: piper's
    length_scale is its inverse, exactly as the retired in-process PiperTTS
    computed it (src/noomesh/voice/tts.py)."""
    try:
        voice = _get_voice(voice_name)
    except NotStaged as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:  # a staged voice that will not load
        raise HTTPException(status_code=404, detail=f"voice {voice_name!r} not available: {e}")

    syn = SynthesisConfig(length_scale=(1.0 / speed) if speed > 0 else 1.0)
    buf = io.BytesIO()
    try:
        with wave.open(buf, "wb") as wav:
            voice.synthesize_wav(text, wav, syn_config=syn)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"synthesis failed: {e}")
    audio = buf.getvalue()
    if not audio:
        raise HTTPException(status_code=422, detail="synthesis produced no audio")
    return audio


def _validated_speed(raw) -> float:
    try:
        speed = float(raw)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="speed must be a number")
    if not 0.25 <= speed <= 4.0:
        raise HTTPException(status_code=400, detail="speed must be between 0.25 and 4.0")
    return speed


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "backend": "piper",
        "default_voice": DEFAULT_VOICE,
        "voices_loaded": sorted(_voices.keys()),
    }


@app.get("/v1/models")
def models() -> dict:
    ids = sorted({v["name"] for v in _installed_voices()} | {DEFAULT_VOICE})
    return {
        "object": "list",
        "data": [{"id": m, "object": "model", "owned_by": "noo-piper"} for m in ids],
    }


@app.get("/voices")
@app.get("/v1/audio/voices")
def voices() -> dict:
    return {"voices": _installed_voices()}


@app.post("/v1/audio/speech")
def speech(body: dict = Body(...)):
    """OpenAI-compatible: {model, input, voice, speed, response_format}."""
    text = (body.get("input") or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="'input' cannot be empty")
    fmt = (body.get("response_format") or "wav").lower()
    if fmt not in ("wav", "pcm"):
        raise HTTPException(
            status_code=400,
            detail=f"response_format {fmt!r} unsupported — this server emits wav/pcm only",
        )
    speed = _validated_speed(body.get("speed", 1.0))
    # `voice` names the piper voice; `model` is accepted as a fallback so an
    # OpenAI client that only sets `model` still selects one.
    name = _resolve_voice_name(body.get("voice") or body.get("model"))
    audio = _synthesize_wav(text, name, speed)
    if fmt == "pcm":
        # Strip the 44-byte canonical RIFF header piper writes.
        return Response(
            content=audio[44:],
            media_type="audio/pcm",
            headers={"X-TTS-Backend": "piper", "X-TTS-Voice": name},
        )
    return Response(
        content=audio,
        media_type="audio/wav",
        headers={"X-TTS-Backend": "piper", "X-TTS-Voice": name},
    )


@app.post("/synthesize")
def synthesize(body: dict = Body(...)):
    """Native shape: {text, voice, speed} (tts_client wire format "piper")."""
    text = (body.get("text") or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="'text' cannot be empty")
    speed = _validated_speed(body.get("speed", 1.0))
    name = _resolve_voice_name(body.get("voice"))
    audio = _synthesize_wav(text, name, speed)
    return Response(
        content=audio,
        media_type="audio/wav",
        headers={"X-TTS-Backend": "piper", "X-TTS-Voice": name},
    )


@app.exception_handler(HTTPException)
def _http_error(_request, exc: HTTPException) -> JSONResponse:
    # JSON error bodies, never a 200 with an audio content-type — the
    # gateway's TTS client rejects JSON-wearing-audio on purpose.
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})


if os.environ.get("PIPER_PRELOAD", "1") != "0":  # pragma: no cover
    try:
        _get_voice(DEFAULT_VOICE)
    except Exception as e:
        # Don't crash-loop on a voice that is not staged yet — the first
        # request after `noo models pull piper:<voice>` loads it.
        print(f"piper preload of {DEFAULT_VOICE!r} failed (will retry on demand): {e}", flush=True)
