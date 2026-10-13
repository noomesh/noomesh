# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Minimal faster-whisper server exposing the OpenAI-compatible audio API.

This is the compose `whisper` service (profile "voice") — the first concrete
provider behind the gateway's generic STT layer (gateway-rust/src/stt_client.rs,
wire format "openai"). Deliberately tiny and auditable instead of pulling a
full model-management stack: one endpoint, one health probe, one model cache.

Endpoints:
  POST /v1/audio/transcriptions  — multipart: file, model, [language],
                                   [response_format=json|text|verbose_json]
  GET  /v1/models                — loaded/loadable models (openai health probe)
  GET  /health                   — liveness

Model names: faster-whisper sizes (tiny/base/small/medium/large-v3, *.en)
or any HuggingFace CTranslate2 repo id. "whisper-1" (the OpenAI cloud name)
maps to WHISPER_MODEL so OpenAI-shaped clients work unchanged.

Env:
  WHISPER_MODEL   default model (default: base) — preloaded at startup
  WHISPER_DEVICE  auto|cpu|cuda (default: auto; cuda needs a CUDA-lib image)
  WHISPER_PRELOAD set to "0" to skip startup preload (load on first request)
"""

from __future__ import annotations

import math
import os
import tempfile
import threading
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse
from faster_whisper import WhisperModel

DEFAULT_MODEL = os.environ.get("WHISPER_MODEL", "base")

app = FastAPI(title="noo-whisper", version="1.0")

_models: dict[str, WhisperModel] = {}
_lock = threading.Lock()


def _device() -> tuple[str, str]:
    dev = os.environ.get("WHISPER_DEVICE", "auto").lower()
    if dev == "cpu":
        return "cpu", "int8"
    if dev == "cuda":
        return "cuda", "float16"
    try:  # auto
        import ctranslate2

        if ctranslate2.get_cuda_device_count() > 0:
            return "cuda", "float16"
    except Exception:
        pass
    return "cpu", "int8"


def _resolve_model_name(requested: Optional[str]) -> str:
    if not requested or requested in ("whisper-1", "default"):
        return DEFAULT_MODEL
    return requested


def _get_model(name: str) -> WhisperModel:
    with _lock:
        if name not in _models:
            device, compute = _device()
            _models[name] = WhisperModel(name, device=device, compute_type=compute)
        return _models[name]


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "models_loaded": sorted(_models.keys())}


@app.get("/v1/models")
def models() -> dict:
    ids = sorted(set(_models.keys()) | {DEFAULT_MODEL})
    return {"object": "list", "data": [{"id": m, "object": "model", "owned_by": "noo-whisper"} for m in ids]}


@app.post("/v1/audio/transcriptions")
async def transcriptions(
    file: UploadFile = File(...),
    model: str = Form(default=""),
    language: str = Form(default=""),
    response_format: str = Form(default="json"),
    temperature: float = Form(default=0.0),
):
    audio = await file.read()
    if not audio:
        raise HTTPException(status_code=400, detail="empty audio file")

    model_name = _resolve_model_name(model)
    try:
        wm = _get_model(model_name)
    except Exception as e:  # unknown model / download failure
        raise HTTPException(status_code=404, detail=f"model {model_name!r} not available: {e}")

    suffix = Path(file.filename or "audio.wav").suffix or ".wav"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(audio)
        tmp_path = Path(tmp.name)
    try:
        # Same decode params as the retired in-process transcriber
        # (src/noomesh/voice/transcription.py) — parity, not invention.
        segments_iter, info = wm.transcribe(
            str(tmp_path),
            language=language or None,
            beam_size=5,
            temperature=temperature,
            vad_filter=True,
            vad_parameters=dict(
                min_speech_duration_ms=100,
                min_silence_duration_ms=300,
                speech_pad_ms=200,
                threshold=0.35,
            ),
        )
        segments = [
            {
                "id": i,
                "start": round(seg.start, 3),
                "end": round(seg.end, 3),
                "text": seg.text,
                "avg_logprob": seg.avg_logprob,
                "no_speech_prob": seg.no_speech_prob,
                "temperature": temperature,
            }
            for i, seg in enumerate(segments_iter)
        ]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"transcription failed: {e}")
    finally:
        tmp_path.unlink(missing_ok=True)

    text = " ".join(s["text"].strip() for s in segments).strip()

    if response_format == "text":
        return PlainTextResponse(text)
    if response_format == "verbose_json":
        return JSONResponse(
            {
                "task": "transcribe",
                "language": info.language,
                "duration": round(info.duration, 3),
                "text": text,
                "segments": segments,
                # Extension field (harmless to OpenAI clients): whisper's
                # language-detection confidence.
                "language_probability": round(info.language_probability, 4),
            }
        )
    return JSONResponse({"text": text})


if os.environ.get("WHISPER_PRELOAD", "1") != "0":  # pragma: no cover
    try:
        _get_model(DEFAULT_MODEL)
    except Exception as e:
        # Don't crash-loop on a cold cache with no network — first request
        # will retry the download.
        print(f"whisper preload of {DEFAULT_MODEL!r} failed (will retry on demand): {e}", flush=True)


def _self_test() -> None:
    """Import-time sanity used by the image build: math only, no model."""
    assert math.isclose(math.exp(0.0), 1.0)


_self_test()
