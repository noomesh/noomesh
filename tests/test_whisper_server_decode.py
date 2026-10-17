# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""docker/whisper_server.py's transcribe path, through the REAL decode.

The model is faked (no weights in CI), but the fake does what
WhisperModel.transcribe does first with a path — it calls faster-whisper's
own `decode_audio` — so the PyAV API the image pins is exercised for real.
That is the call stack 0.6.5 broke: av 19.0.1 dropped
`av.open(metadata_errors=)`, decode_audio passes it, and every
POST /v1/audio/transcriptions became 422 `transcription failed: open() got an
unexpected keyword argument 'metadata_errors'`. Against av 19.0.1 this test
fails with exactly that 422; against the pinned av it passes.

CI installs faster-whisper, av and python-multipart at the versions
docker/Dockerfile.whisper pins (.github/workflows/ci.yml), so this does not
skip there (tests/_ci_skip_guard.py would fail the session if it did).
"""

from __future__ import annotations

import importlib
import io
import math
import struct
import sys
import wave
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]

fw_transcribe = pytest.importorskip("faster_whisper.transcribe")
pytest.importorskip("multipart")
from fastapi.testclient import TestClient  # noqa: E402


def sine_wav(seconds: float = 1.0, rate: int = 16000) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(b"".join(
            struct.pack("<h", int(8000 * math.sin(2 * math.pi * 440 * i / rate))) for i in range(int(seconds * rate))
        ))
    return buf.getvalue()


class DecodingFakeModel:
    """WhisperModel's first step with a path, for real; then one segment."""

    def __init__(self) -> None:
        self.samples = None

    def transcribe(self, audio, **_kw):
        # The same name WhisperModel.transcribe calls (faster_whisper/transcribe.py).
        decoded = fw_transcribe.decode_audio(audio, sampling_rate=16000)
        self.samples = len(decoded)
        seg = SimpleNamespace(start=0.0, end=len(decoded) / 16000, text=" a tone", avg_logprob=-0.1, no_speech_prob=0.9)
        info = SimpleNamespace(language="en", duration=len(decoded) / 16000, language_probability=0.5)
        return iter([seg]), info


@pytest.fixture()
def server(monkeypatch):
    monkeypatch.setenv("WHISPER_PRELOAD", "0")
    monkeypatch.syspath_prepend(str(ROOT / "docker"))
    sys.modules.pop("whisper_server", None)
    mod = importlib.import_module("whisper_server")
    fake = DecodingFakeModel()
    monkeypatch.setattr(mod, "_get_model", lambda _name: fake)
    yield mod, fake
    sys.modules.pop("whisper_server", None)


def test_transcribe_decodes_a_real_wav_through_the_pinned_av(server) -> None:
    mod, fake = server
    r = TestClient(mod.app).post(
        "/v1/audio/transcriptions",
        files={"file": ("tone.wav", sine_wav(), "audio/wav")},
        data={"model": "base", "response_format": "verbose_json"},
    )
    assert r.status_code == 200, f"transcribe path failed ({r.status_code}): {r.text}"
    assert fake.samples == 16000, f"decode_audio returned {fake.samples} samples for a 1 s 16 kHz WAV"
    body = r.json()
    assert body["text"] == "a tone"
    assert body["duration"] == 1.0


def test_an_undecodable_upload_is_a_422_not_a_crash(server) -> None:
    mod, _ = server
    r = TestClient(mod.app).post(
        "/v1/audio/transcriptions",
        files={"file": ("junk.wav", b"not audio at all", "audio/wav")},
        data={"model": "base"},
    )
    assert r.status_code == 422
    assert r.json()["detail"].startswith("transcription failed:")
