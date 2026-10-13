# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Voice transcription with faster-whisper (CTranslate2)."""
from __future__ import annotations

import math
import tempfile
from pathlib import Path
from typing import Optional

import structlog

log = structlog.get_logger(__name__)

try:
    from faster_whisper import WhisperModel

    FASTER_WHISPER_AVAILABLE = True
except ImportError:
    FASTER_WHISPER_AVAILABLE = False

# Keep backwards-compatible alias
WHISPER_AVAILABLE = FASTER_WHISPER_AVAILABLE


def _detect_device() -> tuple[str, str]:
    """Detect best available device. Returns (device, compute_type)."""
    try:
        import torch

        if torch.cuda.is_available():
            log.info("whisper_device_detected", device="cuda")
            return "cuda", "float16"
    except ImportError:
        pass
    try:
        import ctranslate2

        if "cuda" in ctranslate2.get_supported_compute_types("cuda"):
            log.info("whisper_device_detected", device="cuda")
            return "cuda", "float16"
    except Exception:
        pass
    log.info("whisper_device_detected", device="cpu")
    return "cpu", "int8"


class VoiceTranscriber:
    """Voice transcription using faster-whisper (CTranslate2).

    Much faster than OpenAI's whisper, with GPU acceleration support.

    Models (by size/accuracy):
    - tiny / tiny.en: Fastest, least accurate
    - base / base.en: Good balance
    - small / small.en: Better accuracy
    - medium / medium.en: High accuracy
    - large-v3: Best accuracy, slowest
    """

    def __init__(
        self,
        model_name: str = "base",
        device: Optional[str] = None,
        compute_type: Optional[str] = None,
    ):
        if not FASTER_WHISPER_AVAILABLE:
            raise ImportError(
                "faster-whisper not available. Install with: "
                "pip install 'noomesh[voice]'"
            )
        self.model_name = model_name
        auto_device, auto_compute = _detect_device()
        self.device = device or auto_device
        self.compute_type = compute_type or auto_compute
        self._model: Optional[WhisperModel] = None

    def _load_model(self) -> WhisperModel:
        if self._model is None:
            log.info(
                "whisper_model_loading",
                model=self.model_name,
                device=self.device,
                compute_type=self.compute_type,
            )
            self._model = WhisperModel(
                self.model_name,
                device=self.device,
                compute_type=self.compute_type,
            )
            log.info("whisper_model_loaded", model=self.model_name)
        return self._model

    def transcribe(
        self,
        audio_file: str | Path,
        language: Optional[str] = None,
        task: str = "transcribe",
    ) -> dict:
        """Transcribe audio file to text.

        Args:
            audio_file: Path to audio file (wav, mp3, webm, ogg, m4a, etc.)
            language: Source language code (e.g. "en"). None = auto-detect.
            task: "transcribe" or "translate" (translate to English).

        Returns:
            dict with keys: text, language, confidence, segments, duration
        """
        model = self._load_model()
        segments_iter, info = model.transcribe(
            str(audio_file),
            language=language,
            task=task,
            beam_size=5,
            vad_filter=True,
            vad_parameters=dict(
                min_speech_duration_ms=100,   # detect short utterances
                min_silence_duration_ms=300,   # don't split on brief pauses
                speech_pad_ms=200,             # pad around detected speech
                threshold=0.35,                # lower = more sensitive
            ),
        )
        segments = []
        full_text_parts = []
        for seg in segments_iter:
            segments.append(
                {
                    "start": seg.start,
                    "end": seg.end,
                    "text": seg.text.strip(),
                    "avg_logprob": seg.avg_logprob,
                }
            )
            full_text_parts.append(seg.text.strip())

        text = " ".join(full_text_parts)
        confidence = 0.0
        if segments:
            avg_logprob = sum(s["avg_logprob"] for s in segments) / len(segments)
            confidence = round(math.exp(avg_logprob), 4)

        return {
            "text": text,
            "language": info.language,
            "confidence": confidence,
            "language_probability": round(info.language_probability, 4),
            "duration": round(info.duration, 2),
            "segments": segments,
        }

    def transcribe_with_timestamps(
        self,
        audio_file: str | Path,
        language: Optional[str] = None,
    ) -> list[dict]:
        """Transcribe with segment-level timestamps."""
        result = self.transcribe(audio_file, language=language)
        return result["segments"]

    def transcribe_bytes(
        self,
        audio_bytes: bytes,
        format: str = "wav",
        language: Optional[str] = None,
    ) -> dict:
        """Transcribe audio from raw bytes.

        Returns:
            dict with keys: text, language, confidence, duration
        """
        with tempfile.NamedTemporaryFile(suffix=f".{format}", delete=False) as tmp:
            tmp.write(audio_bytes)
            tmp_path = Path(tmp.name)
        try:
            return self.transcribe(tmp_path, language=language)
        finally:
            tmp_path.unlink(missing_ok=True)

    def detect_language(self, audio_file: str | Path) -> dict:
        """Detect language of audio file."""
        model = self._load_model()
        _, info = model.transcribe(str(audio_file), beam_size=1)
        return {
            "language": info.language,
            "probability": round(info.language_probability, 4),
        }


def quick_transcribe(audio_file: str | Path, model: str = "base") -> str:
    """Quick transcription -- returns text only."""
    t = VoiceTranscriber(model_name=model)
    return t.transcribe(audio_file)["text"]
