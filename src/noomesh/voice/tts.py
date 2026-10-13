# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Text-to-speech synthesis with Piper (local) and edge-tts (fallback)."""
from __future__ import annotations

import asyncio
import io
import tempfile
import wave
from pathlib import Path
from typing import AsyncIterator, Optional

import structlog

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Import guards
# ---------------------------------------------------------------------------

try:
    from piper import PiperVoice

    PIPER_AVAILABLE = True
except ImportError:
    PIPER_AVAILABLE = False

try:
    import edge_tts

    EDGE_TTS_AVAILABLE = True
except ImportError:
    EDGE_TTS_AVAILABLE = False

TTS_AVAILABLE = PIPER_AVAILABLE or EDGE_TTS_AVAILABLE


# ---------------------------------------------------------------------------
# Piper TTS (local, fast, runs on CPU/Pi)
# ---------------------------------------------------------------------------


class PiperTTS:
    """Local TTS using piper-tts. Lightweight, MIT-licensed, CPU-friendly."""

    def __init__(
        self,
        model_path: Optional[str] = None,
        voice_name: str = "en_US-lessac-medium",
        speaker_id: Optional[int] = None,
    ):
        if not PIPER_AVAILABLE:
            raise ImportError(
                "piper-tts not available. Install with: pip install piper-tts"
            )
        self.voice_name = voice_name
        self.speaker_id = speaker_id
        self._voice: Optional[PiperVoice] = None
        self._model_path = model_path

    def _load_voice(self) -> PiperVoice:
        if self._voice is None:
            if self._model_path:
                self._voice = PiperVoice.load(self._model_path)
            else:
                from piper.download import ensure_voice_exists, find_voice, get_voices

                data_dir = Path.home() / ".local" / "share" / "piper" / "voices"
                data_dir.mkdir(parents=True, exist_ok=True)
                voices_info = get_voices(str(data_dir), update_voices=True)
                ensure_voice_exists(
                    self.voice_name, data_dir, data_dir, voices_info
                )
                model_path, config_path = find_voice(self.voice_name, data_dir)
                self._voice = PiperVoice.load(
                    str(model_path), config_path=str(config_path)
                )
            log.info("piper_voice_loaded", voice=self.voice_name)
        return self._voice

    def synthesize_to_bytes(self, text: str, speed: float = 1.0) -> bytes:
        """Synthesize text to WAV bytes."""
        voice = self._load_voice()
        buf = io.BytesIO()
        with wave.open(buf, "wb") as wav:
            voice.synthesize(
                text,
                wav,
                speaker_id=self.speaker_id,
                length_scale=1.0 / speed if speed > 0 else 1.0,
            )
        return buf.getvalue()

    def synthesize_to_file(
        self, text: str, output_path: str | Path, speed: float = 1.0
    ) -> Path:
        """Synthesize text and save to WAV file."""
        audio = self.synthesize_to_bytes(text, speed=speed)
        out = Path(output_path)
        out.write_bytes(audio)
        log.info("piper_synthesized", output=str(out), size=len(audio))
        return out

    def synthesize_stream(self, text: str, speed: float = 1.0, chunk_size: int = 4096):
        """Yield WAV audio in chunks for streaming responses."""
        audio = self.synthesize_to_bytes(text, speed=speed)
        offset = 0
        while offset < len(audio):
            yield audio[offset : offset + chunk_size]
            offset += chunk_size

    @staticmethod
    def list_voices() -> list[dict]:
        """List available Piper voice models."""
        if not PIPER_AVAILABLE:
            return []
        try:
            from piper.download import get_voices

            data_dir = Path.home() / ".local" / "share" / "piper" / "voices"
            data_dir.mkdir(parents=True, exist_ok=True)
            voices_info = get_voices(str(data_dir), update_voices=False)
            results = []
            for name, info in voices_info.items():
                results.append(
                    {
                        "name": name,
                        "language": info.get("language", {}).get("code", ""),
                        "quality": (
                            list(info.get("files", {}).keys())[0]
                            if info.get("files")
                            else ""
                        ),
                        "description": info.get("description", ""),
                        "backend": "piper",
                    }
                )
            return results
        except Exception as e:
            log.warning("piper_list_voices_failed", error=str(e))
            return []


# ---------------------------------------------------------------------------
# Edge TTS (free Microsoft API, no GPU needed, good quality)
# ---------------------------------------------------------------------------


class EdgeTTS:
    """Cloud TTS fallback using Microsoft Edge's free TTS API."""

    def __init__(self, voice: str = "en-US-AriaNeural"):
        if not EDGE_TTS_AVAILABLE:
            raise ImportError(
                "edge-tts not available. Install with: pip install edge-tts"
            )
        self.voice = voice

    async def synthesize_to_bytes(self, text: str, speed: float = 1.0) -> bytes:
        """Synthesize text to MP3 bytes."""
        rate_pct = int((speed - 1.0) * 100)
        rate_str = f"{rate_pct:+d}%"
        communicate = edge_tts.Communicate(text, self.voice, rate=rate_str)
        buf = io.BytesIO()
        async for chunk in communicate.stream():
            if chunk["type"] == "audio":
                buf.write(chunk["data"])
        return buf.getvalue()

    async def synthesize_to_file(
        self, text: str, output_path: str | Path, speed: float = 1.0
    ) -> Path:
        """Synthesize text and save to MP3 file."""
        audio = await self.synthesize_to_bytes(text, speed=speed)
        out = Path(output_path)
        out.write_bytes(audio)
        log.info("edge_tts_synthesized", output=str(out), size=len(audio))
        return out

    async def synthesize_stream(
        self, text: str, speed: float = 1.0
    ) -> AsyncIterator[bytes]:
        """Yield MP3 audio chunks as they arrive from the API."""
        rate_pct = int((speed - 1.0) * 100)
        rate_str = f"{rate_pct:+d}%"
        communicate = edge_tts.Communicate(text, self.voice, rate=rate_str)
        async for chunk in communicate.stream():
            if chunk["type"] == "audio":
                yield chunk["data"]

    @staticmethod
    async def list_voices() -> list[dict]:
        """List available Edge TTS voices."""
        if not EDGE_TTS_AVAILABLE:
            return []
        voices = await edge_tts.list_voices()
        return [
            {
                "name": v["ShortName"],
                "language": v.get("Locale", ""),
                "gender": v.get("Gender", ""),
                "description": v.get("FriendlyName", ""),
                "backend": "edge-tts",
            }
            for v in voices
        ]


# ---------------------------------------------------------------------------
# Unified TTS interface (auto-selects best available backend)
# ---------------------------------------------------------------------------


class TextToSpeech:
    """Unified TTS that picks the best available backend.

    Priority: Piper (local) > Edge TTS (cloud fallback).
    """

    def __init__(
        self,
        backend: Optional[str] = None,
        voice: Optional[str] = None,
        speed: float = 1.0,
    ):
        self.speed = speed
        self._piper: Optional[PiperTTS] = None
        self._edge: Optional[EdgeTTS] = None

        if backend == "piper" or (backend is None and PIPER_AVAILABLE):
            try:
                self._piper = PiperTTS(
                    voice_name=voice or "en_US-lessac-medium"
                )
                self.active_backend = "piper"
                return
            except Exception as e:
                log.warning("piper_init_failed_falling_back", error=str(e))

        if backend == "edge" or (backend is None and EDGE_TTS_AVAILABLE):
            self._edge = EdgeTTS(voice=voice or "en-US-AriaNeural")
            self.active_backend = "edge-tts"
            return

        raise ImportError(
            "No TTS backend available. Install with: "
            "pip install 'noomesh[voice]'"
        )

    def synthesize_bytes_sync(self, text: str) -> tuple[bytes, str]:
        """Synchronous synthesis. Returns (audio_bytes, content_type)."""
        if self._piper:
            return self._piper.synthesize_to_bytes(text, speed=self.speed), "audio/wav"
        if self._edge:
            audio = asyncio.run(
                self._edge.synthesize_to_bytes(text, speed=self.speed)
            )
            return audio, "audio/mpeg"
        raise RuntimeError("No TTS backend initialized")

    async def synthesize_bytes(self, text: str) -> tuple[bytes, str]:
        """Async synthesis. Returns (audio_bytes, content_type)."""
        if self._piper:
            audio = self._piper.synthesize_to_bytes(text, speed=self.speed)
            return audio, "audio/wav"
        if self._edge:
            audio = await self._edge.synthesize_to_bytes(text, speed=self.speed)
            return audio, "audio/mpeg"
        raise RuntimeError("No TTS backend initialized")

    async def synthesize_stream(self, text: str):
        """Async streaming synthesis. Returns (async_iterator, content_type)."""
        if self._piper:

            async def _gen():
                for chunk in self._piper.synthesize_stream(
                    text, speed=self.speed
                ):
                    yield chunk

            return _gen(), "audio/wav"
        if self._edge:
            return (
                self._edge.synthesize_stream(text, speed=self.speed),
                "audio/mpeg",
            )
        raise RuntimeError("No TTS backend initialized")

    def get_available_voices(self) -> list[dict]:
        """List voices from all available backends."""
        voices = []
        if PIPER_AVAILABLE:
            voices.extend(PiperTTS.list_voices())
        if EDGE_TTS_AVAILABLE:
            try:
                edge_voices = asyncio.run(EdgeTTS.list_voices())
                voices.extend(edge_voices)
            except Exception:
                pass
        return voices


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------


def speak(
    text: str, speed: float = 1.0, backend: Optional[str] = None
) -> None:
    """Quick speak: synthesize and play audio."""
    tts = TextToSpeech(backend=backend, speed=speed)
    audio_bytes, content_type = tts.synthesize_bytes_sync(text)
    ext = "wav" if "wav" in content_type else "mp3"
    with tempfile.NamedTemporaryFile(suffix=f".{ext}", delete=False) as f:
        f.write(audio_bytes)
        tmp_path = f.name
    log.info(
        "tts_audio_saved",
        path=tmp_path,
        size=len(audio_bytes),
        backend=tts.active_backend,
    )
    try:
        import subprocess
        import sys

        if sys.platform == "darwin":
            subprocess.run(["afplay", tmp_path], check=True)
        elif sys.platform.startswith("linux"):
            cmd = ["aplay", tmp_path] if ext == "wav" else ["mpg123", tmp_path]
            subprocess.run(cmd, check=True)
        elif sys.platform == "win32":
            import os

            os.startfile(tmp_path)
    except Exception as e:
        log.warning("audio_playback_failed", error=str(e), path=tmp_path)
    finally:
        Path(tmp_path).unlink(missing_ok=True)
