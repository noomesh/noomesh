# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Voice transcription and TTS for Mesh."""

try:
    from .transcription import VoiceTranscriber, quick_transcribe, FASTER_WHISPER_AVAILABLE

    WHISPER_AVAILABLE = FASTER_WHISPER_AVAILABLE
except ImportError:
    WHISPER_AVAILABLE = False
    FASTER_WHISPER_AVAILABLE = False

try:
    from .tts import (
        TextToSpeech,
        PiperTTS,
        EdgeTTS,
        speak,
        TTS_AVAILABLE,
        PIPER_AVAILABLE,
        EDGE_TTS_AVAILABLE,
    )
except ImportError:
    TTS_AVAILABLE = False
    PIPER_AVAILABLE = False
    EDGE_TTS_AVAILABLE = False

__all__ = [
    "VoiceTranscriber",
    "quick_transcribe",
    "WHISPER_AVAILABLE",
    "FASTER_WHISPER_AVAILABLE",
    "TextToSpeech",
    "PiperTTS",
    "EdgeTTS",
    "speak",
    "TTS_AVAILABLE",
    "PIPER_AVAILABLE",
    "EDGE_TTS_AVAILABLE",
]
