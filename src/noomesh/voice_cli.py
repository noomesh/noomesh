# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""CLI commands for voice transcription and TTS (noo voice ...)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from .cli_utils import (
    console,
    fatal,
    is_json_output,
    output_json,
    print_info,
    print_success,
)

voice_app = typer.Typer(
    help="\U0001f399\ufe0f [dim]Voice transcription & TTS[/]",
    rich_markup_mode="rich",
)


@voice_app.command("transcribe")
def voice_transcribe(
    audio_file: Path = typer.Argument(
        ..., help="Path to audio file (wav, mp3, webm, ogg, m4a)."
    ),
    model: str = typer.Option(
        "base", help="Whisper model: tiny, base, small, medium, large-v3."
    ),
    language: Optional[str] = typer.Option(
        None, help="Source language code (e.g. en, es). Auto-detect if omitted."
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Save transcription to file."
    ),
    timestamps: bool = typer.Option(
        False, "--timestamps", help="Include segment timestamps."
    ),
    device: Optional[str] = typer.Option(
        None, help="Device: cuda or cpu. Auto-detect if omitted."
    ),
) -> None:
    """\U0001f3a4 [bold]Transcribe[/] an audio file with faster-whisper."""
    try:
        from .voice.transcription import VoiceTranscriber
    except ImportError:
        fatal(
            "faster-whisper not installed. Install with: pip install 'noomesh[voice]'"
        )

    if not audio_file.exists():
        fatal(f"File not found: {audio_file}")

    import contextlib

    ctx = (
        contextlib.nullcontext()
        if is_json_output()
        else console.status(f"Transcribing with faster-whisper ({model})...")
    )
    try:
        with ctx:
            transcriber = VoiceTranscriber(model_name=model, device=device)
            result = transcriber.transcribe(str(audio_file), language=language)
    except ImportError as e:
        fatal(str(e))

    if timestamps:
        lines = [
            f"[{s['start']:.2f}s - {s['end']:.2f}s] {s['text']}"
            for s in result.get("segments", [])
        ]
        text = "\n".join(lines)
    else:
        text = result["text"]

    if output:
        output.write_text(text)

    if is_json_output():
        payload = {
            "text": result["text"],
            "language": result.get("language"),
            "confidence": result.get("confidence"),
            "duration": result.get("duration"),
        }
        if timestamps:
            payload["segments"] = result.get("segments", [])
        if output:
            payload["saved_to"] = str(output)
        output_json(payload)
        return

    lang = result.get("language", "?")
    conf = result.get("confidence", 0)
    dur = result.get("duration", 0)
    print_info(f"Language: {lang}  Confidence: {conf:.2%}  Duration: {dur:.1f}s")

    if output:
        print_success(f"Saved to {output}")
    else:
        console.print(text)


@voice_app.command("synthesize")
def voice_synthesize(
    text: str = typer.Argument(..., help="Text to synthesize."),
    output: Path = typer.Option(
        ..., "--output", "-o", help="Output audio file path."
    ),
    backend: Optional[str] = typer.Option(
        None, help="TTS backend: piper or edge. Auto-select if omitted."
    ),
    voice: Optional[str] = typer.Option(
        None, help="Voice name (backend-specific)."
    ),
    speed: float = typer.Option(1.0, help="Speed multiplier (0.5 - 2.0)."),
) -> None:
    """\U0001f50a [bold]Synthesize[/] speech from text and save to file."""
    try:
        from .voice.tts import TextToSpeech
    except ImportError:
        fatal(
            "No TTS backend available. Install with: pip install 'noomesh[voice]'"
        )

    import contextlib

    ctx = (
        contextlib.nullcontext()
        if is_json_output()
        else console.status("Synthesizing speech...")
    )
    try:
        with ctx:
            tts = TextToSpeech(backend=backend, voice=voice, speed=speed)
            audio_bytes, content_type = tts.synthesize_bytes_sync(text)
    except ImportError as e:
        fatal(str(e))

    ext = "wav" if "wav" in content_type else "mp3"
    out = output.with_suffix(f".{ext}") if not output.suffix else output
    out.write_bytes(audio_bytes)
    if is_json_output():
        output_json(
            {
                "status": "ok",
                "output": str(out),
                "bytes": len(audio_bytes),
                "backend": tts.active_backend,
                "content_type": content_type,
            }
        )
    else:
        print_success(
            f"Saved {len(audio_bytes):,} bytes to {out} (backend: {tts.active_backend})"
        )


@voice_app.command("speak")
def voice_speak(
    text: str = typer.Argument(..., help="Text to speak."),
    backend: Optional[str] = typer.Option(
        None, help="TTS backend: piper or edge."
    ),
    speed: float = typer.Option(1.0, help="Speed multiplier."),
) -> None:
    """\U0001f50a [bold]Speak[/] text using TTS (plays audio)."""
    try:
        from .voice.tts import speak
    except ImportError:
        fatal(
            "No TTS backend available. Install with: pip install 'noomesh[voice]'"
        )
    try:
        speak(text, speed=speed, backend=backend)
    except ImportError as e:
        fatal(str(e))
    if is_json_output():
        output_json({"status": "ok", "action": "speak"})


@voice_app.command("voices")
def voice_list_voices(
    backend: Optional[str] = typer.Option(
        None, help="Filter by backend: piper or edge."
    ),
) -> None:
    """\U0001f4cb List available [bold]TTS voices[/]."""
    try:
        from .voice.tts import TextToSpeech
    except ImportError:
        fatal(
            "No TTS backend available. Install with: pip install 'noomesh[voice]'"
        )

    try:
        tts = TextToSpeech(backend=backend)
    except ImportError as e:
        fatal(str(e))
    voices = tts.get_available_voices()

    if backend:
        voices = [v for v in voices if v.get("backend") == backend]

    if is_json_output():
        output_json({"voices": voices, "count": len(voices)})
        return

    console.print(f"Available voices ({len(voices)}):")
    for v in voices[:50]:
        console.print(
            f"  [{v.get('backend', '?')}] {v['name']} "
            f"({v.get('language', '?')}) {v.get('gender', '')}"
        )
    if len(voices) > 50:
        console.print(f"  ... and {len(voices) - 50} more")


@voice_app.command("status")
def voice_status() -> None:
    """\U0001f4ca Show voice system [bold]status[/] (STT + TTS backends)."""
    from rich.table import Table

    try:
        from .voice.transcription import FASTER_WHISPER_AVAILABLE
    except ImportError:
        FASTER_WHISPER_AVAILABLE = False

    try:
        from .voice.tts import PIPER_AVAILABLE, EDGE_TTS_AVAILABLE
    except ImportError:
        PIPER_AVAILABLE = False
        EDGE_TTS_AVAILABLE = False

    if is_json_output():
        payload = {
            "stt": {"faster_whisper": FASTER_WHISPER_AVAILABLE},
            "tts": {"piper": PIPER_AVAILABLE, "edge": EDGE_TTS_AVAILABLE},
        }
        if FASTER_WHISPER_AVAILABLE:
            try:
                from .voice.transcription import _detect_device

                device, compute = _detect_device()
                payload["stt"]["device"] = device
                payload["stt"]["compute_type"] = compute
            except Exception:
                pass
        output_json(payload)
        return

    table = Table(title="Voice System Status")
    table.add_column("Component", style="bold")
    table.add_column("Backend")
    table.add_column("Status")

    def _status(available: bool) -> str:
        return "[green]available[/green]" if available else "[red]not installed[/red]"

    table.add_row("STT", "faster-whisper", _status(FASTER_WHISPER_AVAILABLE))
    table.add_row("TTS (primary)", "piper-tts", _status(PIPER_AVAILABLE))
    table.add_row("TTS (fallback)", "edge-tts", _status(EDGE_TTS_AVAILABLE))

    console.print(table)

    if not (FASTER_WHISPER_AVAILABLE or PIPER_AVAILABLE or EDGE_TTS_AVAILABLE):
        print_info("Install voice support: pip install 'noomesh[voice]'")

    if FASTER_WHISPER_AVAILABLE:
        try:
            from .voice.transcription import _detect_device

            device, compute = _detect_device()
            console.print(f"  STT device: {device} ({compute})")
        except Exception:
            pass
