# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Where noo-whisper and noo-piper find their models: staged files only.

The controller stages everything (i105): the voice containers never fetch
from Hugging Face. `noo models pull whisper:<size>` / `piper:<voice>` (also
run by `noo addons enable voice`, `noo upgrade --stack` and onboard when
voice is on) downloads, verifies and lays the files out under the
controller's model store (`<MODELS_DIR>/voice/{whisper,piper}`), which
compose mounts READ-ONLY at WHISPER_MODEL_DIR (/models) and PIPER_VOICE_DIR
(/voices). This module only answers "where is it" or raises NotStaged with
the exact command; it imports nothing that can reach the network, so the
servers and the tests share it without faster-whisper or piper installed.

Layout (the CLI's noo-cli/src/commands/voice_models.rs writes the same):
  <WHISPER_MODEL_DIR>/<name, '/' -> '--'>/{model.bin, config.json,
                                           tokenizer.json, vocabulary.*,
                                           [preprocessor_config.json]}
  <PIPER_VOICE_DIR>/<voice>.onnx, <voice>.onnx.json
"""

from __future__ import annotations

from pathlib import Path

# The files faster-whisper cannot load a CTranslate2 model without.
WHISPER_REQUIRED = ("model.bin", "config.json", "tokenizer.json")


class NotStaged(RuntimeError):
    """The model or voice is not among the controller's staged files."""


def safe_name(name: str) -> str:
    """The directory/file stem for a model name: a repo id's `/` becomes
    `--` (the HF cache convention). Anything that could leave the staged
    root — a caller-supplied name reaches here from a form field — is
    refused, never resolved."""
    n = (name or "").strip()
    s = n.replace("/", "--")
    if not s or s.startswith(".") or ".." in s or "\\" in s or "\0" in s or s != s.strip():
        raise NotStaged(f"{name!r} is not a model name")
    return s


def whisper_model_dir(root: Path, name: str) -> Path:
    """The staged CTranslate2 directory for whisper model `name`."""
    d = Path(root) / safe_name(name)
    missing = [f for f in WHISPER_REQUIRED if not (d / f).is_file()]
    if missing:
        raise NotStaged(
            f"whisper model {name!r} is not staged on the controller "
            f"({d} has no {', '.join(missing)}); the voice containers never download. "
            f"Stage it on the controller: noo models pull whisper:{name}"
        )
    return d


def piper_voice_files(root: Path, name: str) -> tuple[Path, Path]:
    """The staged (model, config) pair for piper voice `name`."""
    stem = safe_name(name)
    model = Path(root) / f"{stem}.onnx"
    config = Path(root) / f"{stem}.onnx.json"
    missing = [p.name for p in (model, config) if not p.is_file()]
    if missing:
        raise NotStaged(
            f"piper voice {name!r} is not staged on the controller "
            f"({Path(root)} has no {', '.join(missing)}); the voice containers never download. "
            f"Stage it on the controller: noo models pull piper:{name}"
        )
    return model, config


def staged_whisper_models(root: Path) -> list[str]:
    """Directory names under `root` that hold a loadable model."""
    r = Path(root)
    if not r.is_dir():
        return []
    return sorted(d.name for d in r.iterdir() if d.is_dir() and all((d / f).is_file() for f in WHISPER_REQUIRED))
