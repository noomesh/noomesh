# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The voice images resolve nothing at build time.

Stack 0.6.5 shipped a whisper image whose PyAV floated: faster-whisper 1.1.1
declares `av>=11`, the build resolved av 19.0.1, which dropped
`metadata_errors` from av.open(), and every transcription became a 422
(`open() got an unexpected keyword argument 'metadata_errors'`). Nobody
changed a line; the resolver did. So every `pip install` in the two voice
Dockerfiles must name each package with an exact `==` pin AND pass
`--no-deps` (a transitive dep is otherwise still resolved), and the av pin
must stay below 19.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILES = ["docker/Dockerfile.whisper", "docker/Dockerfile.piper"]

_REQ = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*==[0-9][0-9A-Za-z.+!-]*$")


def pip_installs(text: str) -> list[list[str]]:
    """Each `pip install` command's tokens, continuation lines joined,
    stopped at the next shell operator."""
    joined = re.sub(r"\\\n", " ", text)
    out = []
    for line in joined.splitlines():
        for m in re.finditer(r"pip3? install\b(.*)", line):
            toks = []
            for t in m.group(1).split():
                if t in ("&&", "||", ";", "|"):
                    break
                toks.append(t.strip("\"'"))
            out.append(toks)
    return out


def unpinned(tokens: list[str]) -> list[str]:
    return [t for t in tokens if not t.startswith("-") and not _REQ.match(t)]


@pytest.mark.parametrize("rel", DOCKERFILES)
def test_every_pip_install_is_exactly_pinned_with_no_deps(rel: str) -> None:
    installs = pip_installs((ROOT / rel).read_text())
    assert installs, f"{rel}: no `pip install` found — the parse is wrong, not the file clean"
    for toks in installs:
        pkgs = [t for t in toks if not t.startswith("-")]
        assert pkgs, f"{rel}: a pip install names no package: {toks}"
        assert not unpinned(toks), f"{rel}: unpinned requirement(s) {unpinned(toks)} — pin with =="
        assert "--no-deps" in toks, f"{rel}: pip install without --no-deps resolves transitive deps at build time"


def test_whisper_pins_an_av_that_accepts_metadata_errors() -> None:
    text = (ROOT / "docker/Dockerfile.whisper").read_text()
    m = re.search(r"\bav==(\d+)\.", text)
    assert m, "Dockerfile.whisper must pin av explicitly — it is the dep that broke STT"
    assert int(m.group(1)) < 19, "av>=19 dropped av.open(metadata_errors=) which faster_whisper decode_audio passes"


def test_the_guard_catches_a_floating_line() -> None:
    bad = 'RUN pip install --no-cache-dir \\\n    faster-whisper==1.1.1 \\\n    "fastapi>=0.115,<0.116" requests\n'
    (toks,) = pip_installs(bad)
    assert unpinned(toks) == ["fastapi>=0.115,<0.116", "requests"]
    assert "--no-deps" not in toks
