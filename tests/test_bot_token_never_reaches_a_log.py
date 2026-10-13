# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""A Telegram request error must be scrubbed before it becomes text.

The bot token lives in the request PATH, and a `reqwest` error renders the URL
it failed on. So every site that stringified such an error wrote the token into
the journal in full. `telegram_poll_error` did it on every failed poll, and a
502 from Telegram is routine, so the live controller's log held the token many
times over (2026-09-12).

That token is the bot's password: it reads the chat and posts as the bot. A
`docker logs` dump is pasted freely during an incident, which is exactly when
this would be handed to somebody.

This check is static and runs in the Python job, so it needs no gateway and
cannot be silenced by the code it is about.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
GW = REPO / "gateway-rust/src"

# Every file that builds a Telegram API URL. A new one is in scope the moment
# it does, which is why this is derived rather than listed.
TELEGRAM_URL = re.compile(r"api\.telegram\.org/bot\{")


def _files_calling_telegram() -> list[Path]:
    out = []
    for p in GW.rglob("*.rs"):
        if TELEGRAM_URL.search(p.read_text()):
            out.append(p)
    return out


def test_there_is_a_telegram_call_site_to_guard():
    files = _files_calling_telegram()
    assert files, "no file builds a Telegram API URL any more; retire this check deliberately"


def test_no_telegram_request_error_becomes_text_unscrubbed():
    """`{e}` or `e.to_string()` on a reqwest error carries the URL.

    Scoped to the WINDOW after a bot URL is built, not to the whole file. A
    file-wide rule flagged every unrelated database error in a 4000-line module,
    and a guard that cries wolf gets waived wholesale rather than read — which
    would leave the real leak uncovered.
    """
    # Scope, not a line count. A fixed 30-line window missed the send path,
    # whose error render sits 33 lines below the URL it leaks — and widening the
    # number would have been a guess that happened to work on today's layout.
    # The request's scope ends at a new `match` arm, a new function, or the end
    # of the enclosing function.
    SCOPE_END = re.compile(r'^\s*(("[\w_]+"|\w+)\s*=>|(pub )?(async )?fn )|^\}')
    offenders: list[str] = []
    for path in _files_calling_telegram():
        lines = path.read_text().splitlines()
        starts = [i for i, l in enumerate(lines) if TELEGRAM_URL.search(l)]
        for start in starts:
            for n in range(start, len(lines)):
                line = lines[n]
                if n > start and SCOPE_END.match(line):
                    break
                if "redact::scrub" in line or line.lstrip().startswith("//"):
                    continue
                renders_error = (
                    "e.to_string()" in line
                    or re.search(r"format!\([^)]*\{e\}", line)
                    or re.search(r"error\s*=\s*%e\b", line)
                )
                if renders_error:
                    offenders.append(f"{path.relative_to(REPO)}:{n + 1}\t{line.strip()}")
    assert not offenders, (
        "a Telegram request error is rendered without scrubbing, so the bot token "
        "reaches the log:\n  " + "\n  ".join(sorted(set(offenders)))
    )


def test_the_scrubber_exists_and_is_shape_based():
    src = (GW / "redact.rs").read_text()
    assert "pub fn scrub" in src, "the scrubber named by every call site is gone"
    assert "TELEGRAM_BOT_TOKEN" not in src, (
        "the scrubber must not need the token's VALUE: a value-based redactor "
        "misses a rotated token, a second bot, and a token this process never held"
    )
