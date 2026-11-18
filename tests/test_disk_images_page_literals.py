# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""docs/operating/disk-and-images.md quotes output an agent matches on: each
quote is still what the code prints.

The 2026-11-18 launch audit found quoted output nothing compared. This page's
"For agents" part is a contract (verify row details, the roll's blocked line,
the keep file's `why`), so its quotes are pinned by rule, not by a list: every
backtick literal there with at least three words that is not a command or a
path is output, and each part of it between placeholders (`<…>`, `…`) must
occur in the CLI's or the node agent's source.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "docs" / "operating" / "disk-and-images.md"


def _block_end(text: str, j: int) -> int:
    """Index just past the `}` closing the block whose `{` ends at j: braces
    are counted outside Rust strings, raw strings, char literals and comments."""
    depth, n = 1, len(text)
    while j < n and depth:
        c = text[j]
        if text.startswith("//", j):
            j = text.find("\n", j)
            j = n if j < 0 else j
            continue
        if text.startswith("/*", j):
            k = text.find("*/", j + 2)
            j = n if k < 0 else k + 2
            continue
        raw = re.match(r'r(#*)"', text[j:j + 12])
        if raw and (j == 0 or not (text[j - 1].isalnum() or text[j - 1] == "_")):
            close = '"' + raw.group(1)
            k = text.find(close, j + raw.end())
            j = n if k < 0 else k + len(close)
            continue
        if c == '"':
            j += 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            j += 1
            continue
        if c == "'":
            lit = re.match(r"'(\\.|[^\\'])'", text[j:j + 4])
            if lit:
                j += lit.end()
                continue
        depth += {"{": 1, "}": -1}.get(c, 0)
        j += 1
    return j


def _without_test_modules(text: str) -> str:
    """Drop every `#[cfg(test)] mod … { … }` block; keep the rest, including
    production code after a test module."""
    out, i = [], 0
    for m in re.finditer(r"#\[cfg\(test\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{", text):
        if m.start() < i:
            continue
        out.append(text[i:m.start()])
        i = _block_end(text, m.end())
    out.append(text[i:])
    return "".join(out)


def _source() -> str:
    parts = []
    for base, ext in ((ROOT / "noo-cli" / "src", "*.rs"), (ROOT / "node-agent-go", "*.go")):
        for p in base.rglob(ext):
            if "_test" in p.name:
                continue
            text = p.read_text(errors="replace")
            # Production code only: a Rust file's `#[cfg(test)]` modules assert
            # the same strings, and would keep a reworded one "found".
            parts.append(_without_test_modules(text) if ext == "*.rs" else text)
    return "\n".join(parts)


def _agent_quotes() -> list[str]:
    text = PAGE.read_text()
    agents = text.split("## For agents", 1)[1]
    # A quote may wrap across lines in the markdown: one space for each run.
    quotes = [re.sub(r"\s+", " ", q) for q in re.findall(r"`([^`]+)`", agents)]
    out = []
    for q in quotes:
        # Not output: a command, a path, or a JSON shape (`{at, tag, rows}`).
        if q.count(" ") < 2 or re.match(r"^(noo|docker|sudo|scripts/|<root>|/|\{)", q):
            continue
        out.append(q)
    return out


def _fragments(quote: str) -> list[str]:
    parts = re.split(r"<[^>]*>|…|\.\.\.", quote)
    # Whitespace only: the quote's punctuation is part of what an agent
    # matches on (`; not on this host` is the keep file's suffix; "not on
    # this host" alone also occurs in unrelated messages).
    return [p.strip() for p in parts if len(p.strip()) >= 6]


def test_the_rule_finds_the_contract_quotes():
    quotes = _agent_quotes()
    assert any("not cleaned since the roll to" in q for q in quotes), quotes
    assert any("NOT cleaned up" in q for q in quotes), quotes
    assert len(quotes) >= 8, quotes


def test_every_quoted_output_is_still_printed():
    src = _source()
    missing = [(q, f) for q in _agent_quotes() for f in _fragments(q) if f not in src]
    assert not missing, "disk-and-images.md quotes output the code no longer prints: " + "; ".join(f"{q!r} (missing {f!r})" for q, f in missing)
