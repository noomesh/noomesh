#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""text_summarizer sandbox capability — extractive summarization, stdlib only.

Contract (see manifest.yml):
  input  (env SKILL_INPUT, JSON): {text: str (required),
                                   max_length: number = 150 (words),
                                   style: "brief"|"detailed"|"bullet_points" = "brief"}
  output (stdout, JSON):          {summary: str, word_count: number}

Errors go to stderr with a non-zero exit code; the sandbox executor turns a
non-zero exit into a failed SandboxResult. No network, no filesystem writes —
the container runs with network=none and only /skill mounted.
"""
import json
import math
import os
import re
import sys
from collections import Counter

_STOPWORDS = frozenset(
    """a about above after again against all am an and any are as at be because been
    before being below between both but by can did do does doing down during each few
    for from further had has have having he her here hers herself him himself his how
    i if in into is it its itself just me more most my myself no nor not now of off
    on once only or other our ours ourselves out over own same she should so some
    such than that the their theirs them themselves then there these they this those
    through to too under until up very was we were what when where which while who
    whom why will with you your yours yourself yourselves""".split()
)


def _sentences(text: str) -> list:
    """Naive sentence splitter (period/question/exclamation + newlines)."""
    parts = re.split(r"(?<=[.!?])\s+|\n{2,}", text.strip())
    return [p.strip() for p in parts if p and p.strip()]


def _words(text: str) -> list:
    return re.findall(r"[A-Za-z0-9']+", text.lower())


def summarize(text: str, max_length: int, style: str) -> str:
    """Frequency-based extractive summary honoring max_length (words)."""
    sents = _sentences(text)
    if not sents:
        return ""

    freq = Counter(w for w in _words(text) if w not in _STOPWORDS)
    if not freq:
        freq = Counter(_words(text))
    top = freq.most_common(1)[0][1] or 1

    def score(sent: str, idx: int) -> float:
        ws = [w for w in _words(sent) if w not in _STOPWORDS]
        if not ws:
            return 0.0
        base = sum(freq[w] / top for w in ws) / math.sqrt(len(ws))
        # Mild lead bias: earlier sentences carry more summary weight.
        return base * (1.0 + 0.5 / (1 + idx))

    ranked = sorted(range(len(sents)), key=lambda i: score(sents[i], i), reverse=True)

    # detailed keeps more sentences within the same word budget granularity
    n_target = {"brief": 3, "detailed": 6, "bullet_points": 5}.get(style, 3)

    chosen: list = []
    used_words = 0
    for i in ranked:
        w = len(_words(sents[i]))
        if chosen and used_words + w > max_length:
            continue
        chosen.append(i)
        used_words += w
        if len(chosen) >= n_target or used_words >= max_length:
            break
    chosen.sort()  # restore original order
    picked = [sents[i] for i in chosen]

    if style == "bullet_points":
        summary = "\n".join(f"- {s}" for s in picked)
    else:
        summary = " ".join(picked)

    # Hard cap at max_length words (keep bullet prefixes intact).
    tokens = summary.split()
    words_seen = 0
    out_tokens = []
    for t in tokens:
        if re.search(r"[A-Za-z0-9]", t):
            words_seen += 1
        out_tokens.append(t)
        if words_seen >= max_length:
            break
    return " ".join(out_tokens) if words_seen >= max_length else summary


def main() -> int:
    try:
        inputs = json.loads(os.environ.get("SKILL_INPUT", "{}"))
    except json.JSONDecodeError as e:
        print(f"invalid SKILL_INPUT JSON: {e}", file=sys.stderr)
        return 2

    text = inputs.get("text")
    if not isinstance(text, str) or not text.strip():
        print("missing required input 'text'", file=sys.stderr)
        return 2

    try:
        max_length = int(inputs.get("max_length") or 150)
    except (TypeError, ValueError):
        max_length = 150
    max_length = max(10, max_length)
    style = str(inputs.get("style") or "brief")
    if style not in ("brief", "detailed", "bullet_points"):
        style = "brief"

    summary = summarize(text, max_length, style)
    word_count = len(re.findall(r"[A-Za-z0-9']+", summary))
    json.dump({"summary": summary, "word_count": word_count}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
