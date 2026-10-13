#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""The style guide's state table and `ui::state()` must not drift.

`ui::state()` is the only place a state word gets its colour, and
CLI_STYLE_GUIDE.md §4 is where an author looks up which word to use. Nothing
forced them to agree, and they did not: the guide listed ten words, the code
knew forty-one. Every one of the thirty-one undocumented ones is a word some
command is already printing that no author would find by reading the guide.

Both directions are checked, because each has its own failure:

  code but not guide   an author invents a synonym for a word that already
                       exists, and the guide cannot tell them not to
  guide but not code   the guide promises a word that renders unstyled, so
                       following the guide produces the wrong output

Tone is compared too. A word that moves from `warn` to `bad` in code while
the guide still calls it a warning is the "degraded read as failed" mistake
the outcome section exists to prevent.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "noo-cli/src/ui.rs"
GUIDE = ROOT / "noo-cli/CLI_STYLE_GUIDE.md"

# `In-sync` / `In sync` is one row for two spellings; `Would <verb>` is a
# pattern whose code arm is the bare verb-less "would".
ALIASES = {"would <verb>": "would"}


def code_words() -> dict[str, str]:
    src = UI.read_text()
    m = re.search(r"pub fn state\(word: &str\) -> String \{(.*?)\n\}", src, re.S)
    if not m:
        print("check-state-words: could not find ui::state()", file=sys.stderr)
        sys.exit(1)
    body = m.group(1)
    out: dict[str, str] = {}
    for tone in ("good", "warn", "bad"):
        arm = re.search(
            r'((?:\s*"[^"]+"\s*\|)*\s*"[^"]+")\s*=>\s*\{?\s*' + tone + r"\(&w\)", body, re.S
        )
        if not arm:
            print(f"check-state-words: no {tone} arm in ui::state()", file=sys.stderr)
            sys.exit(1)
        for w in re.findall(r'"([^"]+)"', arm.group(1)):
            out[w] = tone
    return out


def guide_words() -> dict[str, str]:
    out: dict[str, str] = {}
    in_table = False
    for line in GUIDE.read_text().splitlines():
        if line.startswith("### State words"):
            in_table = True
            continue
        if in_table and line.startswith("### "):
            break
        if not in_table or not line.startswith("| `"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 2 or cells[1] not in ("good", "warn", "bad"):
            continue
        for w in re.findall(r"`([^`]+)`", cells[0]):
            w = w.lower()
            out[ALIASES.get(w, w)] = cells[1]
    return out


def main() -> int:
    code, guide = code_words(), guide_words()
    problems: list[str] = []

    for w, tone in sorted(code.items()):
        if w not in guide:
            problems.append(f"  `{w}` ({tone}) is in ui::state() but not in the guide table")
    for w, tone in sorted(guide.items()):
        if w not in code:
            problems.append(f"  `{w}` ({tone}) is in the guide table but not in ui::state()")
    for w, tone in sorted(code.items()):
        if w in guide and guide[w] != tone:
            problems.append(f"  `{w}`: ui::state() says {tone}, the guide says {guide[w]}")

    if problems:
        print("check-state-words: FAIL — the state vocabulary has drifted:", file=sys.stderr)
        print("\n".join(problems), file=sys.stderr)
        print(
            "\nAdd the word to both, with the same tone. The guide is where an author "
            "looks it up; ui::state() is what actually renders it.",
            file=sys.stderr,
        )
        return 1

    print(f"check-state-words: ok ({len(code)} state word(s) in sync)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
