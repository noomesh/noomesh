# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""onboard's closing first-chat line asks what first-chat.md asks (i677 #5)."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_onboard_prints_the_pages_own_first_prompt():
    page = (ROOT / "docs/getting-started/first-chat.md").read_text()
    doc = re.search(r'^noo chat --message "([^"]+)"$', page, re.M)
    assert doc, "first-chat.md has no noo chat --message line"
    src = (ROOT / "noo-cli/src/onboard/mod.rs").read_text()
    cli = re.search(r'pub\(crate\) const FIRST_CHAT_PROMPT: &str = "([^"]+)";', src)
    assert cli, "FIRST_CHAT_PROMPT not found"
    assert cli.group(1) == doc.group(1), (cli.group(1), doc.group(1))
