# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC
"""What taking an autonomy rule live means is said in three places: the
gateway's `dry_run_gate` (the answer's `live_means`), the console's
`LIVE_MEANS` (the Go live confirm) and the CLI's `LIVE_MEANS` (the
`noo autonomy live` prompt). The person confirming deletion reads one of the
two client copies; they must say exactly what the gateway enforces, for
exactly the rules the gateway gates."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _gateway():
    src = (ROOT / "gateway-rust/src/routes/intelligence.rs").read_text()
    body = src[src.index("pub(crate) fn dry_run_gate("):]
    body = body[: body.index("\n}\n")]
    out = {}
    for name, text in re.findall(r'"([a-z_]+)" => Some\(\s*((?:"(?:[^"\\]|\\.)*"\s*)+),?\s*\)', body, re.S):
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', text, re.S)
        joined = "".join(parts)
        joined = re.sub(r"\\\n\s*", "", joined)  # Rust line continuations
        out[name] = joined.replace('\\"', '"')
    return out


def _cli():
    src = (ROOT / "noo-cli/src/commands/autonomy.rs").read_text()
    block = src[src.index("pub(crate) const LIVE_MEANS"): src.index("];", src.index("pub(crate) const LIVE_MEANS"))]
    return {n: t.replace('\\"', '"') for n, t in re.findall(r'\(\s*"([a-z_]+)",\s*"((?:[^"\\]|\\.)*)",\s*\)', block)}


def _console():
    src = (ROOT / "ui/apps/web/src/features/autonomy/AutonomyPanel.tsx").read_text()
    block = src[src.index("export const LIVE_MEANS"): src.index("};", src.index("export const LIVE_MEANS"))]
    out = {}
    for name, q, text in re.findall(r"([a-z_]+):\s*(['\"])((?:(?!\2)[^\\]|\\.)*)\2", block):
        out[name] = text.replace("\\'", "'")
    return out


def test_the_three_copies_name_the_same_rules_and_say_the_same_thing():
    gw, cli, ui = _gateway(), _cli(), _console()
    assert set(gw) == {"disk_watermark", "cert_auto_rotate"}, gw
    assert cli == gw, f"CLI differs from the gateway:\n{cli}\n{gw}"
    assert ui == gw, f"console differs from the gateway:\n{ui}\n{gw}"


def test_disk_reclaim_says_it_deletes_and_what_it_never_touches():
    text = _gateway()["disk_watermark"]
    assert "DELETE" in text and "superseded noomesh images" in text and "never images outside noomesh's registries" in text
