# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Rust ↔ Python parity for heartbeat ML-action surface routing.

The Rust dispatcher routes actions named in
``heartbeat_actions::TRELLION_ACTIONS`` to the trellion worker
(``worker.api.heartbeat.run_ml``); everything else goes to the core
worker, which has no ML tree. The two sides can drift independently:

- A Python handler grows an ML dependency without joining the Rust list
  → it lands on core and dies (loudly, post-fu 52 — the handlers raise —
  but it dies every run until someone updates the list).
- An action joins the Rust list without its handler needing ML → it
  needlessly requires the trellion add-on.

Same cross-language pinning idea as ``test_posture_key_parity``: parse
the Rust constant, classify the Python handlers by what services their
bodies actually touch, and require the two sets to be identical.
"""
from __future__ import annotations

import os
import re

REPO = os.path.join(os.path.dirname(__file__), "..")
RUST = os.path.join(REPO, "gateway-rust", "src", "heartbeat_actions.rs")
PY = os.path.join(REPO, "src", "noomesh", "gateway", "heartbeat.py")

# Service markers that mean "this handler needs the trellion container".
_ML_MARKERS = (
    "_get_pageindex_store",
    "pageindex_rag",
    "GRAPH_METRICS",
    "recall_memory",
    "..memory.video",
)


def _rust_trellion_actions() -> set[str]:
    src = open(RUST).read()
    m = re.search(
        r"pub const TRELLION_ACTIONS: &\[&str\] = &\[(.*?)\];", src, re.S
    )
    assert m, "TRELLION_ACTIONS not found in heartbeat_actions.rs"
    return set(re.findall(r'"([a-z_]+)"', m.group(1)))


def _rust_native_or_llm() -> set[str]:
    src = open(RUST).read()
    out: set[str] = set()
    for name in ("RUST_LLM_ACTIONS", "RUST_NATIVE_ACTIONS"):
        m = re.search(
            rf"const {name}: &\[&str\] = &\[(.*?)\];", src, re.S
        )
        assert m, f"{name} not found"
        out |= set(re.findall(r'"([a-z_]+)"', m.group(1)))
    return out


def _python_delegate_ml_actions() -> set[str]:
    src = open(PY).read()
    m = re.search(r"_dispatch: Dict\[str, Any\] = \{(.*?)\}", src, re.S)
    assert m, "_dispatch map not found in heartbeat.py"
    actions = dict(re.findall(r'"([a-z_]+)": self\.(_[a-z_]+)', m.group(1)))

    rust_owned = _rust_native_or_llm()
    ml: set[str] = set()
    for action, fn in actions.items():
        if action in rust_owned:
            continue  # Python body is dead code for these
        body_m = re.search(
            rf"async def {fn}\(self.*?(?=\n    async def |\n    def )",
            src,
            re.S,
        )
        body = body_m.group(0) if body_m else ""
        if any(marker in body for marker in _ML_MARKERS):
            ml.add(action)
    return ml


def test_rust_trellion_actions_match_python_ml_handlers():
    rust = _rust_trellion_actions()
    python = _python_delegate_ml_actions()
    assert rust == python, (
        f"heartbeat ML surface drift — "
        f"in Rust TRELLION_ACTIONS but handler shows no ML usage: "
        f"{sorted(rust - python)}; "
        f"handler uses ML services but missing from TRELLION_ACTIONS "
        f"(would land on the core worker and fail every run): "
        f"{sorted(python - rust)}"
    )


def test_trellion_actions_are_not_rust_owned():
    overlap = _rust_trellion_actions() & _rust_native_or_llm()
    assert not overlap, (
        f"actions cannot be both Rust-owned and trellion-delegated: "
        f"{sorted(overlap)}"
    )
