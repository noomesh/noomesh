# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""an earlier change — NOO_WORKER_SURFACES splits handler registration.

Registration happens at import time, so each mode is probed in a fresh
subprocess. The pins encode the seam itself: core is EXACTLY the non-ML
surfaces, ml is EXACTLY the trellion pack, and all == core ∪ ml with no
subject orphaned or double-owned."""

from __future__ import annotations

import json
import os
import subprocess
import sys

REPO_SRC = os.path.join(os.path.dirname(__file__), "..", "src")

CORE_SUBJECTS = {
    "worker.tool.generic",
    "worker.api.coding.task",
    "worker.api.heartbeat.run",
}


def _subjects(mode: str) -> set[str]:
    out = subprocess.run(
        [sys.executable, "-c",
         "import json; from noomesh.workers import all_handlers; "
         "print(json.dumps(sorted(all_handlers())))"],
        env={**os.environ,
             "PYTHONPATH": REPO_SRC,
             "NOO_WORKER_SURFACES": mode},
        capture_output=True, text=True, timeout=120,
    )
    assert out.returncode == 0, out.stderr[-500:]
    return set(json.loads(out.stdout.strip().splitlines()[-1]))


def test_core_is_exactly_the_non_ml_surfaces():
    assert _subjects("core") == CORE_SUBJECTS


ML_INTEL_SUBJECTS = {
    "worker.temporal.extract",
    "worker.api.heartbeat.run_ml",
    # The whole `worker.graph.*` family. Every one calls a module that left
    # trellion's open tree, so the base noo-trellion
    # image cannot import any of them — registering these on `ml` would put
    # the handlers on the one container guaranteed not to satisfy them.
    "worker.graph.recluster",
    "worker.graph.navigate",
    "worker.graph.traverse",
    "worker.graph.explain_path",
    "worker.graph.semantic_search",
    "worker.graph.search_clusters",
    "worker.graph.classify_intent",
    "worker.graph.extract_relations",
    "worker.graph.recall_traversals",
    "worker.graph.recall_walks",
}


def test_ml_intel_is_exactly_the_graph_engine_surface():
    assert _subjects("ml-intel") == ML_INTEL_SUBJECTS


def test_all_is_core_union_ml_union_intel_with_no_overlap():
    core, ml, intel, all_ = (
        _subjects("core"), _subjects("ml"), _subjects("ml-intel"), _subjects("all")
    )
    assert core | ml | intel == all_
    assert not core & ml, f"double-owned: {core & ml}"
    assert not core & intel, f"double-owned: {core & intel}"
    assert not ml & intel, f"double-owned: {ml & intel}"
    # the pack is the pack: every ml subject is knowledge-shaped
    for s in ml:
        assert s.split(".")[1] in {
            "rag", "memory", "retrieval", "recall",
            "temporal", "api", "autonomy",
        }, s


def test_unknown_mode_fails_safe_to_all():
    assert _subjects("bogus") == _subjects("all")
