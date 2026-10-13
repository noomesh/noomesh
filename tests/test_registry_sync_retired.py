# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Port-lane item 10 — the node-registry sync loop is gone and stays gone.

The loop copied NATS mesh_nodes into a Python registry every 30s for
three consumers that no longer exist (Rust-native backend routes, a
caller-less TaskRouter, device tools that POST the Rust gateway). These
pins fail if a rebase resurrects any of it."""

from __future__ import annotations

import pathlib

WORKER_POOL = pathlib.Path("src/noomesh/gateway/worker_pool.py").read_text()


def test_sync_loop_is_gone():
    assert "_node_registry_sync_loop" not in WORKER_POOL
    assert "_sync_nats_kv_to_registry" not in WORKER_POOL


def test_backend_manager_not_constructed():
    assert "BackendManager(registry" not in WORKER_POOL


def test_backends_worker_module_deleted():
    assert not pathlib.Path("src/noomesh/workers/backends.py").exists(), (
        "workers/backends.py held only the KV→registry sync helpers and "
        "was deleted with the loop — nothing may reintroduce it without "
        "reintroducing a consumer first"
    )


def test_workers_package_imports_without_backends():
    import noomesh.workers as w

    assert not hasattr(w, "backends")
