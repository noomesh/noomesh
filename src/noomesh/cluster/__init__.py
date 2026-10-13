# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Distributed cluster management for Mesh."""

# node.py (Node/NodeRegistry/NodeTier/...) was archived to
# legacy/python-cluster-reference/ the earlier sweep: Rust owns
# node state (routes/cluster.rs) and the registry sync loop that fed the
# Python copy was retired 2026-08-12 — every reader saw an empty shell.
# No NodeTier is left in this package: provisioner.py went with the retired
# `cluster add-node` verb. Tier classification lives in the
# Rust CLI and the gateway.

from .cli import cluster_app

__all__ = [
    "cluster_app",
]
