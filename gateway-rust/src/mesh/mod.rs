// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Mesh peer coordination: `gossip` (NATS-based peer discovery/announce,
//! interoperable with Python's mesh_gossip.py) and `router` (backend
//! discovery over `mesh.inference.discover`, interoperable with Python's
//! mesh_router.py).

pub mod gossip;
pub mod router;
