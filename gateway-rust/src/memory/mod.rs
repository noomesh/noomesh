// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The memory-provider seam.
//!
//! mesh ships trellion as its reference memory system, but memory is a
//! PROVIDER SLOT, not a hard dependency: a third party should be able to
//! bring their own vector store / graph / recall strategy by ADDING a
//! system alongside ours, not by reproducing trellion's 29 table shapes.
//! This module is that seam on the gateway side. Every call the gateway
//! makes into the AUGMENTATION plane — recall, KB search/ingest, graph
//! tools, snapshots — funnels through [`provider::MemoryProvider`], so a
//! provider fails (or gets swapped) at one boundary instead of silently
//! diverging across ~58 call sites.
//!
//! ## The two planes — read this before adding a call site
//!
//! The split is drawn where the degradation contract already is
//!
//!
//! * **Transcript plane — mesh-owned, direct SQL, NOT this module.**
//!   Turn writes, conversation/entry reads, session resolution, rolling
//!   summaries. A chat turn must never block on a memory provider —
//!   that is an availability bug, not a seam. Those sites keep their SQL
//!   on purpose; do not "clean them up" into the facade.
//! * **Augmentation plane — provider-owned, goes through here.** KB
//!   query/ingest, knowledge-graph tools, prune-restore writes into
//!   provider tables, snapshots, semantic relationships. If a new call
//!   site touches provider-derived data, it belongs behind the facade.
//!
//! Two deliberate exceptions stay direct SQL: OBSERVABILITY counts
//! (`/metrics`, autonomy evaluators, dashboards — pure `COUNT(*)`s that
//! must keep working to REPORT a provider outage) and the TEMPORAL
//! exception (`temporal_graph.rs` — plane ownership deferred to
//! TEMPORAL_KNOWLEDGE_GRAPH.md phase 1).
//!
//! ## What a provider must / may implement
//!
//! The contract is call-shaped, versioned HTTP: `/v1/memory/*` (see the
//! endpoint table). Capability groups:
//!
//! * `core` — recall, turns:batch, search, forget, health: **mandatory**.
//!   `forget` is core because a provider that cannot forget is a
//!   compliance problem, not a feature gap.
//! * `kb`, `recall`, `temporal`, `snapshots` — optional. An unimplemented
//!   group degrades exactly like provider-absent for those routes; the
//!   degradation table is the spec (and becomes a CI test
//!   in phase 5).
//!
//! `embed` is a REVERSE hook, not a provider capability: the gateway owns
//! embedding placement and the provider consumes `/api/embed` from us.
//!
//! ## Where provider discovery will come from
//!
//! Phase 2 adds the `Http` implementation, discovered as `role=memory`
//! through the design's `mesh::targets(state, role, opts)` resolver —
//! mTLS + service bearer on every hop, never URL-in-env (memory carries
//! conversation content and PII). Until then the sole implementation is
//! [`provider::NatsTrellion`], which speaks today's `worker.*` NATS
//! subjects and keeps the remaining augmentation SQL internal, so call
//! sites are already provider-shaped when the transport flips.
//!
//! ## Observability
//!
//! Every operation increments `memory_provider_calls_total{op=...}` on
//! `/metrics` — the per-subject frequency data phase 0 found missing,
//! and phase 3's soak baseline.

pub mod cluster_audit;
pub mod provider;
pub mod scope;

pub use provider::MemoryProvider;
