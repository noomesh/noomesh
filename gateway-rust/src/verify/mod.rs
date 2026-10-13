// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Verifier helpers — checks that catch model misbehavior before it
//! reaches the user, the audit log, or external storage.
//!
//! Background: as we've added LLM-driven flows, a recurring pattern
//! emerged of "the model said X but X isn't true" — malformed tool-call
//! XML emitted as prose, scheduling claims with no actual tool call,
//! `<think>` blocks leaking into user-visible output, heartbeat reports
//! that are 9ms long with no real content. Each was patched in place
//! (in coordinator.rs, heartbeat_actions.rs, routes/communication.rs,
//! routes/intelligence.rs) and the same checks started getting
//! duplicated. This module is the canonical home so new verifiers land
//! in one place and existing call sites can deduplicate.
//!
//! Scope today:
//! - `response`: post-process the coordinator's final response
//!   (think-block stripping, malformed-tool-call detection,
//!   scheduling-hallucination correction)
//!
//! Likely additions:
//! - `stall`: extract the stall-detection logic from coordinator.rs's
//!   agentic loop (currently inline)
//! - `artifact`: extract the heartbeat/Drive artifact-quality gate
//!   from heartbeat_actions.rs and routes/communication.rs (each
//!   currently calls into `response::` helpers; the *gate* logic is
//!   still copy-pasted between them)
//!
//! about which checks belong here vs. inline.

pub mod response;
