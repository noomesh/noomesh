// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! What a node harness runs beside a foreign loop (i83 phase E).
//!
//! - [`translator`]: the loopback wire translator a vendor CLI talks to
//!   instead of the node's model endpoint. It speaks the CLI's wire
//!   (OpenAI chat, Anthropic Messages) in front of the backend's wire, and
//!   counts every token on the way through.
//! - [`driver`]: runs the vendor's headless CLI as the node's task executor,
//!   against the translator, with a per-turn user-door key for noomesh's
//!   tools.

pub mod driver;
pub mod translator;
