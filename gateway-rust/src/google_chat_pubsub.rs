// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Google Chat inbound over Cloud Pub/Sub — the PULL transport, in Rust.
//!
//! With ngrok retired there is no public webhook, so Chat events reach us
//! only by the bot dialing out and pulling them off a Pub/Sub subscription.
//! This loop owns that transport: mint token → `:pull` → `:acknowledge` →
//! hand each decoded event to the native pipeline
//! (`channels::google_chat_pipeline`), in process.
//!
//! # Why this is Rust
//!
//! The pull loop shipped in Python for deploy convenience —
//! Python is bind-mounted, so it needed no image rebuild. The cost showed up
//! on 2026-07-27: that adapter cached OAuth tokens with NO expiry, so ~1h
//! after every gateway start each pull returned 401 forever and ALL inbound
//! Chat silently stopped. `google_auth` here has always refreshed ~5 minutes
//! before expiry; the Python copy simply reimplemented the same job worse.
//! Moving the transport onto `google_auth` deletes that whole bug class
//! rather than patching it again.
//!
//! Event *processing* followed in stage 1 (`google_chat_pipeline`), and the
//! Python half was retired entirely in stage 4: the
//! `worker.channels.pubsub_event` subject no longer exists on either side,
//! and the engine selectors that used to hand transport or pipeline back to
//! Python (`NOO_GCHAT_PUBSUB_ENGINE`, `NOO_GCHAT_PIPELINE`) are obsolete —
//! warned about and ignored, never honoured (see
//! [`warn_if_obsolete_python_selector`]).
//!
//! # Authenticity
//!
//! Pulled events carry no `Authorization` header; authenticity is
//! structural instead: only the Chat app's publisher SA can publish to the
//! topic and only our subscriber SA can pull it. Do NOT route pulled events
//! through webhook-style signature verification — it fails closed on them
//! and silently drops every event (the stage-0 landmine).

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::state::AppState;

const PUBSUB_API: &str = "https://pubsub.googleapis.com/v1";
const PUBSUB_SCOPE: &str = "https://www.googleapis.com/auth/pubsub";
/// Pub/Sub caps a pull at this many messages per round trip.
const MAX_MESSAGES: u32 = 10;
/// The `:pull` call long-polls, so give it room; Chat events are bursty.
const PULL_TIMEOUT_SECS: u64 = 75;
const ACK_TIMEOUT_SECS: u64 = 30;
const MAX_BACKOFF_SECS: u64 = 60;

/// Start the pull loop. No-op unless `GOOGLE_CHAT_PUBSUB_SUBSCRIPTION` is
/// set, so Telegram-only deployments are unaffected.
///
/// This loop runs UNCONDITIONALLY when a subscription is configured. The
/// `NOO_GCHAT_PUBSUB_ENGINE=python` hatch that used to stand it down is
/// obsolete: the Python pull loop can no longer start,
/// so honouring the selector would leave the subscription with ZERO pullers
/// and the channel silently dead — the worst possible failure shape.
pub fn spawn(state: Arc<AppState>) {
    let subscription = match std::env::var("GOOGLE_CHAT_PUBSUB_SUBSCRIPTION") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => return,
    };
    crate::channels::warn_if_obsolete_python_selector("NOO_GCHAT_PUBSUB_ENGINE");
    crate::channels::warn_if_obsolete_python_selector("NOO_GCHAT_PIPELINE");
    tokio::spawn(async move {
        run(state, subscription).await;
    });
}

async fn run(state: Arc<AppState>, subscription: String) {
    let client = crate::tls::client_builder()
        .timeout(Duration::from_secs(PULL_TIMEOUT_SECS + 15))
        .build()
        .unwrap_or_default();

    let pull_url = format!("{PUBSUB_API}/{subscription}:pull");
    let ack_url = format!("{PUBSUB_API}/{subscription}:acknowledge");

    tracing::info!(subscription = %subscription, "gchat_pubsub_started");

    let mut backoff = 1u64;
    loop {
        crate::loop_health::record_tick("gchat_pubsub", 60);

        match pull_once(&state, &client, &pull_url, &ack_url).await {
            Ok(n) => {
                backoff = 1;
                if n == 0 {
                    // Empty long-poll return — brief pause so we don't spin.
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
            Err(e) => {
                tracing::error!(error = %e, backoff, "gchat_pubsub_error");
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(MAX_BACKOFF_SECS);
            }
        }
    }
}

/// One pull → ack → dispatch round. Returns how many events were handled.
async fn pull_once(
    state: &Arc<AppState>,
    client: &reqwest::Client,
    pull_url: &str,
    ack_url: &str,
) -> Result<usize, String> {
    // google_auth caches and refreshes ~5min before expiry, so this is cheap
    // on the hot path and — unlike the Python original — cannot go stale.
    let token = crate::google_auth::access_token(&[PUBSUB_SCOPE]).await?;

    let resp = client
        .post(pull_url)
        .bearer_auth(&token)
        .json(&json!({ "maxMessages": MAX_MESSAGES }))
        .timeout(Duration::from_secs(PULL_TIMEOUT_SECS))
        .send()
        .await
        .map_err(|e| format!("pull request: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "pull {status}: {}",
            body.chars().take(300).collect::<String>()
        ));
    }

    let body: Value = resp.json().await.map_err(|e| format!("pull decode: {e}"))?;
    let received = body
        .get("receivedMessages")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if received.is_empty() {
        return Ok(0);
    }

    // ACK FIRST. Reply generation runs inference (~30-80s) and would blow the
    // ack deadline, causing Pub/Sub to redeliver and the user to get the same
    // answer twice. The webhook path acks immediately then replies async too.
    let ack_ids: Vec<&str> = received
        .iter()
        .filter_map(|m| m.get("ackId").and_then(|v| v.as_str()))
        .collect();
    if !ack_ids.is_empty() {
        let ack = client
            .post(ack_url)
            .bearer_auth(&token)
            .json(&json!({ "ackIds": ack_ids }))
            .timeout(Duration::from_secs(ACK_TIMEOUT_SECS))
            .send()
            .await;
        match ack {
            Ok(r) if !r.status().is_success() => {
                tracing::warn!(status = %r.status(), "gchat_pubsub_ack_failed");
            }
            Err(e) => tracing::warn!(error = %e, "gchat_pubsub_ack_failed"),
            _ => {}
        }
    }

    // Dispatch. `data` is already base64 in the Pub/Sub envelope and the
    // consumer wants base64, so pass it through untouched rather than
    // decode-then-re-encode.
    let mut dispatched = 0usize;
    for m in &received {
        let Some(data_b64) = m
            .get("message")
            .and_then(|msg| msg.get("data"))
            .and_then(|d| d.as_str())
        else {
            continue;
        };
        // Native pipeline: parse → identity → inference → send, all in
        // process. The `worker.channels.pubsub_event` NATS branch that used
        // to sit here was retired stage 4 — its Python
        // handler is unregistered, so publishing to it would drop every
        // event into a subscriber-less subject.
        //
        // Spawned so one slow reply cannot stall the pull loop; the
        // message is already acked (ack-first), so the alternative to
        // spawning is blocking every other event behind this one.
        let st = state.clone();
        let b64 = data_b64.to_string();
        tokio::spawn(async move {
            match base64_decode(&b64) {
                Ok(body) => {
                    if let Err(e) =
                        crate::channels::google_chat_pipeline::handle_event(st, &body).await
                    {
                        // WARN, not debug: a dropped inbound message is
                        // invisible to the user except as silence.
                        tracing::warn!(error = %e, "gchat_pipeline_failed");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "gchat_pubsub_bad_base64"),
            }
        });
        dispatched += 1;
    }

    tracing::info!(count = dispatched, "gchat_pubsub_events_dispatched");
    Ok(dispatched)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    

    #[test]
    fn no_nats_delegation_remains_in_this_module() {
        // pulled events are handled by the in-process
        // pipeline, full stop. The `worker.channels.pubsub_event` handler is
        // unregistered on the Python side, so a reintroduced publish here
        // would fire every inbound Chat message into a subscriber-less
        // subject — delivered, acked, and never answered.
        let src = include_str!("google_chat_pubsub.rs");
        // Concatenated so this test's own source (included in `src`) does
        // not match it. The retired subject NAME still appears in comments
        // (deliberately — it documents what was deleted), so the guard is
        // on the publish MECHANISM, not the string.
        let marker = ["worker_client", "::"].concat();
        assert!(
            !src.contains(marker.as_str()),
            "google_chat_pubsub.rs references `{marker}` again — pulled \
             events must go to channels::google_chat_pipeline in-process"
        );
    }
}
