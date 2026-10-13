// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! Mesh inference router — Rust implementation.
//!
//! Same NATS subject (mesh.inference.discover) and JSON protocol
//! as Python's mesh_router.py.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

const DISCOVER_SUBJECT: &str = "mesh.inference.discover";
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendOffer {
    pub node_id: String,
    pub backend_type: String,
    pub model: String,
    pub url: String,
    pub load: f64,
    #[serde(default = "default_api_format")]
    pub api_format: String,
}

fn default_api_format() -> String { "openai".into() }

/// Discover a backend via NATS mesh request/reply.
pub async fn discover_backend(
    nats: &async_nats::Client,
    model: Option<&str>,
    backend_type: Option<&str>,
) -> Result<Option<BackendOffer>> {
    let payload = json!({
        "type": "discover",
        "model": model,
        "backend_type": backend_type,
    });
    let data = serde_json::to_vec(&payload)?;

    match tokio::time::timeout(
        DISCOVER_TIMEOUT,
        nats.request(DISCOVER_SUBJECT, data.into()),
    )
    .await
    {
        Ok(Ok(msg)) => {
            let offer: BackendOffer = serde_json::from_slice(&msg.payload)?;
            tracing::info!(
                node_id = %offer.node_id,
                model = %offer.model,
                load = offer.load,
                "mesh.discovered"
            );
            Ok(Some(offer))
        }
        Ok(Err(e)) => {
            tracing::debug!("mesh.discover_failed: {e}");
            Ok(None)
        }
        Err(_) => {
            tracing::debug!("mesh.discover_timeout");
            Ok(None)
        }
    }
}
