// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

//! The "tempo" and "tempo listener" controller rows (i359, request tracing).
//!
//! `tempo`: the gateway sends its request spans to Tempo and can read Tempo's
//! `/ready` with its own leaf (`GET /api/traces/status`). `tempo listener`:
//! the shipped config requires a cluster client certificate on BOTH doors
//! (OTLP 4318 and the query API 3200), Tempo's internal gRPC stays on
//! loopback, usage reporting is off, and compose publishes no port. Same
//! shape as the `loki` / `loki listener` pair.

use super::{fail, ok, warn, Check};
use crate::Globals;
use serde_json::Value;

pub(crate) const ROW: &str = "tempo";
pub(crate) const LISTENER_ROW: &str = "tempo listener";

/// The shipped config, as `cluster verify` reads it from the running checkout.
pub(crate) const CONFIG_PATH: &str = "monitoring/tempo/tempo.yml";

fn leaf_present() -> bool {
    crate::pki::pki_dir().join("services").join("tempo").join("service.crt").is_file()
}

/// The `tempo` row from the gateway's `/api/traces/status` answer.
pub(crate) fn tempo_check(status: Option<&Value>, leaf_present: bool) -> Check {
    if !leaf_present {
        return fail(
            ROW,
            "no services/tempo/service.crt — Tempo's mTLS listeners cannot start and no request span is kept",
            "noo security pki issue-service tempo   # then: noo stack restart --force tempo",
        );
    }
    let Some(s) = status else {
        return warn(
            ROW,
            "not read (the gateway did not answer /api/traces/status; a gateway before request tracing has no such route)",
            Some("noo upgrade --stack".into()),
        );
    };
    if s["exporting"].as_bool() != Some(true) {
        let url = s["tempo_otlp_url"].as_str().unwrap_or("");
        let why = if url.trim().is_empty() {
            "the gateway has no NOO_TEMPO_OTLP_URL, so it keeps request summaries but sends no spans".to_string()
        } else {
            format!("the gateway refuses NOO_TEMPO_OTLP_URL={url} (spans go over https:// only)")
        };
        return fail(ROW, why, "noo upgrade --stack   # the shipped compose hands the gateway https://tempo:4318");
    }
    if s["tempo_configured"].as_bool() != Some(true) {
        return fail(
            ROW,
            "the gateway has no NOO_TEMPO_URL, so neither this row nor Grafana can read Tempo",
            "noo upgrade --stack   # the shipped compose hands the gateway https://tempo:3200",
        );
    }
    let url = s["tempo_url"].as_str().unwrap_or("?");
    if s["tempo_ready"].as_bool() != Some(true) {
        let why = s["tempo_ready_detail"]
            .as_str()
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(|d| format!("/ready {d}"))
            .unwrap_or_else(|| "/ready did not answer — the container is down, or its leaf/CA does not match the gateway's".into());
        return fail(ROW, format!("configured ({url}) but {why}"), "noo stack status   # then: docker logs noo-tempo");
    }
    let days = s["retention_days"].as_i64().map(|d| format!("; summaries kept {d} days")).unwrap_or_default();
    ok(ROW, format!("ready at {url}; the gateway sends a span per request with its own leaf{days}"))
}

/// Lines of a YAML file with comments dropped and indentation trimmed.
fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(|l| l.split('#').next().unwrap_or("").trim()).filter(|l| !l.is_empty())
}

/// The `tempo listener` row from the shipped config and compose file.
pub(crate) fn tempo_listener_check(config: Option<&str>, compose: Option<&str>) -> Check {
    let (Some(config), Some(compose)) = (config, compose) else {
        return warn(
            LISTENER_ROW,
            format!("could not read {CONFIG_PATH} or docker-compose.cluster.yml from the running checkout"),
            None,
        );
    };
    let lines: Vec<&str> = code_lines(config).collect();
    let restore = "restore the shipped config (noo upgrade --stack re-materialises it)";
    if !lines.contains(&"client_auth_type: RequireAndVerifyClientCert") {
        return fail(
            LISTENER_ROW,
            format!("{CONFIG_PATH} does not set client_auth_type: RequireAndVerifyClientCert — anything on the compose network could read every request trace"),
            restore,
        );
    }
    if !lines.contains(&"client_ca_file: /tls/ca.crt") || lines.iter().filter(|l| l.starts_with("client_ca_file:")).count() < 2 {
        return fail(
            LISTENER_ROW,
            format!("{CONFIG_PATH}: the OTLP receiver does not require a cluster client certificate (no client_ca_file on both doors) — anything on the compose network could write spans"),
            restore,
        );
    }
    if !lines.contains(&"grpc_listen_address: 127.0.0.1") {
        return fail(
            LISTENER_ROW,
            format!("{CONFIG_PATH}: Tempo's internal gRPC is not bound to loopback, so it listens in plaintext on the compose network"),
            restore,
        );
    }
    let usage_off = config.contains("usage_report:") && lines.contains(&"reporting_enabled: false");
    if !usage_off {
        return fail(
            LISTENER_ROW,
            format!("{CONFIG_PATH}: usage_report.reporting_enabled is not false, so Tempo reports usage to stats.grafana.org"),
            restore,
        );
    }
    let Some(block) = super::compose_service_block(compose, "tempo") else {
        return warn(LISTENER_ROW, "docker-compose.cluster.yml has no tempo service", None);
    };
    if block.lines().any(|l| l.trim() == "ports:") {
        return fail(
            LISTENER_ROW,
            "the tempo service publishes a host port — Tempo is compose-network only by design (the gateway is its only caller)",
            "remove the ports: block from the tempo service and recreate it",
        );
    }
    ok(LISTENER_ROW, "client certificate required on OTLP and the query API; gRPC on loopback; usage reporting off; no published port")
}

/// Both rows, as `cluster verify --controller` prints them.
pub(crate) fn rows(g: &Globals) -> Vec<Check> {
    let status = crate::http::get_json_opt(g, "/api/traces/status", true, 10);
    let root = crate::envfile::repo_root();
    let config = std::fs::read_to_string(root.join(CONFIG_PATH)).ok();
    let compose = std::fs::read_to_string(root.join("docker-compose.cluster.yml")).ok();
    vec![tempo_check(status.as_ref(), leaf_present()), tempo_listener_check(config.as_deref(), compose.as_deref())]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::cluster_verify::Verdict;
    use serde_json::json;

    fn ready() -> Value {
        json!({
            "tempo_otlp_url": "https://tempo:4318", "exporting": true,
            "tempo_url": "https://tempo:3200", "tempo_configured": true,
            "tempo_ready": true, "tempo_ready_detail": null, "retention_days": 30,
        })
    }

    #[test]
    fn a_ready_tempo_passes_and_says_how_long_summaries_stay() {
        let c = tempo_check(Some(&ready()), true);
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
        assert!(c.detail.contains("https://tempo:3200") && c.detail.contains("30 days"), "{}", c.detail);
    }

    #[test]
    fn each_way_tempo_is_not_there_fails_with_its_own_reason() {
        assert_eq!(tempo_check(Some(&ready()), false).verdict, Verdict::Fail, "no leaf");
        assert_eq!(tempo_check(None, true).verdict, Verdict::Warn, "an older gateway is not read, not failed");

        let mut s = ready();
        s["exporting"] = json!(false);
        s["tempo_otlp_url"] = json!("");
        let c = tempo_check(Some(&s), true);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("NOO_TEMPO_OTLP_URL"), "{}", c.detail);

        s["tempo_otlp_url"] = json!("http://tempo:4318");
        let c = tempo_check(Some(&s), true);
        assert!(c.detail.contains("https:// only"), "{}", c.detail);

        let mut s = ready();
        s["tempo_configured"] = json!(false);
        assert!(tempo_check(Some(&s), true).detail.contains("NOO_TEMPO_URL"));

        let mut s = ready();
        s["tempo_ready"] = json!(false);
        s["tempo_ready_detail"] = json!("answered 503: Ingester not ready");
        let c = tempo_check(Some(&s), true);
        assert_eq!(c.verdict, Verdict::Fail);
        assert!(c.detail.contains("/ready answered 503: Ingester not ready"), "{}", c.detail);
    }

    const SHIPPED: &str = include_str!("../../../../monitoring/tempo/tempo.yml");
    const COMPOSE: &str = include_str!("../../../../docker-compose.cluster.yml");

    #[test]
    fn the_shipped_listener_passes() {
        let c = tempo_listener_check(Some(SHIPPED), Some(COMPOSE));
        assert_eq!(c.verdict, Verdict::Ok, "{}", c.detail);
    }

    #[test]
    fn each_loosening_of_the_listener_fails() {
        let cases = [
            ("client_auth_type: RequireAndVerifyClientCert", "client_auth_type: NoClientCert", "RequireAndVerifyClientCert"),
            ("            client_ca_file: /tls/ca.crt\n", "", "OTLP receiver"),
            ("grpc_listen_address: 127.0.0.1", "grpc_listen_address: 0.0.0.0", "loopback"),
            ("reporting_enabled: false", "reporting_enabled: true", "stats.grafana.org"),
        ];
        for (from, to, want) in cases {
            assert!(SHIPPED.contains(from), "the shipped config no longer has {from:?}");
            let cfg = SHIPPED.replacen(from, to, 1);
            let c = tempo_listener_check(Some(&cfg), Some(COMPOSE));
            assert_eq!(c.verdict, Verdict::Fail, "{from:?}: {}", c.detail);
            assert!(c.detail.contains(want), "{from:?}: {}", c.detail);
        }
        let published = COMPOSE.replacen("  tempo:\n", "  tempo:\n    ports:\n      - \"4318:4318\"\n", 1);
        assert_ne!(published, COMPOSE, "the compose file has no tempo service to plant into");
        assert_eq!(tempo_listener_check(Some(SHIPPED), Some(&published)).verdict, Verdict::Fail);
        assert_eq!(tempo_listener_check(None, Some(COMPOSE)).verdict, Verdict::Warn);
    }
}
