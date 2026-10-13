# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Default monitoring locations for the autonomy engine.

These cover the core operational scenarios for self-managing clusters:
  1. Unembedded documents need processing
  2. Graph entity coverage is falling behind
  3. Cluster nodes have gone offline
  4. No inference backends are running
  5. Job queue is backing up
  6. Idle backends wasting VRAM
  7. Nodes with persistent failures need quarantine
  8. Backend scaling under high load (opt-in)
  9. Test suite health degradation
"""

from __future__ import annotations

import os

from .autonomy_types import Action, Condition, LocationType, MonitorLocation

# Gateway base URL for endpoint monitors — https always: the gateway has
# no plaintext listener.
_gw_port = os.getenv("GATEWAY_PORT", "8080")
_GW = f"https://127.0.0.1:{_gw_port}"

# Pause scheduling new embed jobs once the unembedded backlog crosses this
# threshold. The embedding worker keeps draining what's already there; we
# just stop piling on. Override via env when TEI capacity differs.
_EMBED_BACKPRESSURE = int(os.getenv("NOO_EMBEDDING_BACKPRESSURE_THRESHOLD", "5000"))

DEFAULT_LOCATIONS: list[MonitorLocation] = [
    # ── Knowledge maintenance ──────────────────────────────────────────
    MonitorLocation(
        name="unembedded_documents",
        type=LocationType.RAG_STORE,
        config={"check": "unembedded_pages"},
        check_interval_seconds=60,
        # AND semantics: schedule a new embed job only when there's work to
        # do AND the backlog isn't already overloaded. Worker continues
        # draining whatever has accumulated independently of this trigger.
        conditions_mode="all",
        conditions=[
            Condition(metric="unembedded_pages", operator="gt", threshold=0),
            Condition(metric="unembedded_pages", operator="lt", threshold=_EMBED_BACKPRESSURE),
        ],
        # Alert-only: the background_embed job this once submitted is retired
        # (gateway-rust/src/job_types.rs RETIRED_JOB_TYPES). trellion's
        # PageIndexEmbedder drains pages/chunks on its own loop; the live Rust
        # evaluator alerts when that backlog stops shrinking.
        actions=[Action(type="alert", config={"message": "Embedding backlog not draining"})],
    ),
    MonitorLocation(
        name="missing_graph_entities",
        type=LocationType.RAG_STORE,
        config={"check": "entity_coverage"},
        check_interval_seconds=120,
        conditions=[Condition(metric="entity_gap", operator="gt", threshold=5)],
        actions=[Action(type="submit_job", config={"type": "background_graph", "scope": "extract"})],
    ),

    # ── Cluster health ─────────────────────────────────────────────────
    MonitorLocation(
        name="node_health",
        type=LocationType.CLUSTER,
        config={"check": "node_status"},
        check_interval_seconds=30,
        conditions=[Condition(metric="offline_count", operator="gt", threshold=0)],
        actions=[Action(type="alert", config={"message": "Node(s) offline"})],
    ),
    MonitorLocation(
        name="node_auto_quarantine",
        type=LocationType.CLUSTER,
        config={"check": "node_failures"},
        check_interval_seconds=60,
        conditions=[Condition(metric="quarantine_candidates", operator="gt", threshold=0)],
        actions=[Action(type="quarantine_nodes", config={})],
        cooldown_seconds=120,
    ),

    # ── Edge / Companion health ─────────────────────────────────────────
    MonitorLocation(
        name="edge_node_health",
        type=LocationType.CLUSTER,
        config={"check": "edge_health"},
        check_interval_seconds=60,
        conditions=[Condition(metric="edge_offline_count", operator="gt", threshold=0)],
        actions=[Action(type="alert", config={"message": "Edge node(s) offline"})],
        cooldown_seconds=300,
    ),
    MonitorLocation(
        name="companion_battery_low",
        type=LocationType.CLUSTER,
        config={"check": "companion_battery"},
        check_interval_seconds=120,
        conditions=[Condition(metric="low_battery_companions", operator="gt", threshold=0)],
        actions=[Action(type="log", config={
            "level": "warning",
            "message": "Companion device(s) with low battery",
        })],
        cooldown_seconds=600,
    ),

    # ── Backend lifecycle ──────────────────────────────────────────────
    MonitorLocation(
        name="backend_availability",
        type=LocationType.CLUSTER,
        config={"check": "backends"},
        check_interval_seconds=30,
        conditions=[Condition(metric="running_count", operator="eq", threshold=0)],
        actions=[Action(type="start_backend", config={})],  # tier-aware: vLLM for Tier 1, etc.
    ),
    MonitorLocation(
        name="backend_idle_scaledown",
        type=LocationType.CLUSTER,
        config={"check": "backend_idle"},
        check_interval_seconds=120,
        conditions=[Condition(metric="running_count", operator="gt", threshold=0)],
        actions=[Action(type="scale_down_backend", config={"idle_threshold_sec": 600})],
        cooldown_seconds=600,
    ),
    MonitorLocation(
        name="backend_scaling",
        type=LocationType.CLUSTER,
        config={"check": "backend_load"},
        check_interval_seconds=60,
        conditions=[Condition(metric="avg_load", operator="gt", threshold=0.8)],
        actions=[Action(type="scale_backend", config={"backend": "vllm", "desired": 2})],
        cooldown_seconds=300,
        enabled=False,  # Opt-in: enable via `noo autonomy enable backend_scaling`
    ),

    # ── Scheduler ──────────────────────────────────────────────────────
    MonitorLocation(
        name="job_queue_depth",
        type=LocationType.SCHEDULER,
        config={"check": "queue"},
        check_interval_seconds=15,
        conditions=[Condition(metric="queue_depth", operator="gt", threshold=10)],
        actions=[Action(type="log", config={"level": "warning", "message": "Job queue backing up"})],
    ),

    # ── Watched folders (proactive file ingestion) ──────────────────────
    # DEPRECATED 2026-04-28: replaced by native Rust ingest_loop in
    # gateway-rust/src/ingest_loop.rs. The Rust gateway intercepts the
    # autonomy API path, so this MonitorLocation is dead in the standard
    # deployment. Retained for Python-only deployments.
    MonitorLocation(
        name="watched_folders",
        type=LocationType.FILESYSTEM,
        config={},  # populated from AppConfig.watched_folders at startup
        check_interval_seconds=60,
        conditions=[Condition(metric="new_count", operator="gt", threshold=0)],
        actions=[Action(type="ingest_files", config={"max_batch_size": 10})],
        enabled=False,  # enabled at startup when config has folders
        cooldown_seconds=30,
    ),


    # ── Graph enrichment ────────────────────────────────────────────────
    MonitorLocation(
        name="graph_cluster_stale",
        type=LocationType.SCHEDULER,
        config={},
        check_interval_seconds=3600,  # hourly
        conditions=[Condition(metric="stale", operator="eq", threshold=True)],
        actions=[Action(type="log", config={
            "level": "info",
            "message": "Graph clusters may be stale — consider running graph_clustering task",
        })],
        enabled=False,  # user enables via `noo autonomy enable graph_cluster_stale`
        cooldown_seconds=3600,
    ),
    MonitorLocation(
        name="gnn_reclustering",
        type=LocationType.RAG_STORE,
        config={"check": "entity_count_delta"},
        check_interval_seconds=3600,  # hourly
        conditions=[Condition(metric="entity_count_delta", operator="gt", threshold=20)],
        actions=[Action(type="submit_job", config={
            "type": "gnn_recluster",
            "description": "Re-cluster knowledge graph entities using GNN embeddings",
        })],
        enabled=False,  # opt-in: `noo autonomy enable gnn_reclustering`
        cooldown_seconds=7200,  # at most every 2 hours
    ),

    # ── Quality gates ──────────────────────────────────────────────────
    MonitorLocation(
        name="test_suite_health",
        type=LocationType.ENDPOINT,
        config={"url": f"{_GW}/api/tests/status"},
        check_interval_seconds=300,
        conditions=[Condition(metric="failed", operator="gt", threshold=0)],
        actions=[Action(type="alert", config={
            "title": "Test suite regression",
            "message": "Unit tests have failures — investigate before deploying",
            "alert_type": "error",
        })],
        cooldown_seconds=600,
    ),

    # ── Security ───────────────────────────────────────────────────────
    MonitorLocation(
        name="failed_auth_spike",
        type=LocationType.ENDPOINT,
        config={"url": f"{_GW}/api/security/audit/stats",
                "check": "auth_failures"},
        check_interval_seconds=60,
        conditions=[Condition(metric="auth_failures_5m", operator="gt", threshold=10)],
        actions=[Action(type="alert", config={
            "title": "Auth failure spike",
            "message": ">10 auth failures in 5 minutes — possible brute-force attempt",
            "alert_type": "error",
        })],
        cooldown_seconds=300,
    ),
    MonitorLocation(
        name="cert_expiry_check",
        type=LocationType.ENDPOINT,
        config={"url": f"{_GW}/api/security/pki/status",
                "check": "cert_expiry"},
        check_interval_seconds=86400,  # once per day
        conditions=[Condition(metric="expiring_soon", operator="gt", threshold=0)],
        actions=[Action(type="alert", config={
            "title": "TLS certificate expiring soon",
            "message": "One or more cluster certificates expire within 30 days",
            "alert_type": "warning",
        })],
        cooldown_seconds=86400,
    ),
    MonitorLocation(
        name="cert_auto_rotate",
        type=LocationType.ENDPOINT,
        config={"url": f"{_GW}/api/security/pki/status",
                "check": "cert_expiry"},
        check_interval_seconds=86400,  # once per day
        conditions=[Condition(metric="expiring_soon", operator="gt", threshold=0)],
        actions=[
            Action(type="api_call", config={
                "method": "POST",
                "path": "/api/security/pki/rotate-expiring",
                "body": {"warn_days": 30, "new_cert_days": 90},
            }),
            Action(type="alert", config={
                "title": "Certificates auto-rotated",
                "message": "Expiring leaf certificates were automatically renewed",
                "alert_type": "info",
            }),
        ],
        cooldown_seconds=86400,
        enabled=False,  # Opt-in: enable via `noo autonomy enable cert_auto_rotate`
    ),

    # ── Trellion: snapshot consolidation (Phase 6) ─────
    # The hippocampus → cortex consolidation cycle. Periodically slices
    # the live bi-temporal graph (per topic, time window, or user
    # attention) and runs trellion's deterministic build pipeline to
    # produce a System 1.5 snapshot. Snapshots are immutable + dated →
    # diffable across cycles.
    #
    # Default: opt-in (enable via `noo autonomy enable consolidation_due`).
    # Default cadence: nightly, time-window snapshot of the past 24h.
    # Once enabled, customise via `noo autonomy edit consolidation_due`.
    MonitorLocation(
        name="consolidation_due",
        type=LocationType.ENDPOINT,
        config={"url": f"{_GW}/api/snapshots", "check": "snapshot_freshness"},
        check_interval_seconds=86400,  # once per day
        # Always fire when enabled — the orchestrator itself will skip work
        # when the slice is empty.
        conditions=[Condition(metric="snapshot_count", operator="gte", threshold=0)],
        actions=[
            # In-process call — bypasses HTTP/NATS round-trip. Same Python
            # interpreter as the worker pool, so we reach SnapshotOrchestrator
            # directly via trellion.snapshots. Time placeholders below are
            # resolved by autonomy._trellion_consolidate at action time.
            Action(type="trellion_consolidate", config={
                "kind": "time_window",
                "params": {
                    "from": "{{ now_minus_24h }}",
                    "to": "{{ now }}",
                },
                "label": "nightly time-window cycle",
            }),
            Action(type="alert", config={
                "title": "trellion: consolidation cycle complete",
                "message": "Nightly snapshot built — query via /api/snapshots",
                "alert_type": "info",
            }),
        ],
        cooldown_seconds=86400,
        enabled=False,  # Opt-in: enable via `noo autonomy enable consolidation_due`
    ),
]
