# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Literal, Optional

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


def _default_config_path() -> Path:
    return Path.home() / ".config" / "mesh" / "config.yaml"


class OllamaConfig(BaseModel):
    base_url: str = Field(
        default="http://localhost:11434",
        description="Ollama API base URL"
    )
    model: str = Field(
        default="gpt-oss:20b",
        min_length=1,
        description="Ollama model name"
    )
    options: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional Ollama options (temperature, etc.)"
    )

    @field_validator('model')
    @classmethod
    def validate_model(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Model name cannot be empty or whitespace")
        return v.strip()

    @field_validator('base_url')
    @classmethod
    def validate_base_url(cls, v: str) -> str:
        if not v.startswith(('http://', 'https://')):
            raise ValueError("base_url must start with http:// or https://")
        return v.rstrip('/')


class AgentConfig(BaseModel):
    system_prompt: str = Field(
        default="You are noomesh, a local-first assistant. Be concise and action-oriented.",
        min_length=1,
        description="System prompt for the agent"
    )
    max_tool_loops: int = Field(
        default=3,
        ge=1,
        le=20,
        description="Maximum tool execution iterations"
    )
    tool_mode: Literal["auto", "off"] = Field(
        default="auto",
        description="Tool execution mode"
    )


class ContextConfig(BaseModel):
    files: list[str] = Field(default_factory=list)


class ToolsConfig(BaseModel):
    enabled: list[str] = Field(
        default_factory=lambda: ["web_search", "python_exec", "local_files"],
        description="List of enabled tool names"
    )
    selection_mode: Literal["smart", "all"] = Field(
        default="smart",
        description="Tool selection strategy"
    )
    max_selected: int = Field(
        default=8,
        ge=1,
        le=50,
        description="Maximum tools to select per query"
    )
    min_score: float = Field(
        default=0.1,
        ge=0.0,
        le=1.0,
        description="Minimum relevance score threshold"
    )
    selection_scoring: Literal["jaccard", "bm25"] = Field(
        default="jaccard",
        description="Scoring algorithm for tool selection"
    )
    always_include: list[str] = Field(
        default_factory=list,
        description="Tools to always include regardless of score"
    )
    allowed_paths: list[str] = Field(
        default_factory=list,
        description="Directories the local_files tool can access (watched_folders are added automatically)",
    )


class WebSearchConfig(BaseModel):
    provider: str = "duckduckgo"
    max_results: int = 5


# MCPServerConfig removed: external MCP servers are a
# DB registry (`noo mcp server add …`, `noo mcp import <yaml>`), not a config
# list. The outbound client (`noomesh.mcp.client`) stays for the node-side
# bridge of phase C.


class MCPConfig(BaseModel):
    enabled: bool = False
    # Config-graduation phase 2 — env overrides win (NOO_MCP_TIMEOUT,
    # NOO_MCP_TOOLS). `port` is retired since stack-v0.2.40: the gateway's
    # separate MCP listener is gone; the key is tolerated and unread.
    port: Optional[int] = Field(default=None, description="retired (stack-v0.2.40): the operator door is /mcp/operator on the gateway port")
    timeout: Optional[float] = Field(default=None, description="MCP tool-call timeout seconds (env NOO_MCP_TIMEOUT, default 120)")
    tools_filter: Optional[str] = Field(default=None, description="Comma list / 'all' tool filter (env NOO_MCP_TOOLS)")


class SandboxConfig(BaseModel):
    url: Optional[str] = Field(
        default=None,
        description="Python sandbox URL for isolated code execution. "
                    "Set to 'https://sandbox:9000' when using Docker cluster (internal network; "
                    "mTLS — the caller presents its cluster leaf). "
                    "None = local subprocess execution.",
    )


class MemoryPGVectorConfig(BaseModel):
    enabled: bool = False
    dsn: Optional[str] = None
    table: str = "noo_memory"
    dim: int = Field(default=768, description="Embedding vector dimension")
    create_extension: bool = True
    create_index: bool = True


class MemoryConfig(BaseModel):
    enabled: bool = Field(
        default=False,
        description="Enable memory system"
    )
    include_session: bool = Field(
        default=True,
        description="Include session-specific memory"
    )
    include_global: bool = Field(
        default=True,
        description="Include global persistent memory"
    )
    session_top_k: int = Field(
        default=4,
        ge=1,
        le=50,
        description="Number of session memories to retrieve"
    )
    global_top_k: int = Field(
        default=4,
        ge=1,
        le=50,
        description="Number of global memories to retrieve"
    )
    min_score: float = Field(
        default=0.1,
        ge=0.0,
        le=1.0,
        description="Minimum relevance score for retrieval"
    )
    retrieval_scoring: Literal["jaccard", "bm25"] = Field(
        default="jaccard",
        description="Scoring algorithm for memory retrieval"
    )
    max_chars: int = Field(
        default=2000,
        ge=100,
        le=50000,
        description="Maximum characters in retrieved context"
    )
    max_session_items: int = Field(
        default=200,
        ge=10,
        le=10000,
        description="Maximum items in session memory"
    )
    max_global_items: int = Field(
        default=2000,
        ge=10,
        le=100000,
        description="Maximum items in global memory"
    )
    global_path: Optional[str] = Field(
        default=None,
        description="Path to global memory file"
    )
    embedding_model: Optional[str] = Field(
        default=None,
        description="Model for generating embeddings"
    )
    embedding_base_url: Optional[str] = Field(
        default=None,
        description="Base URL for embedding model"
    )
    pgvector: MemoryPGVectorConfig = Field(
        default_factory=MemoryPGVectorConfig,
        description="PostgreSQL pgvector configuration"
    )


class TemporalGraphConfig(BaseModel):
    """Thresholds for the bi-temporal knowledge graph.

    Consumed by the conversation-extractor add-on role
    (``noomesh.addon_roles.CONVERSATION_EXTRACTOR``; extraction path). There is no decay/reconcile
    ``TemporalReasoner`` class anywhere in this tree. The decay/prune
    fields below describe design intent, not a shipped reconciler.
    Centralised here so operators can tune without
    code edits.
    """

    extraction_timeout_seconds: float = Field(
        default=60.0,
        ge=5.0,
        le=600.0,
        description="HTTP timeout for the extraction LLM call",
    )
    max_message_chars: int = Field(
        default=4000,
        ge=500,
        le=100000,
        description="Truncate input messages longer than this before extraction",
    )
    extracted_confidence_default: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Fallback confidence when the LLM omits the field",
    )
    min_confidence: float = Field(
        default=0.4,
        ge=0.0,
        le=1.0,
        description="Drop extracted assertions below this confidence",
    )
    decay_per_day: float = Field(
        default=0.005,
        ge=0.0,
        le=0.5,
        description="Daily confidence decay applied by the reasoner to unconfirmed edges",
    )
    confidence_floor: float = Field(
        default=0.2,
        ge=0.0,
        le=1.0,
        description="Reasoner supersedes edges that decay below this threshold",
    )
    confirmation_boost: float = Field(
        default=0.05,
        ge=0.0,
        le=1.0,
        description="Reasoner adds this when the same assertion is restated",
    )
    prune_superseded_after_days: int = Field(
        default=90,
        ge=1,
        le=3650,
        description="Drop superseded edges older than this. Currently-valid edges are kept indefinitely.",
    )
    prune_superseded_below_confidence: float = Field(
        default=0.6,
        ge=0.0,
        le=1.0,
        description="Only prune superseded edges whose confidence is below this — high-confidence supersessions (real evolution) stay forever. May be adjusted at runtime by an add-on.",
    )


class WalksConfig(BaseModel):
    """Recallable walks: a user's saved threads.

    Saving is a per-ACCOUNT choice (``walks.save_threads``, default on, stored
    in ``noo_user_settings``); this section is the install-wide tuning that
    governs what recall does with what was saved. The soft gates are
    LOG-FIRST: they are computed and logged for every candidate but filter
    nothing until ``soft_gating`` is turned on
    (after about two weeks of looking at the logged distribution). The hard
    gates (an unreadable step, a snipped edge, a deleted document, a
    superseded temporal edge, a rejected verification) always drop a walk.
    """

    soft_gating: bool = Field(
        default=False,
        description="Filter recall on the soft gates (relevance, usefulness, step confidence). Off = log them only.",
    )
    min_relevance: float = Field(default=0.55, ge=0.0, le=1.0, description="Soft gate: minimum query similarity")
    min_usefulness: float = Field(default=0.5, ge=0.0, le=1.0, description="Soft gate: minimum composite usefulness U")
    min_confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Soft gate: minimum current edge confidence on any step")
    freshness_half_life_days: float = Field(
        default=90.0, gt=0.0, le=3650.0, description="Half-life of the freshness term of U"
    )
    thread_ttl_days: int = Field(
        default=180, ge=1, le=3650, description="A saved thread expires this many days after it is saved"
    )
    max_threads_per_user: int = Field(
        default=500, ge=1, le=100000,
        description="Cap on a user's active threads; over it, the least-recalled (then oldest) are staged out of recall",
    )


# ── Recall memory: the `video_memory` -> `recall_memory` rename ──
#
# The section, the env var and the class were renamed for 0.6.0. For one
# release after 0.6.0 the old spellings still work and warn once; when both
# are present the NEW one wins and the warning names the ignored duplicate.
# The data directory keeps its path (/data/video_memory): it is invisible to
# operators and moving it would be a data migration for no reader benefit.

RECALL_MEMORY_SECTION = "recall_memory"
LEGACY_RECALL_MEMORY_SECTION = "video_memory"
RECALL_MEMORY_PATH_ENV = "NOO_RECALL_MEMORY_PATH"
LEGACY_RECALL_MEMORY_PATH_ENV = "NOO_VIDEO_MEMORY_PATH"
RECALL_MEMORY_DEFAULT_DIR = "/data/video_memory"

_deprecations_warned: set[str] = set()


def _warn_deprecated(old: str, new: str, *, both: bool = False) -> None:
    """One structured ``deprecated_config`` warning per process per name."""
    key = f"{old}->{new}:{both}"
    if key in _deprecations_warned:
        return
    _deprecations_warned.add(key)
    message = (
        f"{old} and {new} are both set; {new} wins and {old} is ignored — remove {old}"
        if both
        else f"{old} is deprecated; rename it to {new} (the old name is removed in the release after 0.6.0)"
    )
    try:
        from ._logging import get_logger

        get_logger(__name__).warning("deprecated_config", old=old, new=new, both_set=both, detail=message)
    except Exception:  # pragma: no cover - logging must never break config load
        import logging

        logging.getLogger(__name__).warning("deprecated_config: %s", message)


def recall_memory_path_env() -> Optional[str]:
    """The recall-memory directory from the environment, or None.

    ``NOO_RECALL_MEMORY_PATH`` first; ``NOO_VIDEO_MEMORY_PATH`` is honoured
    with a deprecation warning. Compose sets BOTH while trellion still reads
    only the old name, so equal values are the expected transition state and
    do not warn; different values warn and the new one wins.
    """
    new = os.environ.get(RECALL_MEMORY_PATH_ENV) or None
    old = os.environ.get(LEGACY_RECALL_MEMORY_PATH_ENV) or None
    if new and old and new != old:
        _warn_deprecated(LEGACY_RECALL_MEMORY_PATH_ENV, RECALL_MEMORY_PATH_ENV, both=True)
    elif old and not new:
        _warn_deprecated(LEGACY_RECALL_MEMORY_PATH_ENV, RECALL_MEMORY_PATH_ENV)
    return new or old


def migrate_recall_memory_section(data: Any) -> Any:
    """Read a ``video_memory:`` section as ``recall_memory:`` (warns once).

    Pure on its input: returns a new dict when it changes anything.
    """
    if not isinstance(data, dict) or LEGACY_RECALL_MEMORY_SECTION not in data:
        return data
    data = dict(data)
    legacy = data.pop(LEGACY_RECALL_MEMORY_SECTION)
    if RECALL_MEMORY_SECTION in data:
        _warn_deprecated(LEGACY_RECALL_MEMORY_SECTION, RECALL_MEMORY_SECTION, both=True)
    else:
        _warn_deprecated(LEGACY_RECALL_MEMORY_SECTION, RECALL_MEMORY_SECTION)
        data[RECALL_MEMORY_SECTION] = legacy
    return data


def _legacy_aware_section(original: dict) -> str:
    """The yaml key the recall-memory section is written under: the new one
    only when the file already uses it; otherwise the old one (the file's own
    key, or — with neither — the key evolve still reads)."""
    if isinstance(original, dict) and RECALL_MEMORY_SECTION in original:
        return RECALL_MEMORY_SECTION
    return LEGACY_RECALL_MEMORY_SECTION


class RecallMemoryConfig(BaseModel):
    """App-facing schema for recall memory (System 1), section ``recall_memory``.

    Field-compatible with ``trellion.live.video.config.VideoMemoryConfig`` —
    the gateway passes this instance straight to ``VideoMemoryManager``, which
    only reads attributes. Defined locally (not imported) because importing
    anything under ``trellion.live`` drags in sqlalchemy/structlog/torch and
    the CLI pays that on every invocation. Keep fields in sync with trellion.
    """

    enabled: bool = Field(default=False, description="Enable recall memory system")
    storage_dir: str = Field(
        default_factory=lambda: recall_memory_path_env() or RECALL_MEMORY_DEFAULT_DIR,
        description="Directory for FAISS indices and replay data (noo-data volume); "
        "NOO_RECALL_MEMORY_PATH decides it (NOO_VIDEO_MEMORY_PATH is the deprecated name)",
    )
    codec: str = Field(default="ffv1", description="Video codec (ffv1=lossless, mp4v=lossy fallback)")
    fps: int = Field(default=1, description="Frames per second (data storage, not playback)")
    frame_size: int = Field(default=800, description="Frame dimensions in pixels (square)")
    qr_version: int = Field(
        default=40,
        ge=1,
        le=40,
        description="QR code version (40 = max capacity ~2953 bytes binary)",
    )
    qr_error_correction: str = Field(
        default="M",
        description="QR error correction level: L (7%), M (15%), Q (25%), H (30%)",
    )
    tile_layout: str = Field(
        default="1x1",
        description="QR tile layout per frame: '1x1' or '2x2' (4x capacity)",
    )
    embedding_dim: int = Field(
        default_factory=lambda: int(os.environ.get("EMBEDDING_DIM", "1024")),
        description="Embedding dimension (must match the embedder/PageIndex; default is ollama/harrier, not TEI)",
    )
    archive_interval_minutes: int = Field(
        default=10,
        description="Minutes between automatic archival runs",
    )
    archive_batch_size: int = Field(
        default=100,
        description="Max conversations to archive per batch",
    )
    max_video_size_mb: int = Field(
        default=500,
        description="Max single video file size in MB before rolling",
    )
    promotion_confidence_threshold: float = Field(
        default=0.6,
        ge=0.0,
        le=1.0,
        description="Min score for promoting video results to System 2",
    )

    # -- Lifecycle management --
    prune_after_days: int = Field(
        default=90,
        ge=1,
        description="Min age (days) before a low-prominence record can be pruned",
    )
    prune_prominence_floor: float = Field(
        default=0.05,
        ge=0.0,
        le=1.0,
        description="Records below this prominence are pruned (truly worthless)",
    )
    elevate_prominence_ceiling: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        description=(
            "Records with prominence below this ceiling (but above prune floor) "
            "are consolidated into System 2 and removed from System 1"
        ),
    )
    elevate_min_access: int = Field(
        default=1,
        ge=0,
        description="Record must have been accessed at least this many times to be worth elevating",
    )
    lifecycle_interval_hours: int = Field(
        default=6,
        description="Hours between lifecycle (prune + elevate + compact) runs",
    )
    compact_tombstone_ratio: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        description="Trigger video compaction when tombstoned fraction exceeds this",
    )
    max_evolution_snapshots: int = Field(
        default=50,
        description="Number of lifecycle evolution snapshots to retain",
    )

    # -- Hard retention caps (independent of prominence-based pruning above) --
    max_age_days: int = Field(
        default=365,
        ge=1,
        description=(
            "Hard age cap — records older than this are tombstoned regardless of "
            "prominence. Acts as the outer envelope; prominence-based pruning "
            "(prune_after_days) handles low-value records sooner."
        ),
    )
    max_size_gb: float = Field(
        default=5.0,
        gt=0.0,
        description=(
            "Hard size cap on total MP4 storage. When exceeded, the lifecycle "
            "pass tombstones records oldest-first until under the cap. Set high "
            "(e.g. 100.0) to effectively disable size-based eviction."
        ),
    )

    # -- Storage backend --
    storage_backend: str = Field(
        default="local",
        description="Storage backend type: 'local' (filesystem) or 'azure' (Azure Blob Storage)",
    )
    azure_connection_string: str = Field(
        default="",
        description="Azure Blob Storage connection string (required when storage_backend='azure')",
    )
    azure_container: str = Field(
        default="video-memory",
        description="Azure Blob Storage container name",
    )


#: Deprecated name of :class:`RecallMemoryConfig`.
VideoMemoryConfig = RecallMemoryConfig


# Pro config left this tree: the evolve service owns
# and validates its own configuration (noo-evolve repo, env-driven). These
# stubs keep the yaml sections mountable — pydantic ignores extra keys, so
# a pro install's richer add-on sections load fine —
# and `enabled` stays readable for the runtime pro flag.
_PRO_CONFIG_AVAILABLE = False


class HofstadterLoopConfig(BaseModel):
    """Config stub — the evolve add-on owns the full model."""
    enabled: bool = False


class GAConfig(BaseModel):
    """Config stub — the evolve add-on owns the full model."""
    enabled: bool = False


class RLPolicyConfig(BaseModel):
    """Config stub — the evolve add-on owns the full model."""
    enabled: bool = False


class HeartbeatConfig(BaseModel):
    """Heartbeat scheduler configuration (from noomesh.yaml).

    Canonical home — gateway/heartbeat.py imports it from here so mounting
    the config model doesn't drag the scheduler runtime (httpx, croniter,
    feedparser) into every CLI invocation.
    """
    enabled: bool = Field(default=False, description="Enable heartbeat scheduler")
    tz: Optional[str] = Field(
        default=None,
        description="IANA timezone for cron evaluation. Resolution (Rust "
                    "scheduler): noo_settings DB row -> env NOO_HEARTBEAT_TZ "
                    "-> this key -> America/New_York",
    )
    gateway_url: Optional[str] = Field(
        default=None,
        description="Retired, not read: heartbeat actions call the gateway "
                    "in process (env NOO_HEARTBEAT_GATEWAY_URL is ignored)",
    )
    check_interval_seconds: int = Field(
        default=60, ge=10, le=3600,
        description="How often to check for due tasks (seconds)",
    )
    startup_delay_seconds: int = Field(
        default=30, ge=0, le=600,
        description="Grace period after gateway start before first check",
    )
    tasks: list[Dict[str, Any]] = Field(
        default_factory=list,
        description="Task definitions (id, name, schedule, action, config, channels, recipients)",
    )


class SecurityConfig(BaseModel):
    """Security settings for tool execution, input validation, and rate limiting.

    `exec_approval_mode` is NOT here any more. It is a posture gate
    (`NOO_EXEC_APPROVAL_MODE`, allow-listed in `posture.py` / `posture.rs`),
    because `noomesh.yaml` is writable over `PUT /api/config/security` — which
    the agent's own `noo_config_set` tool reaches. A gate the model can rewrite
    is not a gate. The remaining keys here are inputs to the risk classifier and
    the approval window, not the switch itself.
    """

    @model_validator(mode="before")
    @classmethod
    def _reject_retired_gate(cls, values: Any) -> Any:
        """Refuse to load a config that still sets the retired gate key.

        Loud, not silent: an operator who writes `exec_approval_mode: strict`
        and gets it ignored has a security control that exists only in their
        head. Same refusal the Rust gateway makes at boot
        (`posture::yaml_gate_refusal`), so the two runtimes cannot disagree
        about whether the install is configured.
        """
        if isinstance(values, dict) and values.get("exec_approval_mode") is not None:
            raise ValueError(
                "security.exec_approval_mode is no longer read from noomesh.yaml "
                "— it is a posture gate. Remove the key, then: "
                "noo security posture set NOO_EXEC_APPROVAL_MODE <auto|approval|strict>"
            )
        return values

    exec_approval_timeout: int = Field(
        default=300, ge=10, le=3600,
        description="Seconds before auto-approve in 'auto' mode",
    )
    high_risk_tools: list[str] = Field(
        default_factory=lambda: [
            "local_files_write", "local_files_delete", "skill_execute", "shell",
        ],
        description="Tool names that require approval",
    )
    medium_risk_tools: list[str] = Field(
        default_factory=lambda: ["python_tool", "browser"],
        description="Tool names logged but auto-approved",
    )
    rate_limit_per_minute: int = Field(
        default=60, ge=1, le=10000,
        description="Maximum API requests per minute per client",
    )
    max_input_length: int = Field(
        default=50000, ge=100, le=500000,
        description="Maximum character length for user input",
    )
    blocked_file_patterns: list[str] = Field(
        default_factory=lambda: [
            "*.env", "*.key", "*.pem", "*credentials*", "*.secret",
            "*id_rsa*", "*id_ed25519*",
        ],
        description="Glob patterns for files that tools must never access",
    )
    enable_input_sanitization: bool = Field(
        default=True,
        description="Enable input sanitization for all tool calls",
    )
    node_agent_require_auth: bool = Field(
        default=True,
        description="Require authentication for node agent control endpoints",
    )
    audit_log_file: Optional[str] = Field(
        default=None,
        description="Path to security audit log file (optional, in addition to DB + structlog)",
    )
    audit_retention_months: int = Field(
        default=12,
        ge=1,
        le=120,
        description=(
            "Months of audit history to keep in Postgres (monthly partitions). "
            "Partitions older than this are exported to audit_archive then DROPped. "
            "Default is 12 to meet the ~1-year retrievable-audit-history expectation; "
            "older partitions still live in the archive backend."
        ),
    )


class AuditArchiveConfig(BaseModel):
    """Cold-tier destination for audit log partitions dropped on rotation."""
    backend: Literal["local_dir", "azure_blob", "s3", "none"] = Field(
        default="local_dir",
        description=(
            "Where to ship a partition's contents before DROP. 'none' disables "
            "archival — partitions past the retention window are then RETAINED "
            "(never dropped) rather than silently deleted, so audit history is "
            "never lost to rotation. For compliance use, prefer an OFF-HOST backend "
            "('azure_blob' / 's3'); 'local_dir' writes to the same host and is "
            "lost if that host is compromised or rebuilt."
        ),
    )
    format: Literal["jsonl", "parquet"] = Field(
        default="jsonl",
        description="Export format. jsonl has no extra deps; parquet needs pyarrow.",
    )
    local_dir: str = Field(
        default="${NOO_DATA_DIR}/audit-archive",
        description="Directory for local_dir backend. Created on first rotation.",
    )
    azure_container: str = Field(
        default="noo-audit-cold",
        description="Azure Blob Storage container (when backend=azure_blob)",
    )
    azure_conn_env: str = Field(
        default="NOO_AUDIT_AZURE_CONN",
        description="Env var holding the Azure connection string",
    )
    s3_bucket: str = Field(default="", description="S3 bucket (when backend=s3)")
    s3_region: str = Field(default="us-east-1", description="S3 region")


class ColdArchiveConfig(BaseModel):
    """Hybrid-retention cold tier for "phased out" user data.

    Per the Q3 decision: user view is pragmatist (old data appears gone
    from the system), but a cold archive keeps the data for internal
    training / research. Users may opt-out via ``respect_user_optout=True``
    combined with a per-user opt-out flag (wired when identity system
    fully supports it).

    Layout on disk:

        {base_dir}/temporal-edges/{YYYY-MM}.jsonl
        {base_dir}/video-memory/{YYYY-MM}.jsonl
        {base_dir}/conversations/{YYYY-MM}.jsonl   (future)
        {base_dir}/audit/{YYYY-MM}.jsonl

    Backend can later swap to Azure Blob / S3 without changing callers —
    all archival code goes through the ``ArchiveBackend`` interface.
    """
    enabled: bool = Field(default=True, description="Archive to cold tier before user-view deletion")
    backend: Literal["local_dir", "azure_blob", "s3", "none"] = Field(default="local_dir")
    base_dir: str = Field(
        default="${NOO_DATA_DIR}/cold-archive",
        description="Root directory (local_dir backend). Env vars expanded.",
    )
    format: Literal["jsonl", "parquet"] = Field(default="jsonl")
    respect_user_optout: bool = Field(
        default=True,
        description=(
            "Honor per-user privacy opt-out (skip archive when flag is set). "
            "Opt-out plumbing is wired through the identity system — for now "
            "this flag controls only whether the check is performed at all."
        ),
    )
    azure_container: str = Field(default="noo-cold")
    azure_conn_env: str = Field(default="NOO_COLD_AZURE_CONN")
    s3_bucket: str = Field(default="")
    s3_region: str = Field(default="us-east-1")
    # Encryption at rest for cloud archives (H-D3). Cold-tier exports carry PII
    # (conversations, temporal edges, audit rows), so encrypt them server-side.
    s3_sse: str = Field(
        default="AES256",
        description=(
            "S3 server-side encryption for cold-archive puts: 'AES256' (SSE-S3, "
            "AWS-managed keys, on by default) or 'aws:kms' (set s3_kms_key_id). "
            "Empty string disables (not recommended)."
        ),
    )
    s3_kms_key_id: str = Field(
        default="", description="KMS key id/ARN when s3_sse='aws:kms'"
    )
    azure_encryption_scope: str = Field(
        default="",
        description=(
            "Azure Storage encryption scope for cold-archive blobs "
            "(customer-managed keys). Empty = account default (Microsoft-managed, "
            "still encrypted at rest)."
        ),
    )


class PromptSkillsConfig(BaseModel):
    """Prompt skills — markdown-based expertise templates for agents."""
    enabled: bool = Field(default=True, description="Enable prompt skills system")
    max_skills_per_query: int = Field(default=3, ge=1, le=10, description="Max skills injected per query")
    max_total_chars: int = Field(default=8000, ge=1000, le=50000, description="Max total chars from skills")
    auto_evolve: bool = Field(default=False, description="Allow new skills to be evolved automatically")
    max_evolved_per_role: int = Field(default=20, ge=1, le=100, description="Max evolved skills per agent role")
    llm_moderation: bool = Field(default=False, description="Run LLM moderation on evolved skills")


# EdgeConfig / CompanionConfig removed:
# thirteen fields nothing read. Companion gating is per-node desired state
# (`noo cluster set-config <node> --min-battery …`, or the seed file); the
# gateway's scheduler reads it from `noo_node_config.companion_policy`.


class OCRConfig(BaseModel):
    """OCR for scanned PDFs and images via vision-capable LLM (e.g. DeepSeek-OCR)."""
    enabled: bool = Field(default=False, description="Enable OCR for scanned pages/images")
    model: str = Field(
        default="deepseek-ai/DeepSeek-OCR",
        description="Vision model for OCR (must support /v1/chat/completions with images)",
    )
    min_text_length: int = Field(
        default=50,
        ge=0,
        description="Pages with fewer characters of extracted text trigger OCR",
    )
    dpi: int = Field(
        default=150,
        ge=72,
        le=600,
        description="Resolution for rendering PDF pages to images",
    )
    prompt: str = Field(
        default="<image>\nFree OCR.",
        description="Prompt sent alongside the page image",
    )


class UserDirEntry(BaseModel):
    """A user directory with host origin and container mount path."""
    host: str = Field(description="Host-side absolute path (e.g. /mnt/c/Users/.../Papers)")
    mount: str = Field(description="Container-internal mount path (e.g. /user-dirs/Papers)")
    label: str = Field(default="", description="Category label (e.g. research, code, notes, media)")
    writable: bool = Field(default=False, description="Mount read-write (workspace mode)")


PROTECTED_LABELS: frozenset[str] = frozenset({"code"})
"""Labels whose directories get extra safety protections:
- Autonomy engine skips them during watched_folders scans (no auto-ingest)
- local_files tool flags them for exec approval before AI reads
- File manager UI requires stronger confirmation to remove them
"""


_WORKSPACE_DEFAULT_MOUNT = "/workspace"


class WorkspaceConfig(BaseModel):
    """Writable directory where agents save reports, artifacts, and logs.

    Separate from watched_folders — the workspace is NOT auto-ingested.
    Content here is only ingested when explicitly requested.
    """
    host: str = Field(default="", description="Host-side absolute path (empty = not configured)")
    mount: str = Field(default="", description="Container-internal mount path (e.g. /workspace)")
    enabled: bool = Field(default=False, description="Whether a workspace directory is configured")

    @property
    def path(self) -> str:
        """Container-internal path for runtime use. Empty if not configured."""
        if not self.enabled:
            return ""
        return self.mount or _WORKSPACE_DEFAULT_MOUNT


class WatchedFoldersConfig(BaseModel):
    """Proactive file ingestion from whitelisted folders (read-only)."""
    enabled: bool = Field(default=False, description="Enable watched-folder auto-ingestion")
    folders: list[str | UserDirEntry] = Field(
        default_factory=list,
        description="Directories to watch — strings (container paths) or {host, mount} objects",
    )

    @property
    def mount_paths(self) -> list[str]:
        """Container-internal paths (used at runtime by gateway)."""
        result: list[str] = []
        for f in self.folders:
            if isinstance(f, UserDirEntry):
                result.append(f.mount)
            else:
                result.append(f)
        return result

    @property
    def host_paths(self) -> list[str]:
        """Host-side paths (used by onboard to generate compose mounts)."""
        result: list[str] = []
        for f in self.folders:
            if isinstance(f, UserDirEntry):
                result.append(f.host)
            else:
                result.append(f)  # legacy: path is both host and mount
        return result

    @property
    def dir_mapping(self) -> dict[str, str]:
        """Host→container mapping for compose override generation."""
        mapping: dict[str, str] = {}
        for f in self.folders:
            if isinstance(f, UserDirEntry):
                mapping[f.host] = f.mount
            else:
                mapping[f] = f
        return mapping

    @property
    def labeled_dirs(self) -> list[dict[str, str]]:
        """List of {mount, label} dicts for tool descriptions."""
        result: list[dict[str, str]] = []
        for f in self.folders:
            if isinstance(f, UserDirEntry):
                result.append({"mount": f.mount, "label": f.label or ""})
            else:
                result.append({"mount": f, "label": ""})
        return result

    @property
    def protected_mount_paths(self) -> list[str]:
        """Mount paths of directories whose label is in PROTECTED_LABELS."""
        result: list[str] = []
        for f in self.folders:
            if isinstance(f, UserDirEntry) and f.label in PROTECTED_LABELS:
                result.append(f.mount)
        return result

    @property
    def writable_mount_paths(self) -> list[str]:
        """Mount paths of directories marked as writable."""
        result: list[str] = []
        for f in self.folders:
            if isinstance(f, UserDirEntry) and f.writable:
                result.append(f.mount)
        return result

    patterns: list[str] = Field(
        default_factory=lambda: [
            "*.pdf", "*.md", "*.txt", "*.html",
            "*.docx", "*.pptx", "*.xlsx", "*.csv",
        ],
        description="Glob patterns for eligible files",
    )
    poll_interval_seconds: int = Field(
        default=60, ge=10,
        description="Seconds between filesystem scans",
    )
    recursive: bool = Field(default=True, description="Recurse into subdirectories")
    notify_channels: list[str] = Field(
        default_factory=list,
        description="Channel names to notify (e.g. google_chat, telegram)",
    )
    notify_recipients: list[str] = Field(
        default_factory=list,
        description="Recipient IDs matching notify_channels order",
    )


class CloudProvidersConfig(BaseModel):
    """Cloud model provider configuration."""
    enabled: bool = Field(default=False, description="Enable cloud provider routing")
    default_provider: Optional[str] = Field(
        default=None,
        description="Default cloud provider (anthropic, openai, google)",
    )
    fallback_order: list[str] = Field(
        default_factory=lambda: ["anthropic", "openai", "google"],
        description="Provider fallback order for failover",
    )


class PersonasConfig(BaseModel):
    """Persona-as-Coordinator configuration."""
    enabled: bool = Field(default=False, description="Enable persona coordinator agents")
    source: str = Field(
        default="config",
        description="Persona source: 'config' (static YAML/JSON) or 'database' (noo-core DB)",
    )
    definitions: list[dict] = Field(
        default_factory=list,
        description="Static persona dicts when source=config",
    )
    persona_ids: list[str] = Field(
        default_factory=list,
        description="Specific persona IDs when source=database",
    )
    auto_load: bool = Field(
        default=False,
        description="Load all personas from DB when source=database",
    )
    shared_memory: bool = Field(
        default=True,
        description="Enable shared memory scope (visible to all personas)",
    )
    eager_start: bool = Field(
        default=True,
        description="Start all persona coordinators at gateway startup. "
        "When False, coordinators are created lazily on first request.",
    )


class CoordinatorConfig(BaseModel):
    """Unified coordinator agent configuration."""
    enabled: bool = Field(default=True, description="Enable coordinator agent for all channels")
    max_iterations: int = Field(default=10, ge=1, le=30, description="Max agentic loop iterations")
    session_ttl_seconds: int = Field(default=3600, ge=60, le=86400, description="Session cache TTL")
    max_session_messages: int = Field(default=40, ge=10, le=200, description="Max messages in session window")


class CacheConfig(BaseModel):
    enabled: bool = False
    ttl: int = Field(default=3600, description="Default cache TTL in seconds")


class ServicesConfig(BaseModel):
    """Connection URLs for infrastructure services.

    Secrets (passwords, tokens) should stay in ``.env``.  Only hostnames,
    ports and feature flags belong here.
    """
    # Both brokers serve TLS ONLY (redis: `tls-port 6379, port 0`; nats:
    # `nats-tls.conf`), so the defaults name the TLS scheme. A plaintext
    # scheme here would be a connection that cannot succeed, not a fallback.
    redis_url: str = Field(default="rediss://redis:6379", description="Redis URL (TLS)")
    nats_url: str = Field(default="tls://nats:4222", description="NATS URL (TLS)")
    database_url: str = Field(
        default="postgresql://noo:noo@postgres:5432/noomesh",
        description="PostgreSQL connection string",
    )
    embedding_url: str = Field(
        default="https://gateway:8080",
        description="Embedding endpoint. For Python worker callers this is "
        "the Rust gateway (the only embedding transport); the gateway's own "
        "downstream engine default is ollama-first in embedding_client.rs.",
    )
    embedding_dim: int = Field(
        default_factory=lambda: int(os.environ.get("EMBEDDING_DIM", "1024")),
        description="Expected embedding vector dimension (must match the model)",
    )
    # ── Config-graduation phase 2 ─────────────────────────────────
    # Optional endpoint topology; env vars override each key. All embedding
    # traffic (Rust external/memory/coordinator + Python trellion ingest)
    # goes through one backend-agnostic client at embedding_url speaking
    # the embedding_backend wire format — see noomesh.yaml.example.
    embedding_backend: Optional[str] = Field(
        default=None,
        description="Embedder wire format: tei | openai | ollama "
                    "(env PAGEINDEX_EMBEDDING_BACKEND, default ollama — TEI "
                    "is not deployed on the controller, it is the opt-in "
                    "`tei-compose` profile). openai (/v1/embeddings) is "
                    "served by TEI, llama.cpp, vLLM and Ollama alike.",
    )
    embedding_model: Optional[str] = Field(
        default=None,
        description="Model name sent to openai/ollama-backend embedders; the "
                    "tei backend is model-pinned server-side via TEI_MODEL "
                    "(env PAGEINDEX_EMBEDDING_MODEL)",
    )
    gateway_url: Optional[str] = Field(
        default=None, description="Public/self gateway URL (env NOO_GATEWAY_URL)")
    prometheus_url: Optional[str] = Field(
        default=None, description="Prometheus base URL (env NOO_PROMETHEUS_URL)")
    alertmanager_url: Optional[str] = Field(
        default=None, description="Alertmanager base URL (env NOO_ALERTMANAGER_URL)")
    loki_url: Optional[str] = Field(
        default=None, description="Loki base URL (env NOO_LOKI_URL; empty = logs UI disabled)")
    nvidia_exporter_url: Optional[str] = Field(
        default=None, description="DCGM/nvidia exporter metrics URL (env NVIDIA_EXPORTER_URL)")
    ollama_url: Optional[str] = Field(
        default=None,
        description="Ollama base URL for gateway-side calls (env OLLAMA_URL; "
                    "distinct from the ollama: section used by the local CLI agent)",
    )


class WorkerLimitsConfig(BaseModel):
    """Python worker-pool limits (config-graduation phase 2).

    Env overrides: NOO_WORKER_GLOBAL_CONCURRENCY, NOO_WORKER_TIMEOUT_SECS,
    NOO_WORKER_RSS_LIMIT_MB. The timeout/RSS keys are read by the Rust
    supervisor; global_concurrency by the Python pool.
    """
    global_concurrency: Optional[int] = Field(
        default=None, description="Max concurrent worker tasks (default 32)")
    timeout_secs: Optional[int] = Field(
        default=None, description="Worker NATS request timeout seconds (default 120)")
    rss_limit_mb: Optional[int] = Field(
        default=None, description="Worker RSS restart ceiling in MB (0/unset = disabled)")


class BackendConfig(BaseModel):
    """Configuration for a single inference backend type."""
    enabled: bool = True
    model: str = Field(default="", description="Default model to load")
    gpu_memory_utilization: float = Field(default=0.9, ge=0.1, le=1.0)
    extra_args: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional backend-specific arguments",
    )


class PinnedBackend(BaseModel):
    """A backend that should never be auto-stopped on a specific node."""
    node: str = Field(description="Node ID or hostname")
    backend: str = Field(description="Backend type: vllm, ollama, llamacpp")


class ClusterConfig(BaseModel):
    """Cluster-wide defaults for backends and model management.

    ``default_backend`` is used as a fallback when the tier-aware
    BackendManager cannot start the preferred backend.  Tier 1 nodes
    (VRAM >= 10 GB) will always try vLLM first regardless of this setting.
    """
    default_backend: str = Field(
        default="vllm",
        description="Preferred backend (vllm for Tier 1, ollama as fallback)",
    )
    backends: Dict[str, BackendConfig] = Field(
        default_factory=lambda: {
            "vllm": BackendConfig(model=""),  # Read from YAML config or VLLM_MODEL env
            # Empty like vllm — the model is resolved from the cluster
            # default_model / placement, not hardcoded (was a stale "qwen3:8b").
            "ollama": BackendConfig(model=""),
            "llamacpp": BackendConfig(),
        },
    )
    max_backends_per_node: int = Field(
        default=1, ge=1,
        description="Max concurrent inference backends per node (excess are stopped before starting new)",
    )
    auto_scale: bool = Field(default=False, description="Enable auto-scaling")
    idle_timeout_sec: int = Field(default=600, description="Stop idle backends after N seconds")
    pinned_backends: list[PinnedBackend] = Field(
        default_factory=list,
        description="Backends that idle scaledown must never stop",
    )


class SelfConfig(BaseModel):
    """Mutable identity layer.

    This is the agent's learned behavior: communication style, operating
    principles, user preferences, and self-assessment.  The static identity
    lives in ``prompts/coordinator.md``; this section is what the agent
    learns about *how* to be effective over time.
    """
    tone: str = Field(
        default="direct",
        description="Communication tone: direct, friendly, technical, casual",
    )
    verbosity: str = Field(
        default="concise",
        description="Response length: concise, moderate, detailed",
    )
    operating_principles: list[str] = Field(
        default_factory=list,
        description="Learned operational rules (max 10)",
    )
    user_preferences: list[str] = Field(
        default_factory=list,
        description="Observed user preferences (max 10)",
    )
    avoid: list[str] = Field(
        default_factory=list,
        description="Learned anti-patterns — things NOT to do (max 10)",
    )
    focus: str = Field(
        default="",
        description="Current priority area or domain focus",
    )
    strengths: str = Field(
        default="",
        description="Self-assessed strengths (self-assessed)",
    )
    weaknesses: str = Field(
        default="",
        description="Self-assessed weaknesses (self-assessed)",
    )
    preferred_skills: list[str] = Field(
        default_factory=list,
        description="Preferred prompt skill names (max 5)",
    )
    exploration_policy: dict = Field(
        default_factory=lambda: {
            # Per-intent base exploration rates: how much to explore
            # when this intent is detected.  Definitional queries benefit
            # from exploitation (known paths are usually right);
            # exploratory queries need more wandering.
            "intent_rates": {
                "causal": 0.35,
                "definitional": 0.15,
                "procedural": 0.25,
                "comparative": 0.40,
                "exploratory": 0.60,
            },
            # How strongly composite uncertainty amplifies exploration.
            # Higher = more reactive to any uncertainty signal.
            "confidence_sensitivity": 0.3,
            # Floor: minimum exploration even at max confidence.
            # Prevents total lock-in to proven paths.
            "explore_floor": 0.05,
            # Ceiling: maximum exploration even at zero confidence.
            # Prevents pure random walk.
            "explore_ceiling": 0.85,
            # Weights for each uncertainty signal in the composite.
            # Controls which signals matter most when deciding to explore.
            "uncertainty_weights": {
                "replay_uncertainty": 0.30,
                "intent_uncertainty": 0.20,
                "seed_uncertainty": 0.20,
                "graph_sparsity": 0.15,
                "outcome_variance": 0.15,
            },
        },
        description=(
            "Contextual exploration policy for graph retrieval. Maps "
            "(intent, multi-signal uncertainty) → exploration rate. "
            "Per-intent base rates, uncertainty weights, and sensitivity "
            "are tunable."
        ),
    )
    signal_weights: dict = Field(
        default_factory=lambda: {
            "pagerank": 0.15,
            "personalized_pagerank": 0.25,
            "betweenness": 0.10,
            "temporal_freshness": 0.15,
            "motif_bonus": 0.10,
            "rwr_probability": 0.15,
            "spectral_similarity": 0.10,
        },
        description=(
            "Weights for graph-signal composite scoring. Each key maps to "
            "a signal contribution in entity relevance computation. "
            "Tunable."
        ),
    )


class TerminalConfig(BaseModel):
    """Claude Code embedded terminal settings."""
    default_backend: str = Field(default="vllm", description="Default backend for terminal")
    default_model: str = Field(default="", description="Default model for Claude Code (reads from YAML config)")
    context_length: int = Field(default=16384, description="Context length for Claude variants")
    auto_create_variants: bool = Field(
        default=True,
        description="Auto-create -claude variants with extended context on pull",
    )


class TLSConfig(BaseModel):
    """TLS / mTLS configuration for inter-service encryption."""
    enabled: bool = Field(default=False, description="Enable TLS for gateway")
    cert_file: Optional[str] = Field(default=None, description="Path to TLS certificate")
    key_file: Optional[str] = Field(default=None, description="Path to TLS private key")
    ca_file: Optional[str] = Field(default=None, description="Path to CA certificate")
    mtls_nodes: bool = Field(default=False, description="Require client certs from nodes")
    mtls_gateway: bool = Field(default=False, description="Require client certs on gateway")
    postgres_sslmode: str = Field(default="prefer", description="PostgreSQL SSL mode")
    postgres_sslrootcert: Optional[str] = Field(default=None, description="PostgreSQL CA cert")
    postgres_sslcert: Optional[str] = Field(default=None, description="PostgreSQL client cert for mTLS")
    postgres_sslkey: Optional[str] = Field(default=None, description="PostgreSQL client key for mTLS")
    redis_tls: bool = Field(default=False, description="Enable TLS for Redis")
    nats_tls: bool = Field(default=False, description="Enable TLS for NATS")


class AppConfig(BaseModel):
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    context: ContextConfig = Field(default_factory=ContextConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    web_search: WebSearchConfig = Field(default_factory=WebSearchConfig)
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    services: ServicesConfig = Field(default_factory=ServicesConfig)
    worker: WorkerLimitsConfig = Field(default_factory=WorkerLimitsConfig)
    cluster: ClusterConfig = Field(default_factory=ClusterConfig)
    self_identity: SelfConfig = Field(default_factory=SelfConfig)
    terminal: TerminalConfig = Field(default_factory=TerminalConfig)
    recall_memory: RecallMemoryConfig = Field(default_factory=RecallMemoryConfig)
    temporal_graph: TemporalGraphConfig = Field(default_factory=TemporalGraphConfig)
    walks: WalksConfig = Field(default_factory=WalksConfig)
    personas: PersonasConfig = Field(default_factory=PersonasConfig)
    coordinator: CoordinatorConfig = Field(default_factory=CoordinatorConfig)
    heartbeat: HeartbeatConfig = Field(default_factory=HeartbeatConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    audit_archive: AuditArchiveConfig = Field(default_factory=AuditArchiveConfig)
    cold_archive: ColdArchiveConfig = Field(default_factory=ColdArchiveConfig)
    tls: TLSConfig = Field(default_factory=TLSConfig)
    cloud_providers: CloudProvidersConfig = Field(default_factory=CloudProvidersConfig)
    workspace: WorkspaceConfig = Field(default_factory=WorkspaceConfig)
    watched_folders: WatchedFoldersConfig = Field(default_factory=WatchedFoldersConfig)
    ocr: OCRConfig = Field(default_factory=OCRConfig)
    prompt_skills: PromptSkillsConfig = Field(default_factory=PromptSkillsConfig)
    # Pro fields — mounted unconditionally because we always have stubs above.
    # In OSS the stub classes have only `enabled: bool = False`, so
    # references like `cfg.ga.enabled` still work and evaluate to False.
    hofstadter_loop: HofstadterLoopConfig = Field(default_factory=HofstadterLoopConfig)
    ga: GAConfig = Field(default_factory=GAConfig)
    rl_policy: RLPolicyConfig = Field(default_factory=RLPolicyConfig)

    @model_validator(mode="before")
    @classmethod
    def _read_renamed_sections(cls, data: Any) -> Any:
        """``video_memory:`` is read as ``recall_memory:``."""
        return migrate_recall_memory_section(data)

    @property
    def video_memory(self) -> RecallMemoryConfig:
        """Deprecated name of :attr:`recall_memory`."""
        return self.recall_memory

    @model_validator(mode="after")
    def _check_cross_section_invariants(self) -> "AppConfig":
        """Catch configuration combinations that are inconsistent across
        sections — Pydantic's field-level validators can't see across
        subconfigs, so invariants like "memory.enabled requires an embedding
        model" land here.

        Collects all violations into a single error so operators don't have
        to fix-and-reload repeatedly. Only raises if there are hard errors;
        soft warnings are surfaced via a stashed list on the instance and
        logged by the caller.
        """
        errors: list[str] = []
        warnings: list[str] = []

        # memory needs an embedder. An UNSET backend is gateway delegation
        # (the worker's runtime default, worker_pool.py / PageIndexRAG): the
        # embed call goes to the gateway, which routes it to the placement
        # advertising the embed role, so the model is declared by that
        # placement and must not be restated here (a restated model is a
        # stale override — the 2026-07-29 outage class). Only a client-side
        # wire format (`ollama`, `openai`) needs a model name in the body,
        # and only a non-gateway backend needs its own endpoint URL. Until
        # 2026-09-16 this rule assumed `ollama` when unset and failed the
        # whole AppConfig on a fleet whose embedder is a placement, which
        # took the worker's exec-approval gate and audit logger down with it
        # (both init from get_config()).
        if self.memory.enabled:
            backend = (
                os.environ.get("PAGEINDEX_EMBEDDING_BACKEND")
                or self.services.embedding_backend
                or "gateway"
            ).strip().lower()
            has_model = bool(
                self.memory.embedding_model
                or self.services.embedding_model
                or os.environ.get("EMBEDDING_MODEL")
                or os.environ.get("PAGEINDEX_EMBEDDING_MODEL")
            )
            if backend in ("ollama", "openai") and not has_model:
                errors.append(
                    f"memory.enabled=true with the {backend} embedding backend "
                    "but no embedding model is configured. Set "
                    "services.embedding_model, memory.embedding_model, or the "
                    "PAGEINDEX_EMBEDDING_MODEL / EMBEDDING_MODEL env var — or "
                    "leave the backend unset to use the gateway's embedder."
                )
            has_url = bool(
                self.memory.embedding_base_url
                or os.environ.get("PAGEINDEX_EMBEDDING_URL")
                or os.environ.get("TEI_URL")
                or self.services.embedding_url
            )
            if backend != "gateway" and not has_url:
                errors.append(
                    f"memory.enabled=true with the {backend} embedding backend "
                    "but no embedding endpoint URL is configured. Set "
                    "memory.embedding_base_url, services.embedding_url, or "
                    "the PAGEINDEX_EMBEDDING_URL / TEI_URL env var."
                )

        # recall_memory depends on the memory pipeline + ingestion infra
        if self.recall_memory.enabled and not self.memory.enabled:
            errors.append(
                "recall_memory.enabled=true requires memory.enabled=true "
                "(recall memory archives conversations tracked by the memory system)."
            )

        # watched_folders needs memory to store what it ingests
        if getattr(self.watched_folders, "enabled", False) and not self.memory.enabled:
            errors.append(
                "watched_folders.enabled=true requires memory.enabled=true "
                "(ingested docs need the memory pipeline)."
            )

        # audit_archive backends require credentials / target configuration
        if self.audit_archive.backend == "azure_blob":
            conn_env = self.audit_archive.azure_conn_env
            if not os.environ.get(conn_env):
                warnings.append(
                    f"audit_archive.backend=azure_blob but {conn_env} env var "
                    f"is not set — exports will fail until it is."
                )
        elif self.audit_archive.backend == "s3":
            if not self.audit_archive.s3_bucket:
                warnings.append(
                    "audit_archive.backend=s3 but audit_archive.s3_bucket is empty."
                )

        # parquet format requires pyarrow
        if self.audit_archive.format == "parquet":
            try:
                import pyarrow  # noqa: F401
            except ImportError:
                warnings.append(
                    "audit_archive.format=parquet but pyarrow is not installed. "
                    "Exports will raise at rotation time. Install pyarrow or "
                    "switch to format=jsonl."
                )

        # TLS requires cert+key when enabled
        if self.tls.enabled:
            if not (self.tls.cert_file and self.tls.key_file):
                errors.append(
                    "tls.enabled=true but tls.cert_file and/or tls.key_file is missing."
                )

        # Temporal graph pruning floor must be <= extraction default
        if self.temporal_graph.prune_superseded_below_confidence > self.temporal_graph.extracted_confidence_default:
            warnings.append(
                f"temporal_graph.prune_superseded_below_confidence "
                f"({self.temporal_graph.prune_superseded_below_confidence}) is above "
                f"extracted_confidence_default ({self.temporal_graph.extracted_confidence_default}) — "
                f"newly-extracted edges may be pruned on the first reconciliation pass."
            )

        # Stash warnings for the caller (app.py lifespan) to surface
        object.__setattr__(self, "_config_warnings", tuple(warnings))

        if errors:
            joined = "\n  - ".join(errors)
            raise ValueError(f"Configuration has cross-section errors:\n  - {joined}")
        return self


def resolve_config_path(config_path: Optional[str | Path]) -> Optional[Path]:
    if config_path:
        return Path(config_path)

    env_path = os.getenv("NOO_CONFIG")
    if env_path:
        return Path(env_path)

    # noomesh.yaml is the ONLY config file. A legacy
    # fallback config file was retired: it had drifted from the real config,
    # and a fallback that silently supplies stale values is worse than no
    # config at all.
    for name in ("noomesh.yaml",):
        cwd_path = Path.cwd() / name
        if cwd_path.exists():
            return cwd_path

    default_path = _default_config_path()
    if default_path.exists():
        return default_path

    return None


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _deep_merge(base: dict, updates: dict) -> dict:
    merged = dict(base)
    for key, value in updates.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(
    config_path: Optional[str | Path] = None,
    overrides: Optional[Dict[str, Any]] = None,
) -> tuple[AppConfig, Optional[Path]]:
    resolved_path = resolve_config_path(config_path)
    data: dict = {}
    if resolved_path:
        data = _load_yaml(resolved_path)

    if overrides:
        data = _deep_merge(data, overrides)

    config = AppConfig.model_validate(data)
    return config, resolved_path


def _strip_defaults(data: dict, defaults: dict) -> dict:
    """Recursively remove keys whose values match the defaults."""
    result = {}
    for key, value in data.items():
        default = defaults.get(key)
        if isinstance(value, dict) and isinstance(default, dict):
            nested = _strip_defaults(value, default)
            if nested:  # keep section if anything non-default inside
                result[key] = nested
        elif value != default:
            result[key] = value
        # If the section existed in the original YAML, keep it even if default
        # (this is handled by merging with _original_yaml_data below)
    return result


def save_config(config: AppConfig, path: Path) -> None:
    """Write *config* back to *path* as YAML.

    Merges the current config on top of the original YAML data so that
    sections that were explicitly written remain, but Pydantic-expanded
    defaults that were never in the original file don't bloat it.
    """
    global _original_yaml_data
    full = config.model_dump(mode="python")
    defaults = AppConfig().model_dump(mode="python")

    # Start with the original YAML as the base, then overlay changed values
    base = dict(_original_yaml_data) if _original_yaml_data else {}
    changed = _strip_defaults(full, defaults)
    # Merge: original base + only non-default values from current config
    merged = _deep_merge(base, changed)
    # Also keep any section that was in the original YAML (even if values match defaults)
    for key in _original_yaml_data or {}:
        if key not in merged:
            merged[key] = _original_yaml_data[key]
    # Never rename the operator's key. The dump carries the
    # section as `recall_memory`; write it under whichever key the file uses —
    # the old one when the file has it and not the new one, or has neither
    # (evolve still reads `video_memory` until its update ships).
    target = _legacy_aware_section(_original_yaml_data or {})
    if target != RECALL_MEMORY_SECTION and RECALL_MEMORY_SECTION in changed:
        moved = merged.pop(RECALL_MEMORY_SECTION)
        current = merged.get(target)
        merged[target] = (
            _deep_merge(current, moved) if isinstance(current, dict) and isinstance(moved, dict) else moved
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        yaml.dump(merged, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)
    # The gateway container runs as a nonroot uid and rewrites this file at
    # runtime (PUT /api/config, pro self-tuning). Make it writable by that uid
    # or those writes 500 with "Permission denied". Best-effort.
    try:
        os.chmod(path, 0o666)
    except OSError:
        pass


# ── Global singleton for gateway use ──

_runtime_config: Optional[AppConfig] = None
_runtime_config_path: Optional[Path] = None
_original_yaml_data: Optional[dict] = None


def get_config() -> AppConfig:
    """Return the current runtime config (loaded at gateway startup)."""
    global _runtime_config
    if _runtime_config is None:
        _runtime_config, _ = load_config()
    return _runtime_config


def env_or_yaml(env_key: str, yaml_get, default=None):
    """Config-graduation phase 2 resolution: env var -> noomesh.yaml -> default.

    ``yaml_get`` is a projection out of the loaded config, e.g.
    ``lambda c: c.services.nats_url``. Any config-load error degrades to
    env -> default (read sites must never crash on a bad YAML).
    """
    v = os.environ.get(env_key)
    if v:
        return v
    try:
        y = yaml_get(get_config())
        if y is not None and y != "":
            return y
    except Exception:
        pass
    return default


def recall_memory_enabled() -> bool:
    """The operator's ``recall_memory.enabled`` (or the deprecated ``video_memory``).

    The recall manager is built from Trellion's own config class, whose default
    is ``enabled=False``; without this the worker reported "disabled" for a
    system the operator had switched on. A config-load error reads as False.
    """
    try:
        return bool(get_config().recall_memory.enabled)
    except Exception:
        return False


def get_file_allowed_paths(cfg: Optional[AppConfig] = None) -> list[str]:
    """Merge ``tools.allowed_paths`` + ``watched_folders.mount_paths`` + ``workspace`` (deduplicated)."""
    cfg = cfg or get_config()
    paths: list[str] = list(cfg.tools.allowed_paths)
    if cfg.watched_folders.enabled:
        for f in cfg.watched_folders.mount_paths:
            if f not in paths:
                paths.append(f)
    ws = cfg.workspace.path
    if ws and ws not in paths:
        paths.append(ws)
    return paths


def translate_host_path(path: str, cfg: Optional[AppConfig] = None) -> str:
    """Translate a host-side path to its container mount path if applicable.

    Uses ``watched_folders.dir_mapping`` to translate paths like
    ``/mnt/c/Users/.../Papers/file.pdf`` → ``/user-dirs/Papers/file.pdf``.
    Returns the original path unchanged if no mapping matches.
    """
    cfg = cfg or get_config()
    if not cfg.watched_folders.enabled:
        return path
    for host_prefix, mount_prefix in cfg.watched_folders.dir_mapping.items():
        if path == host_prefix or path.startswith(host_prefix + "/"):
            return mount_prefix + path[len(host_prefix):]
    return path


def get_config_path() -> Optional[Path]:
    """Return the resolved config file path."""
    global _runtime_config_path
    if _runtime_config_path is None:
        _, _runtime_config_path = load_config()
    return _runtime_config_path


def init_runtime_config(
    config_path: Optional[str | Path] = None,
    overrides: Optional[Dict[str, Any]] = None,
) -> AppConfig:
    """Load config once at startup and cache it globally.

    Cross-section invariants are checked by ``AppConfig._check_cross_section_invariants``
    during validation; hard errors raise, soft warnings land on the config
    instance as ``_config_warnings`` and are emitted here so operators see them."""
    global _runtime_config, _runtime_config_path, _original_yaml_data
    _runtime_config, _runtime_config_path = load_config(config_path, overrides)
    # Stash raw YAML so save_config() can preserve the original structure
    if _runtime_config_path:
        _original_yaml_data = _load_yaml(_runtime_config_path)

    # Surface cross-section warnings (soft invariants)
    warnings = getattr(_runtime_config, "_config_warnings", ()) or ()
    if warnings:
        try:
            import structlog
            log = structlog.get_logger(__name__)
            for w in warnings:
                log.warning("config.invariant_warning", message=w)
        except Exception:
            pass

    return _runtime_config


def update_runtime_config(section: str, updates: Dict[str, Any]) -> AppConfig:
    """Update a section of the runtime config and persist to disk.

    ``section`` is a top-level key like ``"cluster"`` or ``"terminal"``.
    ``updates`` is a dict of fields to merge into that section. The legacy
    ``"video_memory"`` names the ``recall_memory`` field —
    without the mapping the update would sit beside the field and be dropped
    by the loader (new wins).
    """
    global _runtime_config
    if section == LEGACY_RECALL_MEMORY_SECTION:
        section = RECALL_MEMORY_SECTION
    cfg = get_config()
    current = cfg.model_dump()
    if section in current and isinstance(current[section], dict):
        current[section] = _deep_merge(current[section], updates)
    else:
        current[section] = updates
    _runtime_config = AppConfig.model_validate(current)

    # Persist
    path = get_config_path()
    if path:
        save_config(_runtime_config, path)
    return _runtime_config
