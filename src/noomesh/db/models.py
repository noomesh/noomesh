# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Legacy SQLAlchemy ORM model definitions for a subset of mesh tables.

Covers 19 PostgreSQL tables that predate the Rust port, defined here
instead of the scattered ``CREATE TABLE IF NOT EXISTS`` statements they
replaced. This is not the single source of truth for the schema: mesh
tables are now authored as SQL migrations (`gateway-rust/src/mesh_migrate.rs`,
the alembic chain is frozen at 046), and memory/trellion tables are owned
by trellion (`MEMORY_TABLE_NAMES`, `trellion/db/__init__.py`).

Notes:
    - Vector columns use ``pgvector.sqlalchemy.Vector``.
    - Index definitions include PostgreSQL-specific options (HNSW, ivfflat, GIN).
    - Tables use explicit ``__tablename__`` matching existing schema names
      so Alembic can detect and migrate existing databases.
"""

from __future__ import annotations

import os
import uuid as _uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    PrimaryKeyConstraint,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID, UUID
from sqlalchemy.orm import DeclarativeBase, relationship

try:
    from pgvector.sqlalchemy import Vector
except ImportError:  # pragma: no cover
    Vector = None  # type: ignore[assignment,misc]

# SQLAlchemy column definitions are evaluated at import time, so we must
# read from the environment here.  At runtime the canonical source of truth
# is ``ServicesConfig.embedding_dim`` (config.py), whose default_factory
# reads the same ``EMBEDDING_DIM`` env var.
#
# MIGRATION NOTE: Changing EMBEDDING_DIM after data exists does NOT alter
# existing pgvector columns.  You must:
#   1. Stop the gateway.
#   2. Run:  ALTER TABLE noo_entries ALTER COLUMN embedding TYPE vector(<new>);
#      (repeat for page_embeddings, chunk_embeddings)
#   3. Re-embed all rows (old vectors are now invalid):
#      UPDATE noo_entries SET embedding = NULL, indexed_at = NULL;
#   4. Restart with the new EMBEDDING_DIM.
_EMBEDDING_DIM = int(os.environ.get("EMBEDDING_DIM", "768"))


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _genuuid() -> _uuid.UUID:
    return _uuid.uuid4()


class Base(DeclarativeBase):
    """Shared declarative base for all PAI models."""

    pass


# ======================================================================
# Memory tables — extracted to trellion.db.models phase 4.
# Re-exported at the bottom of this module for backward-compat with code
# that still does `from noomesh.db.models import PaiConversation, ...`.
# The ORM classes are registered on trellion's Base.metadata, so mesh's
# Alembic env (which targets `Base.metadata` here) does NOT see them — the
# trellion env owns memory migrations. See the design
# ======================================================================


































# ======================================================================
# Cluster: Node Registry  (source: node_store.py)
# ======================================================================

class ClusterNode(Base):
    __tablename__ = "cluster_nodes"

    node_id = Column(Text, primary_key=True)
    hostname = Column(Text, nullable=False)
    ip_address = Column(Text, nullable=False)
    tier = Column(Integer, nullable=False, default=3)
    gpu_model = Column(Text)
    vram_gb = Column(Float, default=0.0)
    cpu_cores = Column(Integer, default=4)
    ram_gb = Column(Float, default=8.0)
    is_arm = Column(Boolean, default=False)
    capabilities = Column(JSONB, server_default=text("'[]'::jsonb"))
    status = Column(Text, default="offline")
    current_load = Column(Float, default=0.0)
    running_backends = Column(JSONB, server_default=text("'{}'::jsonb"))
    tools = Column(JSONB, server_default=text("'[]'::jsonb"))
    agent_url = Column(Text, default="")
    last_heartbeat = Column(DateTime(timezone=True))
    consecutive_heartbeat_failures = Column(Integer, default=0, server_default=text("0"))
    registered_at = Column(DateTime(timezone=True), server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), server_default=text("NOW()"))
    # Edge / Companion extensions
    node_type = Column(Text, default="worker", server_default=text("'worker'"))
    battery_pct = Column(Float, nullable=True)
    is_charging = Column(Boolean, nullable=True)
    network_type = Column(Text, nullable=True)
    thermal_state = Column(Text, nullable=True)
    active_sensors = Column(JSONB, server_default=text("'[]'::jsonb"))
    active_model = Column(Text, nullable=True)
    npu_tops = Column(Float, default=0.0, server_default=text("0"))
    platform = Column(Text, default="", server_default=text("''"))
    app_version = Column(Text, default="", server_default=text("''"))
    sensors = Column(JSONB, server_default=text("'[]'::jsonb"))
    power_budget_watts = Column(Float, default=0.0, server_default=text("0"))


# ======================================================================
# Heartbeat Scheduler  (source: heartbeat_store.py)
# ======================================================================

class PaiHeartbeatTask(Base):
    __tablename__ = "noo_heartbeat_tasks"

    id = Column(Text, primary_key=True)
    name = Column(Text, nullable=False)
    schedule = Column(Text, nullable=False)
    action = Column(Text, nullable=False, server_default=text("'custom_prompt'"))
    config = Column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    channels = Column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    recipients = Column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    enabled = Column(Boolean, nullable=False, default=True)
    last_run = Column(DateTime(timezone=True))
    next_run = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=text("NOW()"))
    created_by = Column(Text, nullable=False, server_default=text("'user'"))

    runs = relationship("PaiHeartbeatRun", back_populates="task", cascade="all, delete-orphan")


class PaiHeartbeatRun(Base):
    __tablename__ = "noo_heartbeat_runs"

    run_id = Column(Text, primary_key=True)
    task_id = Column(Text, ForeignKey("noo_heartbeat_tasks.id", ondelete="CASCADE"), nullable=False)
    task_name = Column(Text, nullable=False)
    action = Column(Text, nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=False)
    completed_at = Column(DateTime(timezone=True))
    status = Column(Text, nullable=False, default="running")
    result_text = Column(Text, default="")
    error = Column(Text, default="")
    duration_ms = Column(Integer, default=0)
    notified_channels = Column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    artifacts = Column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))

    task = relationship("PaiHeartbeatTask", back_populates="runs")


Index("idx_heartbeat_runs_task_id", PaiHeartbeatRun.task_id)
Index("idx_heartbeat_runs_started_at", PaiHeartbeatRun.started_at.desc())


# ======================================================================
# Channel Recipients  (source: former channels/router.py, deleted)
# ======================================================================

class PaiChannelRecipient(Base):
    """Saved channel contact — a space, group, or user to reach out to."""

    __tablename__ = "noo_channel_recipients"

    id = Column(Text, primary_key=True)
    channel = Column(Text, nullable=False)           # e.g. "google_chat", "telegram"
    recipient_id = Column(Text, nullable=False)       # space name, chat ID, phone number
    display_name = Column(Text, nullable=False)       # friendly name shown in UI
    notes = Column(Text, default="")                  # optional description
    is_default = Column(Boolean, default=False)       # default recipient for this channel
    metadata_ = Column("metadata", JSONB, server_default=text("'{}'::jsonb"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=text("NOW()"))
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=text("NOW()"))

    __table_args__ = (
        Index("uq_channel_recipient", "channel", "recipient_id", unique=True),
    )


class PaiChannelStat(Base):
    """Durable per-channel activity counters (received / sent / errors).

    Cumulative-since-first-seen totals. ``ChannelManager`` keeps the live
    counters in memory for the hot path and flushes the absolute values here
    on a periodic loop, seeding from this table on startup so the numbers
    survive gateway restarts (migration 029).
    """

    __tablename__ = "noo_channel_stats"

    channel = Column(Text, primary_key=True)          # e.g. "google_chat", "telegram"
    received = Column(BigInteger, nullable=False, server_default=text("0"))
    sent = Column(BigInteger, nullable=False, server_default=text("0"))
    errors = Column(BigInteger, nullable=False, server_default=text("0"))
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=text("NOW()"))


# ======================================================================
# Coordinator Background Tasks  (source: async_tasks_store.py)
# ======================================================================

class PaiCoordinatorTask(Base):
    """Persisted background task state for async coordinator sessions."""
    __tablename__ = "noo_coordinator_tasks"

    task_id = Column(Text, primary_key=True)
    session_id = Column(Text, nullable=False, index=True)
    conversation_id = Column(Text)
    channel = Column(Text)
    tool_name = Column(Text, nullable=False)
    tool_args = Column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    state = Column(Text, nullable=False, server_default=text("'pending'"))
    exec_mode = Column(Text, nullable=False, server_default=text("'local'"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=text("NOW()"))
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    result_output = Column(Text)
    result_error = Column(Text)
    result_success = Column(Boolean)
    job_id = Column(Text)       # For distributed tasks (JobScheduler)
    tc_id = Column(Text)        # OpenAI tool_call_id for message threading
    session_state = Column(JSONB)  # Serialized AsyncCoordinatorState for resumption


Index("idx_coordinator_tasks_session", PaiCoordinatorTask.session_id)
Index("idx_coordinator_tasks_state", PaiCoordinatorTask.state)


# ======================================================================
# Pro ORM models left this tree: evolve owns its five
# tables outright (noo-evolve repo — its own models + Alembic chain into
# schema `evolve`). Nothing in mesh reads or writes them anymore; the
# dev-only Alembic autogenerate must not see them either, or it would
# propose DROPs for tables another system owns.
# ======================================================================
_PRO_MODELS_AVAILABLE = False



# ======================================================================
# Feedback (migrated from SQLite)  (source: feedback/models.py)
# ======================================================================

class PaiFeedbackConversation(Base):
    __tablename__ = "noo_feedback_conversations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_genuuid)
    session_id = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(String(255), index=True)
    started_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    ended_at = Column(DateTime(timezone=True))
    model = Column(String(255))
    backend = Column(String(50))
    node_id = Column(String(255))
    tokens_used = Column(Integer, default=0)
    total_latency_ms = Column(Float, default=0.0)
    extra_data = Column("metadata", JSONB)

    messages = relationship("PaiFeedbackMessage", back_populates="conversation", cascade="all, delete-orphan")


class PaiFeedbackMessage(Base):
    __tablename__ = "noo_feedback_messages"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_genuuid)
    conversation_id = Column(UUID(as_uuid=True), ForeignKey("noo_feedback_conversations.id"), nullable=False, index=True)
    role = Column(String(50), nullable=False)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    tool_calls = Column(JSONB)
    latency_ms = Column(Float)
    error = Column(Text)

    conversation = relationship("PaiFeedbackConversation", back_populates="messages")
    feedback = relationship("PaiFeedbackRating", back_populates="message", uselist=False)


class PaiFeedbackRating(Base):
    __tablename__ = "noo_feedback_ratings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_genuuid)
    message_id = Column(UUID(as_uuid=True), ForeignKey("noo_feedback_messages.id"), nullable=False, unique=True, index=True)
    user_id = Column(String(255))
    rating = Column(Integer)
    thumbs = Column(Boolean)
    correction = Column(Text)
    dimensions = Column(JSONB)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), onupdate=_utcnow)

    message = relationship("PaiFeedbackMessage", back_populates="feedback")


class PaiFeedbackPreference(Base):
    __tablename__ = "noo_feedback_preferences"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_genuuid)
    prompt = Column(Text, nullable=False)
    chosen_response = Column(Text, nullable=False)
    rejected_response = Column(Text, nullable=False)
    chosen_message_id = Column(UUID(as_uuid=True), ForeignKey("noo_feedback_messages.id"))
    rejected_message_id = Column(UUID(as_uuid=True), ForeignKey("noo_feedback_messages.id"))
    reasoning = Column(Text)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    extra_data = Column("metadata", JSONB)


# ======================================================================
# Legacy flat conversation table  (source: pgvector_store.py)
# ======================================================================
# NOTE: This table is kept for backward-compatibility with the CLI
# ``noo memory`` commands that read from it.  New code should use
# ``noo_conversations`` + ``noo_entries`` instead.

# ======================================================================
# Prompt Skill Stats  (source: prompt_skills/store.py)
# ======================================================================

class PaiPromptSkillStat(Base):
    __tablename__ = "noo_prompt_skill_stats"

    id = Column(Integer, primary_key=True, autoincrement=True)
    skill_name = Column(Text, nullable=False)
    conversation_id = Column(Text)
    used_at = Column(DateTime(timezone=True), nullable=False, server_default=text("NOW()"))
    fitness_delta = Column(Float, default=0.0)
    context = Column(JSONB, server_default=text("'{}'::jsonb"))
    # Multi-user option-value column (PR3b-lite). NULL = shared/global; skill
    # stats are shared learning today. Not written or filtered yet.
    user_id = Column(Text, nullable=True)
    org_id = Column(Text, nullable=True)  # PR5b org/tenant boundary; NULL = 'default'


Index("idx_pss_skill_name", PaiPromptSkillStat.skill_name)
Index("idx_pss_used_at", PaiPromptSkillStat.used_at.desc())
Index("ix_pss_user_id", PaiPromptSkillStat.user_id, postgresql_where=PaiPromptSkillStat.user_id.isnot(None))


# ── Security Tables ───────────────────────────────────────────────────────


class PaiSecurityAudit(Base):
    """Persistent security audit log.

    Partitioned by month on ``timestamp``. The parent table holds no data
    directly; monthly child partitions are created by
    ``security.audit_archive.ensure_partition`` at startup and rotated
    (export → DROP) by the scheduled ``audit_log_rotate`` action once they
    fall outside the retention window.

    Note: Postgres requires the partition key to be part of every unique
    constraint, so the primary key is composite (id, timestamp) rather
    than just id.
    """

    __tablename__ = "noo_security_audit"

    id = Column(UUID(as_uuid=True), default=_genuuid, nullable=False)
    timestamp = Column(DateTime(timezone=True), nullable=False, server_default=text("NOW()"))
    event_type = Column(String(64), nullable=False, index=True)
    severity = Column(String(16), nullable=False, default="info", index=True)
    actor = Column(String(256), nullable=False, default="")
    resource = Column(String(512), nullable=False, default="")
    outcome = Column(String(64), nullable=False, default="")
    details = Column(JSONB, nullable=True)
    request_id = Column(String(32), nullable=True)

    __table_args__ = (
        PrimaryKeyConstraint("id", "timestamp", name="noo_security_audit_pkey"),
        Index("ix_noo_security_audit_ts", "timestamp"),
        {"postgresql_partition_by": "RANGE (timestamp)"},
    )


class PaiNatsDlq(Base):
    """Dead-letter queue for NATS publishes that exhausted retries.

    The Rust gateway writes here when ``publish_fire_and_forget`` fails
    after its retry budget. A periodic drain worker (``dlq_drain.py``)
    reads pending rows, re-publishes to the original subject, and marks
    success — or schedules another retry. Rows where ``next_retry_at IS
    NULL AND succeeded_at IS NULL`` have been abandoned (max retries
    exceeded) and require operator attention.
    """

    __tablename__ = "noo_nats_dlq"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_genuuid)
    subject = Column(Text, nullable=False)
    payload = Column(JSONB, nullable=False)
    attempt_count = Column(Integer, nullable=False, server_default=text("0"))
    last_error = Column(Text)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=text("NOW()"))
    next_retry_at = Column(DateTime(timezone=True), nullable=True)
    succeeded_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # Drain worker scans this hot path: pending rows ready for retry
        Index(
            "ix_noo_nats_dlq_pending",
            "next_retry_at",
            postgresql_where=text("succeeded_at IS NULL"),
        ),
        Index("ix_noo_nats_dlq_subject", "subject"),
    )


class PaiUserChannelLink(Base):
    """Maps external channel identities (Telegram @handle, Google Chat user
    ID, Slack user ID, etc.) to the canonical ``noo_users.username``.

    The same human writing from multiple channels should map to one user;
    otherwise their temporal-graph entries are fragmented into separate
    ``type=user`` entities and the agent can't correlate preferences
    across streams.

    Populate via ``noo users link <channel> <channel_user_id> <username>``
    or automatically via channel adapter onboarding.
    """

    __tablename__ = "noo_user_channel_links"

    channel = Column(String(64), nullable=False)
    channel_user_id = Column(String(256), nullable=False)
    username = Column(String(128), nullable=False, index=True)
    display_name = Column(Text, nullable=True)
    linked_at = Column(DateTime(timezone=True), nullable=False, server_default=text("NOW()"))
    metadata_ = Column("metadata", JSONB, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        PrimaryKeyConstraint("channel", "channel_user_id", name="noo_user_channel_links_pkey"),
        # Note: username index is declared via `Column(index=True)` above —
        # adding a duplicate `Index(name=..., "username")` here would
        # register the same name twice and break `Base.metadata.create_all`
        # on fresh installs (DuplicateTable error).
    )


class PaiUser(Base):
    """Database-backed user store for gateway authentication."""

    __tablename__ = "noo_users"

    # user_uuid is the PRIMARY KEY as of 044_identity_uuid_pk. Identity used
    # to be the NAME, so renaming an account orphaned every reference in all
    # three domains at once. username stays UNIQUE — it is how operators refer
    # to accounts — it is just no longer the key.
    user_uuid = Column(
        PGUUID(as_uuid=True), primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    username = Column(String(128), nullable=False, unique=True)
    hashed_password = Column(Text, nullable=False)
    disabled = Column(Boolean, nullable=False, default=False)
    scopes = Column(JSONB, nullable=False, server_default=text("'[\"read\"]'::jsonb"))
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=text("NOW()"))
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    password_changed_at = Column(DateTime(timezone=True), nullable=True)
    failed_login_count = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    # Org/tenant membership (PR5 org boundary). Which org a user belongs to;
    # every user lands in the `default` org on a single-org deployment. The
    # org is the top tenant boundary — no cross-org data sharing.
    # NOT NULL since 041_users_org_required: an org-less account
    # authenticates but is invisible to every org-scoped read, so the
    # constraint is the thing that keeps that state unrepresentable. The model
    # must agree or `create_all()` builds a fresh table the migration then has
    # to repair.
    org_id = Column(Text, nullable=False, server_default=text("'default'"), index=True)


class PaiOrg(Base):
    """Org / tenant — the top-level boundary above users and teams (PR5).

    An org groups users (``noo_users.org_id``) and teams (``noo_kb_teams.org_id``)
    into an isolation domain: data owned by one org is never visible to another,
    not even the org's shared ("global within org") tier. A single-org
    deployment has exactly one org, ``default``. Managed via ``noo security org``.
    """

    __tablename__ = "noo_orgs"

    # org_uuid is the PRIMARY KEY as of 044_identity_uuid_pk; `id` remains the
    # human-readable slug ('default') and stays UNIQUE.
    org_uuid = Column(
        PGUUID(as_uuid=True), primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    id = Column(Text, nullable=False, unique=True)
    name = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=text("NOW()"))
    created_by = Column(Text, nullable=True)


class ServiceKey(Base):
    """Named service key for external inference consumers (/api/external/*).

    Replaced the single anonymous ``NOO_SERVICE_API_KEY`` env credential so
    callers (noo-trading, noo-trellion, …) can be attributed and audited.
    That env credential was retired on 2026-08-03, so this table is now the
    ONLY way onto the external boundary.
    Issued via ``noo security service-key`` (Python CLI); the Rust gateway
    auth layer hashes the presented bearer, finds the ``active`` row, and
    resolves ``consumer`` + ``scopes``. Stores ``sha256(key)`` — never the
    raw key. Migration: ``011_service_keys``.
    """

    __tablename__ = "noo_service_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_genuuid)
    consumer = Column(Text, nullable=False, index=True)
    key_hash = Column(Text, nullable=False, unique=True)
    scopes = Column(
        JSONB,
        nullable=False,
        server_default=text("'[\"chat\", \"embeddings\", \"rerank\", \"classify\"]'::jsonb"),
    )
    active = Column(Boolean, nullable=False, server_default=text("true"))
    note = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=text("NOW()"))
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    # NULL = machine key, dispatches as the operator (cluster-HMAC). Set = the
    # MCP hub mints this user's JWT per tool call, so their scopes/KB roles
    # apply. CASCADE: a deleted account's keys must stop working, not degrade
    # into operator-tier keys. Migration: ``040_service_key_user``.
    user_id = Column(
        String(128),
        ForeignKey("noo_users.username", ondelete="CASCADE"),
        nullable=True,
    )


class ExternalRequest(Base):
    """One audit/usage row per ``/api/external/*`` call (envelope + usage).

    Written by a Rust middleware scoped to ``/api/external/*`` so external
    inference traffic is tracked per-consumer. Surfaced via
    ``GET /api/external/usage`` — distinct from ``/api/jobs`` (Redis
    background tasks). Migration: ``012_external_requests_audit``.
    """

    __tablename__ = "noo_external_requests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_genuuid)
    ts = Column(DateTime(timezone=True), nullable=False, server_default=text("NOW()"))
    consumer = Column(Text, nullable=False)
    endpoint = Column(Text, nullable=False)
    kind = Column(Text, nullable=True)
    model = Column(Text, nullable=True)
    backend = Column(Text, nullable=True)
    units = Column(JSONB, nullable=True)
    status_code = Column(Integer, nullable=False)
    latency_ms = Column(Integer, nullable=True)
    trace_id = Column(Text, nullable=True)
    error = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_noo_external_requests_consumer_ts", "consumer", "ts"),
        Index("ix_noo_external_requests_ts", "ts"),
    )


# ======================================================================
# Backward-compat re-exports of memory ORM classes.
# The actual class definitions live in trellion.db.models — these import
# bindings let existing code keep doing `from noomesh.db.models import
# PaiConversation` without changes. The classes register on trellion's
# Base.metadata, NOT this module's Base, so mesh's Alembic env doesn't
# see them.
# ======================================================================
try:
    from trellion.db.models import (  # noqa: F401
        ChunkEmbedding,
        Doc,
        Edge,
        Entity,
        EntityCluster,
        EntityClusterMember,
        EntityEmbedding,
        Mention,
        Page,
        PageChunk,
        PageEmbedding,
        PaiContextRetrieval,
        PaiConversation,
        PaiConversationFeedback,
        PaiEntityTyped,
        PaiEntry,
        PaiSemanticRelationship,
        PaiTemporalEdge,
        PaiToolExecution,
    )
except ImportError:
    # Trellion not installed (shouldn't happen in noomesh context, but
    # don't hard-fail if someone is exploring mesh without the dep).
    pass
