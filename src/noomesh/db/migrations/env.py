# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 PersonifAI LLC

"""Alembic environment for the mesh (non-memory) subsystem.

Owns the non-memory tables — cluster, coordinator, heartbeat, channels,
feedback (replay/preference dataset), security, NATS DLQ, prompt skill
stats, plus add-on evolution tables.

Memory tables (conversation, RAG, knowledge graph, bi-temporal graph)
are owned by the trellion env at
``noo-trellion/src/trellion/db/migrations/`` and registered on
``trellion.db.models.Base.metadata`` (a separate Base from this one).

Uses a dedicated version table (``alembic_version_mesh``) so it
coexists with the trellion env on the same database.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool, text

from noomesh.db.models import Base

# Alembic Config object
config = context.config

# Logging (if ini section exists)
if config.config_file_name and os.path.exists(config.config_file_name):
    try:
        fileConfig(config.config_file_name)
    except Exception:
        pass

target_metadata = Base.metadata

VERSION_TABLE = "alembic_version_mesh"


def _get_url() -> str:
    """Resolve DSN in priority order: Alembic config > env vars."""
    url = config.get_main_option("sqlalchemy.url")
    if url:
        return url
    # Fall back to environment
    for key in ("PAGEINDEX_DSN", "PGVECTOR_URL", "DATABASE_URL"):
        val = os.environ.get(key)
        if val:
            return val
    raise RuntimeError(
        "No database URL configured. Set sqlalchemy.url in alembic.ini "
        "or one of PAGEINDEX_DSN / PGVECTOR_URL / DATABASE_URL env vars."
    )


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode — emit SQL to stdout."""
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        version_table=VERSION_TABLE,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode — connect to the DB."""
    url = _get_url()

    # Normalise driver to psycopg (SA 2.x default for postgresql)
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+psycopg://", 1)
    elif url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)

    connectable = engine_from_config(
        {"sqlalchemy.url": url},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        # Ensure extensions before running migrations
        connection.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        connection.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
        connection.commit()

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            version_table=VERSION_TABLE,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
