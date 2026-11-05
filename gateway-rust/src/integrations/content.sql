-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright 2026 PersonifAI LLC

-- Personal provider content never enters the shared KB/graph tables.
ALTER TABLE noo_connection_sources ADD COLUMN sync_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE noo_connection_sources ADD CONSTRAINT connection_source_owner UNIQUE (id, owner_uuid);

CREATE TABLE noo_integration_sync (
    source_id uuid PRIMARY KEY,
    owner_uuid uuid NOT NULL,
    generation uuid,
    lease uuid,
    lease_until timestamptz,
    cursor_sealed jsonb,
    next_run timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','syncing','idle','paused','error')),
    attempts integer NOT NULL DEFAULT 0,
    fault text CHECK (fault IN ('provider','reauth','limit','storage')),
    imported integer NOT NULL DEFAULT 0,
    skipped integer NOT NULL DEFAULT 0,
    FOREIGN KEY (source_id, owner_uuid) REFERENCES noo_connection_sources(id, owner_uuid) ON DELETE CASCADE
);
CREATE INDEX integration_sync_due ON noo_integration_sync(next_run);

CREATE TABLE noo_integration_documents (
    id uuid PRIMARY KEY,
    owner_uuid uuid NOT NULL,
    source_id uuid NOT NULL,
    item_key text NOT NULL,
    generation uuid NOT NULL,
    sealed jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (owner_uuid, source_id, item_key),
    FOREIGN KEY (source_id, owner_uuid) REFERENCES noo_connection_sources(id, owner_uuid) ON DELETE CASCADE
);
CREATE INDEX integration_documents_owner ON noo_integration_documents(owner_uuid, updated_at DESC);
