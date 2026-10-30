-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright 2026 PersonifAI LLC
CREATE TABLE noo_integration_pairings (
    id uuid PRIMARY KEY,
    owner_uuid uuid NOT NULL REFERENCES noo_users(user_uuid) ON DELETE CASCADE,
    code_hash text NOT NULL UNIQUE,
    provider text NOT NULL,
    services text[] NOT NULL,
    device_name text NOT NULL CHECK (length(device_name) BETWEEN 1 AND 100),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','authorizing','connected','cancelled')),
    session_id uuid UNIQUE,
    account_id uuid,
    expires_at timestamptz NOT NULL,
    FOREIGN KEY (account_id,owner_uuid) REFERENCES noo_connected_accounts(id,owner_uuid) ON DELETE CASCADE
);
CREATE INDEX ix_integration_pairings_owner ON noo_integration_pairings(owner_uuid);
CREATE INDEX ix_integration_pairings_expiry ON noo_integration_pairings(expires_at);
