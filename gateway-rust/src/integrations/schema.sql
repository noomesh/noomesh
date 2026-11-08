-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright 2026 PersonifAI LLC
ALTER TABLE noo_connected_accounts DROP CONSTRAINT noo_connected_accounts_provider_check;
ALTER TABLE noo_connected_accounts ADD CHECK (provider ~ '^[a-z][a-z0-9_]{0,63}$');
ALTER TABLE noo_connected_accounts DROP CONSTRAINT noo_connected_accounts_status_check;
ALTER TABLE noo_connected_accounts ADD CHECK (status IN ('needs_auth', 'connected', 'reauth_required', 'disconnected'));
ALTER TABLE noo_connected_accounts
    ADD COLUMN provider_subject text,
    ADD COLUMN email text,
    ADD COLUMN granted_scopes text[] NOT NULL DEFAULT '{}',
    ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now(),
    ADD CHECK (status <> 'connected' OR provider_subject IS NOT NULL);
CREATE UNIQUE INDEX uq_integration_identity ON noo_connected_accounts(owner_uuid, provider, provider_subject) WHERE provider_subject IS NOT NULL;
CREATE TABLE noo_integration_credentials (
    account_id uuid PRIMARY KEY,
    owner_uuid uuid NOT NULL,
    sealed jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (account_id, owner_uuid) REFERENCES noo_connected_accounts(id, owner_uuid) ON DELETE CASCADE
);
CREATE TABLE noo_integration_oauth_sessions (
    id uuid PRIMARY KEY,
    owner_uuid uuid NOT NULL REFERENCES noo_users(user_uuid) ON DELETE CASCADE,
    provider text NOT NULL,
    target_id uuid,
    completion_hash text NOT NULL,
    state_hash text NOT NULL,
    sealed jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    claimed_at timestamptz,
    FOREIGN KEY (target_id, owner_uuid) REFERENCES noo_connected_accounts(id, owner_uuid) ON DELETE CASCADE
);
CREATE INDEX ix_integration_sessions_owner ON noo_integration_oauth_sessions(owner_uuid);
CREATE INDEX ix_integration_sessions_expiry ON noo_integration_oauth_sessions(expires_at);
