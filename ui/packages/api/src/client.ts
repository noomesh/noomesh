// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @metis/api — the typed gateway client.
//
// createMetisClient() returns an openapi-fetch client typed against the generated
// `paths` from contracts/openapi.json, wired to the auth-aware fetch. Every call
// (client.GET('/api/cluster/nodes'), etc.) is checked against the contract at
// compile time — the same discipline the mock enforces at runtime.

import createClient, { type Client } from 'openapi-fetch';
import type { paths } from './schema';
import { createAuthFetch, type TokenStore } from './auth.ts';

export interface MetisClientOptions {
  /** Gateway origin, or '' for same-origin relative paths (web behind the Vite/gateway proxy). */
  baseUrl?: string;
  /**
   * Optional since 2026-09-06. A caller with no credential of its own is a
   * legitimate shape now — the kiosk's local proxy attaches the header, so
   * the browser holds nothing. Omitting BOTH `tokenStore` and `authFetch`
   * gives a plain unauthenticated fetch, which is exactly right against
   * 127.0.0.1 and exactly wrong against a gateway; the caller chooses.
   */
  tokenStore?: TokenStore;
  onLogout?: () => void;
  fetchImpl?: typeof fetch;
  /**
   * A prebuilt fetch used as-is, instead of wrapping `fetchImpl` in the
   * 401-refresh-retry. For a caller whose credential cannot refresh — the
   * kiosk's read-only token — where attempting it would itself be a POST the
   * gateway refuses, and clearing the token store on that refusal would
   * throw away a credential the host watchdog is about to re-mint anyway.
   */
  authFetch?: typeof fetch;
}

export function createMetisClient(opts: MetisClientOptions): Client<paths> {
  const { baseUrl = '', tokenStore, onLogout, fetchImpl, authFetch } = opts;
  return createClient<paths>({
    baseUrl,
    fetch:
      authFetch ??
      (tokenStore
        ? createAuthFetch({ baseUrl, tokenStore, onLogout, fetchImpl })
        : (fetchImpl ?? fetch)),
  });
}

export type MetisClient = Client<paths>;
