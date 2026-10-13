// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @metis/api — auth endpoints (login / me / logout).
//
// Kept separate from the typed CRUD client because /auth/token is
// form-urlencoded. Platform-neutral: the token store is injected (localStorage
// on web, SecureStore on mobile), so the same flow drives both.

import type { TokenStore } from './auth.ts';

export interface MeInfo {
  username: string;
  scopes: string[];
}

export interface AuthApiOptions {
  baseUrl?: string;
  tokenStore: TokenStore;
  fetchImpl?: typeof fetch;
}

export interface AuthApi {
  login(username: string, password: string): Promise<void>;
  logout(): Promise<void>;
  /** Current identity, or null when unauthenticated (401/403). */
  fetchMe(): Promise<MeInfo | null>;
}

export function createAuthApi(opts: AuthApiOptions): AuthApi {
  const { baseUrl = '', tokenStore, fetchImpl = fetch } = opts;

  return {
    async login(username, password) {
      const r = await fetchImpl(`${baseUrl}/auth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
        credentials: 'same-origin',
      });
      if (!r.ok) {
        const d = (await r.json().catch(() => ({}))) as { detail?: string };
        throw new Error(d.detail || `Login failed (${r.status})`);
      }
      const data = (await r.json()) as { access_token?: string };
      if (!data.access_token) throw new Error('Login response missing access_token');
      await tokenStore.set(data.access_token);
    },

    async fetchMe() {
      const token = await tokenStore.get();
      const r = await fetchImpl(`${baseUrl}/auth/me`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        credentials: 'same-origin',
      });
      if (!r.ok) return null;
      return (await r.json()) as MeInfo;
    },

    async logout() {
      try {
        await fetchImpl(`${baseUrl}/api/auth/logout`, { method: 'POST', credentials: 'same-origin' });
      } catch {
        /* best-effort — clear locally regardless */
      }
      await tokenStore.set(null);
    },
  };
}
