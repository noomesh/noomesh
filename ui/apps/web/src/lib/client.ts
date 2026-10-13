// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import {
  createMetisClient,
  createAuthApi,
  createAuthFetch,
  createTokenRefresher,
  webTokenStore,
} from '@metis/api';

// Shared token store — used by the REST client, the WebSocket (?token= URL),
// and the auth API.
export const tokenStore = webTokenStore();

// One gateway client for the app. baseUrl is '' — same-origin relative paths;
// Vite (dev) and the gateway (prod) proxy /api, /auth, /ws to the real backend.
export const client = createMetisClient({
  baseUrl: '',
  tokenStore,
  onLogout: () => {
    // 401 refresh failed → tell the AuthProvider to show the login overlay.
    if (typeof window !== 'undefined') window.dispatchEvent(new Event('metis:logout'));
  },
});

export const authApi = createAuthApi({ baseUrl: '', tokenStore });

// The socket's refresh: on a 4401 close (token expired, logged out) the chat
// socket refreshes once through this and reconnects, or shows the login
// overlay — instead of retrying a dead session every 30 s.
export const refreshToken = createTokenRefresher({
  baseUrl: '',
  tokenStore,
  onLogout: () => {
    if (typeof window !== 'undefined') window.dispatchEvent(new Event('metis:logout'));
  },
});

// Authed fetch reused for best-effort GETs to endpoints outside the typed
// schema (e.g. the pro evolution status feeds that drive the Brain Map dots).
const rawAuthFetch = createAuthFetch({
  baseUrl: '',
  tokenStore,
  onLogout: () => {
    if (typeof window !== 'undefined') window.dispatchEvent(new Event('metis:logout'));
  },
});

/** Best-effort authed GET. Returns null on any non-OK / error (status is telemetry). */
export async function apiGet<T = unknown>(path: string): Promise<T | null> {
  try {
    const r = await rawAuthFetch(new Request(path));
    return r.ok ? ((await r.json()) as T) : null;
  } catch {
    return null;
  }
}
