// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import {
  createMetisClient,
  createAuthApi,
  createAuthFetch,
  createTokenRefresher,
  memoryTokenStore,
  type CrossTab,
} from '@metis/api';

// i515c: the access token lives in memory only. An older console kept it in
// localStorage, where any script on the page could read it: drop that copy
// once. Nothing is ever read from there.
try {
  if (typeof localStorage !== 'undefined') localStorage.removeItem('pai_token');
} catch {
  /* storage blocked: there is nothing to purge */
}

// Shared token store: the REST client, the socket tickets and the auth API.
// After a reload it is empty, and the httpOnly refresh cookie restores it.
export const tokenStore = memoryTokenStore();

// Refreshes are serialized across tabs: two in flight with the same rotating
// cookie look like a replay, and the gateway revokes every session of the
// account. A tab that waited takes the token another tab just shared.
export const crossTab: CrossTab = {
  locks: typeof navigator !== 'undefined' ? navigator.locks : undefined,
  channel: typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel('noo-auth') : undefined,
};

const onLogout = () => {
  // A refresh failed → tell the AuthProvider to show the login overlay.
  if (typeof window !== 'undefined') window.dispatchEvent(new Event('metis:logout'));
};

// One authed fetch for the app's client and its best-effort GETs.
const rawAuthFetch = createAuthFetch({ baseUrl: '', tokenStore, onLogout, crossTab });

// One gateway client for the app. baseUrl is '' — same-origin relative paths;
// Vite (dev) and the gateway (prod) proxy /api, /auth, /ws to the real backend.
export const client = createMetisClient({ baseUrl: '', tokenStore, onLogout, authFetch: rawAuthFetch });

export const authApi = createAuthApi({ baseUrl: '', tokenStore });

// The socket's refresh: on a 4401 close (token expired, logged out) the chat
// socket refreshes once through this and reconnects, or shows the login
// overlay — instead of retrying a dead session every 30 s.
// It also restores the session after a reload (AuthProvider's `restore`).
export const refreshToken = createTokenRefresher({ baseUrl: '', tokenStore, onLogout, crossTab });

/**
 * A refused or failed GET. `status` is the HTTP status (0 = the request never
 * completed: network error); `body` is the parsed refusal body when the
 * gateway sent one ({error, detail, retry_after_secs}). Feed it to
 * `refusalMessage(err.body, fallback)`.
 */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: unknown,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/** The sentence to show for a failed apiGet; the refusal's own detail when it has one. */
export function apiErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError && err.body) {
    const d = (err.body as { detail?: unknown }).detail;
    if (typeof d === 'string' && d) {
      const r = (err.body as { retry_after_secs?: unknown }).retry_after_secs;
      return typeof r === 'number' ? `${d} Retry in ${r}s.` : d;
    }
  }
  return fallback;
}

/**
 * Authed GET. Resolves with the parsed body; throws ApiError on a non-OK
 * response (status + refusal body) or a network failure (status 0). A failure
 * is never "no data": callers show the error or an unknown state.
 */
export async function apiGet<T = unknown>(path: string): Promise<T> {
  let r: Response;
  try {
    r = await rawAuthFetch(new Request(path));
  } catch (e) {
    throw new ApiError(0, undefined, `${path}: ${e instanceof Error ? e.message : 'network error'}`);
  }
  if (!r.ok) {
    let body: unknown;
    try {
      body = await r.json();
    } catch {
      body = undefined;
    }
    throw new ApiError(r.status, body, `${path}: HTTP ${r.status}`);
  }
  return (await r.json()) as T;
}
