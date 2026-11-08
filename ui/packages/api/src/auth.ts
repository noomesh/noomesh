// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

// @metis/api — auth-aware fetch.
//
// Ported from the legacy core/api.js authFetch: injects the Bearer token, and on
// a 401 does a single silent refresh (POST /api/auth/refresh, httponly cookie)
// and retries. The token store is injected so this stays platform-neutral —
// web keeps the access token in memory only (i515c), mobile in expo-secure-store.

/** Where the access token lives. `get` may be async (e.g. SecureStore). */
export interface TokenStore {
  get(): string | null | Promise<string | null>;
  set(token: string | null): void | Promise<void>;
}

export interface AuthFetchOptions {
  /** Absolute gateway origin, or '' for same-origin relative paths (web + proxy). */
  baseUrl?: string;
  tokenStore: TokenStore;
  /** Called when refresh fails — host clears session / shows login. */
  onLogout?: () => void;
  /** Override the fetch implementation (tests, custom agents). */
  fetchImpl?: typeof fetch;
  /** Serialize refreshes across tabs (web); see [`CrossTab`]. */
  crossTab?: CrossTab;
}

/**
 * Serialize refreshes across browser tabs (i515c). With the access token in
 * memory, every tab refreshes on its own; two refreshes in flight with the
 * same rotating cookie look like a replay to the gateway, which then revokes
 * EVERY session of the account. So a refresh holds a Web Lock, and a fresh
 * token is shared over a BroadcastChannel: a tab that waited on the lock and
 * meanwhile received a newer token uses it instead of refreshing again.
 */
export interface CrossTab {
  /** `navigator.locks` (or a test double). Absent: refreshes are coalesced in this tab only. */
  locks?: { request<T>(name: string, cb: () => Promise<T>): Promise<T> };
  /** A same-origin channel the tabs share. */
  channel?: {
    postMessage(m: unknown): void;
    addEventListener(t: 'message', l: (e: { data: unknown }) => void): void;
  };
  lockName?: string;
}

export type TokenRefreshOptions = Omit<AuthFetchOptions, 'onLogout'> &
  Pick<AuthFetchOptions, 'onLogout'>;

/** The message a tab sends when it holds a fresh token, or has logged out. */
type TabMessage = { type: 'token'; token: string } | { type: 'logout' };

/**
 * One silent refresh: `POST /api/auth/refresh` against the httponly cookie.
 * Resolves the new access token (already written to the store), or null —
 * in which case the stale token has been dropped and `onLogout` fired, so
 * the host shows the login overlay exactly once.
 *
 * Shared by the authed fetch (on a 401) and the WebSocket factory (on a
 * 4401 close): until 2026-09-18 only HTTP calls refreshed, so a console tab
 * whose 15-minute token had lapsed reconnected its chat socket with the
 * stale token every 30 s, forever.
 */
export function createTokenRefresher(opts: TokenRefreshOptions): () => Promise<string | null> {
  const { baseUrl = '', tokenStore, onLogout, fetchImpl = fetch, crossTab } = opts;
  const lockName = crossTab?.lockName ?? 'noo-auth-refresh';

  // Another tab's fresh token (or logout) becomes this tab's too.
  crossTab?.channel?.addEventListener('message', (e) => {
    const m = e.data as TabMessage | null;
    if (m?.type === 'token' && typeof m.token === 'string') void tokenStore.set(m.token);
    else if (m?.type === 'logout') void tokenStore.set(null);
  });

  // Coalesce concurrent callers into a single refresh round-trip.
  let refreshInFlight: Promise<string | null> | null = null;

  return function refresh(): Promise<string | null> {
    if (refreshInFlight) return refreshInFlight;
    refreshInFlight = (async () => {
      const before = await tokenStore.get();
      const locked = <T,>(cb: () => Promise<T>): Promise<T> =>
        crossTab?.locks ? crossTab.locks.request(lockName, cb) : cb();
      const fresh = await locked(async () => {
        // A tab that refreshed while this one waited has already shared its
        // token: use it rather than spend the cookie a second time.
        const now = await tokenStore.get();
        if (now && now !== before) return now;
        const got = await refreshOnce();
        if (got) crossTab?.channel?.postMessage({ type: 'token', token: got } satisfies TabMessage);
        return got;
      });
      if (fresh) {
        await tokenStore.set(fresh);
      } else {
        // Drop the now-known-invalid token so polled queries stop re-sending
        // it (each would otherwise 401 → fail refresh → re-fire onLogout).
        await tokenStore.set(null);
        onLogout?.();
      }
      refreshInFlight = null;
      return fresh;
    })();
    return refreshInFlight;
  };

  async function refreshOnce(): Promise<string | null> {
    let fresh: string | null = null;
    try {
      const r = await fetchImpl(`${baseUrl}/api/auth/refresh`, {
        method: 'POST',
        credentials: 'same-origin',
      });
      if (r.ok) {
        const data = (await r.json().catch(() => null)) as { access_token?: string } | null;
        fresh = data?.access_token ?? null;
      }
    } catch {
      fresh = null;
    }
    return fresh;
  }
}

/**
 * Build a fetch-compatible function with token injection + 401-refresh-retry.
 * The return value is passed straight to openapi-fetch's `fetch` option.
 */
export function createAuthFetch(opts: AuthFetchOptions): typeof fetch {
  const { tokenStore, fetchImpl = fetch } = opts;
  const tryRefresh = createTokenRefresher(opts);

  function authed(src: Request, token: string | null): Request {
    const headers = new Headers(src.headers);
    if (token) headers.set('Authorization', `Bearer ${token}`);
    return new Request(src, { headers, credentials: 'same-origin' });
  }

  return async function authFetch(input, init) {
    const original =
      input instanceof Request && init === undefined ? input : new Request(input, init);
    const token = await tokenStore.get();

    const first = authed(original, token);
    // Clone up front so the body is still available if we need to retry.
    const retrySrc = first.clone();

    const resp = await fetchImpl(first);
    // A 401 refreshes even with no token in hand: on web the access token
    // lives in memory, so after a reload the first call has none, and the
    // httpOnly refresh cookie is what restores the session (i515c).
    if (resp.status !== 401) return resp;

    const fresh = await tryRefresh();
    if (!fresh) return resp; // the refresher dropped the token and fired onLogout
    return fetchImpl(authed(retrySrc, fresh));
  };
}

/**
 * Bearer injection with no refresh. The kiosk's fetch: its credential is a
 * short-lived token the host re-mints, so a 401 means "wait for the watchdog",
 * never "try to refresh" — and a refresh is a POST a read-only key is refused.
 * The status is returned untouched so the caller can tell 401 from 503.
 */
export function createBearerFetch(opts: Omit<AuthFetchOptions, 'onLogout'>): typeof fetch {
  const { baseUrl: _baseUrl = '', tokenStore, fetchImpl = fetch } = opts;
  return async function bearerFetch(input, init) {
    const req = input instanceof Request && init === undefined ? input : new Request(input, init);
    const token = await tokenStore.get();
    const headers = new Headers(req.headers);
    if (token) headers.set('Authorization', `Bearer ${token}`);
    return fetchImpl(new Request(req, { headers, credentials: 'same-origin' }));
  };
}
