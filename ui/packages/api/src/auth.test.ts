// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 PersonifAI LLC

import { describe, it, expect, vi } from 'vitest';
import { createAuthFetch, createTokenRefresher, type CrossTab } from './auth.ts';
import { memoryTokenStore } from './stores.ts';

// Node's `Request` (unlike the browser) requires absolute URLs, so tests use a
// base origin. In the app, baseUrl is '' and the browser resolves relative paths.
const BASE = 'https://gw.test';

function json(status: number, body?: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const asReq = (input: RequestInfo | URL): Request =>
  input instanceof Request ? input : new Request(input);

describe('createAuthFetch', () => {
  it('injects the Bearer token', async () => {
    const store = memoryTokenStore('tok-1');
    const fetchImpl = vi.fn(async () => json(200, { ok: true }));
    const authFetch = createAuthFetch({
      baseUrl: BASE,
      tokenStore: store,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    await authFetch(`${BASE}/api/x`);

    const sent = fetchImpl.mock.calls[0]![0] as unknown as Request;
    expect(sent.headers.get('Authorization')).toBe('Bearer tok-1');
  });

  it('on 401, refreshes once and retries with the fresh token', async () => {
    const store = memoryTokenStore('stale');
    const auths: string[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const req = asReq(input);
      if (req.url.endsWith('/api/auth/refresh')) return json(200, { access_token: 'fresh' });
      auths.push(req.headers.get('Authorization') ?? '');
      return json(auths.length === 1 ? 401 : 200, { ok: true });
    });
    const authFetch = createAuthFetch({
      baseUrl: BASE,
      tokenStore: store,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const res = await authFetch(`${BASE}/api/x`);

    expect(res.status).toBe(200);
    expect(auths).toEqual(['Bearer stale', 'Bearer fresh']);
    expect(await store.get()).toBe('fresh');
  });

  it('clears the token and calls onLogout when refresh fails (finding #5)', async () => {
    const store = memoryTokenStore('stale');
    const onLogout = vi.fn();
    const fetchImpl = vi.fn(async () => json(401)); // both the API call and refresh 401
    const authFetch = createAuthFetch({
      baseUrl: BASE,
      tokenStore: store,
      onLogout,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const res = await authFetch(`${BASE}/api/x`);

    expect(res.status).toBe(401);
    expect(onLogout).toHaveBeenCalledTimes(1);
    expect(await store.get()).toBeNull();
  });

  // i515c: the web console keeps its access token in memory, so after a
  // reload the first call has none; the httpOnly refresh cookie restores it.
  it('refreshes on a 401 even with no token in hand, and retries with the restored one', async () => {
    const store = memoryTokenStore(null);
    let refreshes = 0;
    const seen: (string | null)[] = [];
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const req = asReq(input);
      if (req.url.endsWith('/api/auth/refresh')) {
        refreshes++;
        return json(200, { access_token: 'restored' });
      }
      seen.push(req.headers.get('Authorization'));
      return req.headers.get('Authorization') ? json(200, { ok: true }) : json(401);
    });
    const authFetch = createAuthFetch({
      baseUrl: BASE,
      tokenStore: store,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const res = await authFetch(`${BASE}/api/x`);

    expect(res.status).toBe(200);
    expect(refreshes).toBe(1);
    expect(seen).toEqual([null, 'Bearer restored']);
    expect(await store.get()).toBe('restored');
  });

  it('coalesces concurrent 401s into a single refresh', async () => {
    const store = memoryTokenStore('stale');
    let refreshes = 0;
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const req = asReq(input);
      if (req.url.endsWith('/api/auth/refresh')) {
        refreshes++;
        await new Promise((r) => setTimeout(r, 5));
        return json(200, { access_token: 'fresh' });
      }
      return json(req.headers.get('Authorization') === 'Bearer fresh' ? 200 : 401, {});
    });
    const authFetch = createAuthFetch({
      baseUrl: BASE,
      tokenStore: store,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });

    const [a, b] = await Promise.all([authFetch(`${BASE}/api/a`), authFetch(`${BASE}/api/b`)]);

    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    expect(refreshes).toBe(1);
  });
});

// i515c: two tabs refreshing at once must spend the rotating cookie ONCE.
// A second refresh with an already-rotated cookie looks like a replay, and
// the gateway then revokes every session of the account.
describe('cross-tab refresh', () => {
  /** A FIFO Web Lock and a BroadcastChannel shared by two "tabs". */
  function sharedTabs() {
    let tail: Promise<unknown> = Promise.resolve();
    const locks: CrossTab['locks'] = {
      request<T>(_name: string, cb: () => Promise<T>): Promise<T> {
        const run = tail.then(cb);
        tail = run.catch(() => undefined);
        return run;
      },
    };
    const listeners: ((e: { data: unknown }) => void)[] = [];
    const channelFor = (): NonNullable<CrossTab['channel']> => {
      const mine: ((e: { data: unknown }) => void)[] = [];
      return {
        // A BroadcastChannel never delivers to its sender.
        postMessage: (m) => listeners.filter((l) => !mine.includes(l)).forEach((l) => l({ data: m })),
        addEventListener: (_t, l) => {
          mine.push(l);
          listeners.push(l);
        },
      };
    };
    return { locks, channelFor };
  }

  it('two tabs refreshing at once send ONE refresh request and share its token', async () => {
    const tabs = sharedTabs();
    let refreshes = 0;
    const fetchImpl = (async (input: RequestInfo | URL) => {
      if (asReq(input).url.endsWith('/api/auth/refresh')) {
        refreshes++;
        await Promise.resolve();
        return json(200, { access_token: `fresh-${refreshes}` });
      }
      return json(404);
    }) as unknown as typeof fetch;
    const tab = () => {
      const tokenStore = memoryTokenStore('stale');
      const refresh = createTokenRefresher({
        baseUrl: BASE,
        tokenStore,
        fetchImpl,
        crossTab: { locks: tabs.locks, channel: tabs.channelFor() },
      });
      return { tokenStore, refresh };
    };
    const a = tab();
    const b = tab();

    const [ta, tb] = await Promise.all([a.refresh(), b.refresh()]);

    expect(refreshes).toBe(1);
    expect(ta).toBe('fresh-1');
    expect(tb).toBe('fresh-1');
    expect(await b.tokenStore.get()).toBe('fresh-1');
  });

  it('a tab that opens later, with no token, still refreshes for itself', async () => {
    const tabs = sharedTabs();
    let refreshes = 0;
    const fetchImpl = (async () => {
      refreshes++;
      return json(200, { access_token: `fresh-${refreshes}` });
    }) as unknown as typeof fetch;
    const refresh = createTokenRefresher({
      baseUrl: BASE,
      tokenStore: memoryTokenStore(null),
      fetchImpl,
      crossTab: { locks: tabs.locks, channel: tabs.channelFor() },
    });
    expect(await refresh()).toBe('fresh-1');
    expect(refreshes).toBe(1);
  });
});
